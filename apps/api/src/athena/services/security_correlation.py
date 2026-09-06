"""Cross-product correlation over already-ingested SecurityEvent evidence.

Read-only. Moat and Clutter both report to the same tenant-scoped
SecurityEvent table with the same target_indicator semantics (a minimized
domain, never a full URL -- see SecurityEventCreate's own validator), but
nothing previously connected the two: a domain Moat blocked via its
malicious/phishing filter lists and the same domain impersonating a brand
in someone's inbox (Clutter) were two unrelated rows. Correlating them is a
much higher-confidence signal than either product's own detection alone,
and it needs no new detection logic in either extension -- the data is
already there.

No new table, no migration: this is a query over existing evidence, not a
new decision or a new piece of state. Severity is ranked explicitly in
Python rather than via SQL MAX() on the column, since the severity strings
("low" < "medium" < "high" < "critical") don't sort correctly as plain
text.

The query applies tenant scope in the application as defense in depth while
PostgreSQL RLS remains the authoritative enforcement boundary.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from athena.models import SecurityAgent, SecurityEvent
from athena.tenant_queries import apply_tenant_scope

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass
class CrossProductCorrelation:
    target_indicator: str
    agent_types: list[str]
    event_count: int
    highest_severity: str
    first_seen: datetime
    last_seen: datetime
    rule_ids: list[str] = field(default_factory=list)


def find_cross_product_correlations(
    session: Session,
    window: timedelta = timedelta(days=30),
) -> list[CrossProductCorrelation]:
    """Every target_indicator with events from more than one distinct
    agent_type within `window`, most-recently-seen first. An indicator
    reported only by one product (the overwhelmingly common case -- most
    domains Moat blocks were never also seen in anyone's inbox) never
    appears here; this is specifically the cross-product overlap, not a
    general event listing (see list_events for that). `session` must carry
    validated tenant authority."""
    cutoff = datetime.now(UTC) - window
    statement = (
        select(
            SecurityEvent.target_indicator,
            SecurityAgent.agent_type,
            SecurityEvent.severity,
            SecurityEvent.rule_id,
            SecurityEvent.occurred_at,
        )
        .join(
            SecurityAgent,
            (SecurityEvent.agent_id == SecurityAgent.id)
            & (SecurityEvent.tenant_id == SecurityAgent.tenant_id),
        )
        .where(
            SecurityEvent.target_indicator.is_not(None),
            SecurityEvent.occurred_at >= cutoff,
        )
    )
    rows = session.execute(apply_tenant_scope(session, statement, SecurityEvent)).all()

    by_indicator: dict[str, list[tuple[str, str, str, datetime]]] = defaultdict(list)
    for target_indicator, agent_type, severity, rule_id, occurred_at in rows:
        by_indicator[target_indicator].append((agent_type, severity, rule_id, occurred_at))

    correlations: list[CrossProductCorrelation] = []
    for indicator, entries in by_indicator.items():
        agent_types = sorted({agent_type for agent_type, _, _, _ in entries})
        if len(agent_types) < 2:
            continue  # The common case: reported by exactly one product.
        severities = (severity for _, severity, _, _ in entries)
        highest_severity = max(severities, key=lambda s: SEVERITY_RANK.get(s, -1))
        occurred_ats = [occurred_at for _, _, _, occurred_at in entries]
        correlations.append(
            CrossProductCorrelation(
                target_indicator=indicator,
                agent_types=agent_types,
                event_count=len(entries),
                highest_severity=highest_severity,
                first_seen=min(occurred_ats),
                last_seen=max(occurred_ats),
                rule_ids=sorted({rule_id for _, _, rule_id, _ in entries}),
            )
        )

    correlations.sort(key=lambda c: c.last_seen, reverse=True)
    return correlations
