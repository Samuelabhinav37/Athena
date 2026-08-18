import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from athena.models import AccessObservation, EffectiveEntitlement, Identity, IdentityType
from athena.services.provenance import governance_gaps

MACHINE_IDENTITY_TYPES = (
    IdentityType.SERVICE_ACCOUNT,
    IdentityType.APPLICATION,
    IdentityType.WORKLOAD,
    IdentityType.API_CLIENT,
    IdentityType.AGENT,
)
STALE_USAGE_DAYS = 90
STALE_CREDENTIAL_DAYS = 90


@dataclass(frozen=True)
class MachineIdentityFinding:
    code: str
    severity: Literal["low", "medium", "high"]
    summary: str


@dataclass(frozen=True)
class MachineIdentityPosture:
    identity_id: uuid.UUID
    username: str
    display_name: str
    identity_type: IdentityType
    source: str
    active: bool
    owner: str | None
    active_entitlements: int
    privileged_entitlements: int
    last_used_at: datetime | None
    findings: tuple[MachineIdentityFinding, ...]


def load_machine_identity_posture(session: Session) -> list[MachineIdentityPosture]:
    identities = session.scalars(
        select(Identity)
        .where(Identity.identity_type.in_(MACHINE_IDENTITY_TYPES))
        .order_by(Identity.source, Identity.username, Identity.id)
    ).all()
    return [_posture(session, identity) for identity in identities]


def _posture(session: Session, identity: Identity) -> MachineIdentityPosture:
    entitlements = session.scalars(
        select(EffectiveEntitlement)
        .options(
            selectinload(EffectiveEntitlement.provenance_edges),
            selectinload(EffectiveEntitlement.grant),
        )
        .where(
            EffectiveEntitlement.identity_id == identity.id,
            EffectiveEntitlement.active.is_(True),
        )
    ).unique().all()
    observations = session.scalars(
        select(AccessObservation)
        .join(EffectiveEntitlement)
        .where(EffectiveEntitlement.identity_id == identity.id)
        .order_by(AccessObservation.last_used_at.desc())
    ).all()
    last_used_at = next(
        (observation.last_used_at for observation in observations if observation.last_used_at), None
    )
    metadata = identity.source_metadata if isinstance(identity.source_metadata, dict) else {}
    if last_used_at is None:
        last_used_at = _metadata_datetime(metadata.get("role_last_used_at"))
    owner = metadata.get("owner") if isinstance(metadata.get("owner"), str) else None
    findings: list[MachineIdentityFinding] = []
    if not owner:
        findings.append(
            MachineIdentityFinding("missing_owner", "high", "No accountable owner is recorded")
        )
    if identity.active and last_used_at is None:
        findings.append(
            MachineIdentityFinding("usage_unknown", "medium", "No last-used evidence is recorded")
        )
    elif last_used_at is not None and _age_days(last_used_at) > STALE_USAGE_DAYS:
        findings.append(
            MachineIdentityFinding(
                "stale_usage", "high", f"Last use exceeds {STALE_USAGE_DAYS} days"
            )
        )
    if _has_stale_credential(metadata):
        findings.append(
            MachineIdentityFinding(
                "stale_credential",
                "high",
                f"Active credential exceeds {STALE_CREDENTIAL_DAYS} days",
            )
        )
    ungoverned = sum(bool(governance_gaps(item.grant)) for item in entitlements)
    if ungoverned:
        findings.append(
            MachineIdentityFinding(
                "ungoverned_access",
                "high",
                f"{ungoverned} active entitlement(s) lack required governance evidence",
            )
        )
    privileged = sum(item.permission.privileged for item in entitlements)
    return MachineIdentityPosture(
        identity_id=identity.id,
        username=identity.username,
        display_name=identity.display_name,
        identity_type=identity.identity_type,
        source=identity.source,
        active=identity.active,
        owner=owner,
        active_entitlements=len(entitlements),
        privileged_entitlements=privileged,
        last_used_at=last_used_at,
        findings=tuple(findings),
    )


def _age_days(value: datetime) -> int:
    aware = value if value.tzinfo else value.replace(tzinfo=UTC)
    return max((datetime.now(UTC) - aware).days, 0)


def _has_stale_credential(metadata: dict) -> bool:
    keys = metadata.get("access_keys", [])
    if not isinstance(keys, list):
        return False
    return any(
        isinstance(key, dict)
        and key.get("status") == "Active"
        and isinstance(key.get("age_days"), int)
        and key["age_days"] > STALE_CREDENTIAL_DAYS
        for key in keys
    )


def _metadata_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
