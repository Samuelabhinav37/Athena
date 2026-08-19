import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from athena.models import (
    AnomalyResult,
    AuditEvent,
    ConnectorCheckpoint,
    EffectiveEntitlement,
    Identity,
    MonitoringRun,
    PolicyEvaluation,
    RemediationExecution,
    ReviewCase,
    RiskAssessment,
)
from athena.schemas import EvidenceControlResponse, EvidenceReportResponse

AUTHORITATIVE_SOURCES = [
    "identities",
    "effective_entitlements",
    "policy_evaluations",
    "risk_assessments",
    "anomaly_results",
    "review_cases",
    "remediation_executions",
    "monitoring_runs",
    "connector_checkpoints",
    "audit_events",
    "controls/*.json",
]

LIMITATIONS = [
    "This report describes records currently present in Athena; it is not a certification.",
    "Connector completeness depends on configured read scopes and successful synchronization.",
    "Generated LLM explanations are excluded from authoritative report facts.",
    "NIST mappings marked partial require organizational evidence outside Athena.",
]


def _count(session: Session, model: type, *criteria: Any) -> int:
    statement = select(func.count()).select_from(model)
    if criteria:
        statement = statement.where(*criteria)
    return int(session.scalar(statement) or 0)


def _enum_counts(session: Session, model: type, column: Any) -> dict[str, int]:
    rows = session.execute(select(column, func.count()).select_from(model).group_by(column))
    return {
        (value.value if hasattr(value, "value") else str(value)): int(count)
        for value, count in rows
    }


def _controls(directory: Path) -> list[EvidenceControlResponse]:
    controls = []
    for path in sorted(directory.glob("*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        controls.append(
            EvidenceControlResponse(
                control_id=payload["control_id"],
                title=payload["title"],
                status=payload["status"],
                automated_checks=len(payload.get("automated_checks", [])),
                limitations=payload.get("limitations", []),
            )
        )
    return controls


def _digest_payload(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def evidence_report_facts(report: EvidenceReportResponse) -> dict[str, Any]:
    return {
        "schema_version": report.schema_version,
        "scope": report.scope,
        "inventory": report.inventory,
        "policy_decisions": report.policy_decisions,
        "review_statuses": report.review_statuses,
        "execution_statuses": report.execution_statuses,
        "monitoring_statuses": report.monitoring_statuses,
        "controls": [control.model_dump() for control in report.controls],
        "authoritative_sources": report.authoritative_sources,
        "limitations": report.limitations,
    }


def verify_evidence_report(report: EvidenceReportResponse) -> bool:
    return _digest_payload(evidence_report_facts(report)) == report.evidence_digest


class EvidenceReportService:
    def __init__(self, session: Session, control_directory: Path) -> None:
        self.session = session
        self.control_directory = control_directory

    def build(self) -> EvidenceReportResponse:
        inventory: dict[str, int | float | None] = {
            "identities": _count(self.session, Identity),
            "active_identities": _count(self.session, Identity, Identity.active.is_(True)),
            "active_entitlements": _count(
                self.session, EffectiveEntitlement, EffectiveEntitlement.active.is_(True)
            ),
            "policy_evaluations": _count(self.session, PolicyEvaluation),
            "risk_assessments": _count(self.session, RiskAssessment),
            "maximum_risk_score": self.session.scalar(select(func.max(RiskAssessment.score))),
            "anomalies": _count(self.session, AnomalyResult, AnomalyResult.is_anomaly.is_(True)),
            "review_cases": _count(self.session, ReviewCase),
            "remediation_executions": _count(self.session, RemediationExecution),
            "monitoring_runs": _count(self.session, MonitoringRun),
            "connector_checkpoints": _count(self.session, ConnectorCheckpoint),
            "audit_events": _count(self.session, AuditEvent),
        }
        controls = _controls(self.control_directory)
        facts = {
            "schema_version": "1.0",
            "scope": "Athena continuous authorization evidence snapshot",
            "inventory": inventory,
            "policy_decisions": _enum_counts(
                self.session, PolicyEvaluation, PolicyEvaluation.decision
            ),
            "review_statuses": _enum_counts(self.session, ReviewCase, ReviewCase.status),
            "execution_statuses": _enum_counts(
                self.session, RemediationExecution, RemediationExecution.status
            ),
            "monitoring_statuses": _enum_counts(
                self.session, MonitoringRun, MonitoringRun.status
            ),
            "controls": [control.model_dump() for control in controls],
            "authoritative_sources": AUTHORITATIVE_SOURCES,
            "limitations": LIMITATIONS,
        }
        return EvidenceReportResponse(
            **facts,
            generated_at=datetime.now().astimezone(),
            evidence_digest=_digest_payload(facts),
        )

    @staticmethod
    def markdown(report: EvidenceReportResponse) -> str:
        from athena.services.report_renderers import MarkdownEvidenceRenderer

        return MarkdownEvidenceRenderer().render(report).content.decode()
