import hashlib
import json
import random
import uuid
from dataclasses import dataclass

import sklearn
from sklearn.ensemble import IsolationForest
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from athena.models import (
    AnomalyModelRun,
    AnomalyResult,
    Identity,
    ReviewCase,
    ReviewDecision,
    ReviewStatus,
    RiskAssessment,
)

MODEL_VERSION = "peer-isolation-forest-v2"
COHORT_POLICY_VERSION = "governed-cohort-v1"
RANDOM_SEED = 20260816
CONTAMINATION = 0.05
MINIMUM_COHORT_SIZE = 20
DRIFT_THRESHOLD = 0.25
FEATURES = [
    "entitlement_count",
    "privileged_ratio",
    "critical_ratio",
    "stale_ratio",
    "policy_failure_ratio",
    "retained_ratio",
    "peer_deviation_ratio",
]


@dataclass(frozen=True)
class CohortEntry:
    subject_key: str
    identity_id: uuid.UUID | None
    features: dict[str, float]
    synthetic: bool = False


@dataclass(frozen=True)
class CohortSelection:
    entries: list[CohortEntry]
    definition: dict


@dataclass(frozen=True)
class PeerAnomalyOutcome:
    run_id: uuid.UUID
    result_id: uuid.UUID
    is_anomaly: bool
    decision_score: float
    training_fingerprint: str
    peer_anomaly_count: int
    cohort_source: str
    drift_detected: bool


def features_from_assessment(assessment: RiskAssessment) -> dict[str, float]:
    total = max(assessment.summary["active_entitlements"], 1)
    findings = assessment.findings
    return {
        "entitlement_count": float(total),
        "privileged_ratio": sum(f.factors["privilege"]["value"] for f in findings) / total,
        "critical_ratio": sum(f.factors["sensitivity"]["value"] for f in findings) / total,
        "stale_ratio": sum(f.factors["time_since_use"]["value"] for f in findings) / total,
        "policy_failure_ratio": sum(f.factors["policy_risk"]["value"] for f in findings) / total,
        "retained_ratio": assessment.summary["retained_entitlements"] / total,
        "peer_deviation_ratio": assessment.summary["peer_deviations"] / total,
    }


def synthetic_security_cohort(size: int = 100) -> list[dict[str, float]]:
    rng = random.Random(RANDOM_SEED)
    cohort = []
    for _ in range(size):
        count = rng.randint(1, 5)
        cohort.append(
            {
                "entitlement_count": float(count),
                "privileged_ratio": round(rng.choice([0.0, 0.0, 0.2, 0.25]), 4),
                "critical_ratio": round(rng.choice([0.0, 0.0, 0.0, 0.2]), 4),
                "stale_ratio": round(rng.choice([0.0, 0.0, 0.0, 0.2]), 4),
                "policy_failure_ratio": 0.0,
                "retained_ratio": 0.0,
                "peer_deviation_ratio": round(rng.choice([0.0, 0.0, 0.2]), 4),
            }
        )
    return cohort


class GovernedCohortSelector:
    def __init__(self, session: Session, minimum_size: int = MINIMUM_COHORT_SIZE) -> None:
        self.session = session
        self.minimum_size = minimum_size

    def select(self, target: Identity) -> CohortSelection:
        assessments = list(
            self.session.scalars(
                select(RiskAssessment)
                .options(
                    selectinload(RiskAssessment.findings),
                    selectinload(RiskAssessment.identity).selectinload(Identity.roles),
                )
                .order_by(RiskAssessment.evaluated_at.desc())
            )
        )
        latest: dict[uuid.UUID, RiskAssessment] = {}
        for assessment in assessments:
            if assessment.identity_id != target.id and assessment.identity_id not in latest:
                latest[assessment.identity_id] = assessment
        target_roles = {role.name for role in target.roles}
        candidates = list(latest.values())
        hierarchy = [
            (
                "department_and_role",
                [
                    a
                    for a in candidates
                    if a.identity.department == target.department
                    and target_roles.intersection(role.name for role in a.identity.roles)
                ],
            ),
            ("department", [a for a in candidates if a.identity.department == target.department]),
            ("organization", [a for a in candidates if a.identity.active]),
        ]
        counts = {name: len(rows) for name, rows in hierarchy}
        for name, rows in hierarchy:
            if len(rows) >= self.minimum_size:
                entries = [
                    CohortEntry(a.identity.username, a.identity_id, features_from_assessment(a))
                    for a in rows
                ]
                return CohortSelection(entries, self._definition(name, counts, None))
        fallback = [
            CohortEntry(f"synthetic-security-{index + 1:03d}", None, features, True)
            for index, features in enumerate(synthetic_security_cohort())
        ]
        reason = f"No governed real cohort met minimum size {self.minimum_size}"
        return CohortSelection(fallback, self._definition("synthetic_security", counts, reason))

    def _definition(self, selected: str, counts: dict, fallback_reason: str | None) -> dict:
        return {
            "policy_version": COHORT_POLICY_VERSION,
            "minimum_size": self.minimum_size,
            "hierarchy": [
                "department_and_role",
                "department",
                "organization",
                "synthetic_security",
            ],
            "candidate_counts": counts,
            "selected": selected,
            "synthetic_fallback": selected == "synthetic_security",
            "fallback_reason": fallback_reason,
        }


class PeerAnomalyService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def run(self, identity: Identity) -> PeerAnomalyOutcome:
        assessment = self.session.scalar(
            select(RiskAssessment)
            .options(selectinload(RiskAssessment.findings))
            .where(RiskAssessment.identity_id == identity.id)
            .order_by(RiskAssessment.evaluated_at.desc())
        )
        if assessment is None:
            raise ValueError("A deterministic risk assessment is required before anomaly analysis")
        live = features_from_assessment(assessment)
        selection = GovernedCohortSelector(self.session).select(identity)
        cohort = [entry.features for entry in selection.entries]
        canonical = json.dumps(cohort, sort_keys=True, separators=(",", ":"))
        fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
        matrix = [[row[name] for name in FEATURES] for row in cohort]
        model = IsolationForest(
            n_estimators=200, contamination=CONTAMINATION, random_state=RANDOM_SEED
        ).fit(matrix)
        all_rows = cohort + [live]
        all_matrix = [[row[name] for name in FEATURES] for row in all_rows]
        raw_scores = model.score_samples(all_matrix)
        decisions = model.decision_function(all_matrix)
        predictions = model.predict(all_matrix)
        peer_anomaly_count = int(sum(p == -1 for p in predictions[:-1]))
        means = _feature_means(cohort)
        deviations = sorted(
            (
                {
                    "feature": name,
                    "value": round(live[name], 4),
                    "peer_mean": round(means[name], 4),
                    "absolute_difference": round(abs(live[name] - means[name]), 4),
                }
                for name in FEATURES
            ),
            key=lambda item: item["absolute_difference"],
            reverse=True,
        )[:3]
        drift = self._drift(identity, means, selection.definition["selected"])
        labels = self._reviewed_false_positives()
        run = AnomalyModelRun(
            algorithm="IsolationForest",
            library_version=sklearn.__version__,
            model_version=MODEL_VERSION,
            random_seed=RANDOM_SEED,
            contamination=CONTAMINATION,
            feature_schema=FEATURES,
            training_fingerprint=fingerprint,
            sample_size=len(cohort),
            peer_definition=selection.definition,
            summary={
                "advisory_only": True,
                "peer_anomaly_count": peer_anomaly_count,
                "peer_alert_rate": round(peer_anomaly_count / len(cohort), 4),
                "peer_alert_rate_is_false_positive_rate": False,
                "reviewed_label_metrics": labels,
                "feature_means": means,
                "drift": drift,
            },
        )
        self.session.add(run)
        for index, (row, raw, decision, prediction) in enumerate(
            zip(all_rows, raw_scores, decisions, predictions, strict=True)
        ):
            is_live = index == len(cohort)
            entry = None if is_live else selection.entries[index]
            result = AnomalyResult(
                run=run,
                identity_id=identity.id if is_live else entry.identity_id,
                subject_key=identity.username if is_live else entry.subject_key,
                synthetic=False if is_live else entry.synthetic,
                score_samples=float(raw),
                decision_score=float(decision),
                is_anomaly=bool(prediction == -1),
                features=row,
                explanation={
                    "top_deviations": deviations if is_live else [],
                    "advisory_only": True,
                    "cohort_source": selection.definition["selected"],
                },
            )
            self.session.add(result)
            if is_live:
                live_result = result
        self.session.commit()
        return PeerAnomalyOutcome(
            run.id,
            live_result.id,
            live_result.is_anomaly,
            live_result.decision_score,
            fingerprint,
            peer_anomaly_count,
            selection.definition["selected"],
            drift["detected"],
        )

    def _drift(self, identity: Identity, means: dict, cohort_source: str) -> dict:
        previous = self.session.scalar(
            select(AnomalyModelRun)
            .where(AnomalyModelRun.model_version == MODEL_VERSION)
            .order_by(AnomalyModelRun.trained_at.desc())
        )
        if previous is None or previous.peer_definition.get("selected") != cohort_source:
            return {
                "status": "baseline_established",
                "detected": False,
                "threshold": DRIFT_THRESHOLD,
                "max_feature_shift": None,
            }
        prior = previous.summary.get("feature_means", {})
        shifts = {
            name: round(abs(means[name] - prior[name]) / max(abs(prior[name]), 1.0), 4)
            for name in FEATURES
        }
        maximum = max(shifts.values())
        return {
            "status": "drift_detected" if maximum >= DRIFT_THRESHOLD else "stable",
            "detected": maximum >= DRIFT_THRESHOLD,
            "threshold": DRIFT_THRESHOLD,
            "max_feature_shift": maximum,
            "feature_shifts": shifts,
            "previous_run_id": str(previous.id),
            "subject": identity.username,
        }

    def _reviewed_false_positives(self) -> dict:
        reviewed = list(
            self.session.scalars(
                select(ReviewCase).where(
                    ReviewCase.status == ReviewStatus.RESOLVED,
                    ReviewCase.anomaly_result_id.is_not(None),
                )
            )
        )
        false_positives = sum(
            case.resolution in (ReviewDecision.RETAIN, ReviewDecision.EXCEPTION)
            for case in reviewed
        )
        return {
            "reviewed_anomalies": len(reviewed),
            "false_positive_labels": false_positives,
            "false_positive_rate": None
            if not reviewed
            else round(false_positives / len(reviewed), 4),
            "label_definition": "retain_or_exception",
        }


def _feature_means(rows: list[dict[str, float]]) -> dict[str, float]:
    return {name: round(sum(row[name] for row in rows) / len(rows), 6) for name in FEATURES}


def load_anomaly_results(session: Session, identity_id: uuid.UUID) -> list[AnomalyResult]:
    return list(
        session.scalars(
            select(AnomalyResult)
            .options(selectinload(AnomalyResult.run))
            .where(AnomalyResult.identity_id == identity_id)
            .order_by(AnomalyResult.id.desc())
        )
    )
