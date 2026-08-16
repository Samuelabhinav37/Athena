import hashlib
import json
import random
import uuid
from dataclasses import dataclass

import sklearn
from sklearn.ensemble import IsolationForest
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from athena.models import AnomalyModelRun, AnomalyResult, Identity, RiskAssessment

MODEL_VERSION = "peer-isolation-forest-v1"
RANDOM_SEED = 20260816
CONTAMINATION = 0.05
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
class PeerAnomalyOutcome:
    run_id: uuid.UUID
    result_id: uuid.UUID
    is_anomaly: bool
    decision_score: float
    training_fingerprint: str
    peer_anomaly_count: int


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
        total = max(assessment.summary["active_entitlements"], 1)
        findings = assessment.findings
        live = {
            "entitlement_count": float(total),
            "privileged_ratio": sum(f.factors["privilege"]["value"] for f in findings) / total,
            "critical_ratio": sum(f.factors["sensitivity"]["value"] for f in findings) / total,
            "stale_ratio": sum(f.factors["time_since_use"]["value"] for f in findings) / total,
            "policy_failure_ratio": sum(f.factors["policy_risk"]["value"] for f in findings)
            / total,
            "retained_ratio": assessment.summary["retained_entitlements"] / total,
            "peer_deviation_ratio": assessment.summary["peer_deviations"] / total,
        }
        cohort = synthetic_security_cohort()
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
        means = {name: sum(row[name] for row in cohort) / len(cohort) for name in FEATURES}
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
        run = AnomalyModelRun(
            algorithm="IsolationForest",
            library_version=sklearn.__version__,
            model_version=MODEL_VERSION,
            random_seed=RANDOM_SEED,
            contamination=CONTAMINATION,
            feature_schema=FEATURES,
            training_fingerprint=fingerprint,
            sample_size=len(cohort),
            peer_definition={"department": identity.department, "cohort": "synthetic-security-v1"},
            summary={
                "advisory_only": True,
                "peer_anomaly_count": int(sum(p == -1 for p in predictions[:-1])),
            },
        )
        self.session.add(run)
        for index, (row, raw, decision, prediction) in enumerate(
            zip(all_rows, raw_scores, decisions, predictions, strict=True)
        ):
            is_live = index == len(cohort)
            result = AnomalyResult(
                run=run,
                identity_id=identity.id if is_live else None,
                subject_key=identity.username if is_live else f"synthetic-security-{index + 1:03d}",
                synthetic=not is_live,
                score_samples=float(raw),
                decision_score=float(decision),
                is_anomaly=bool(prediction == -1),
                features=row,
                explanation={
                    "top_deviations": deviations if is_live else [],
                    "advisory_only": True,
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
            run.summary["peer_anomaly_count"],
        )


def load_anomaly_results(session: Session, identity_id: uuid.UUID) -> list[AnomalyResult]:
    return list(
        session.scalars(
            select(AnomalyResult)
            .options(selectinload(AnomalyResult.run))
            .where(AnomalyResult.identity_id == identity_id)
            .order_by(AnomalyResult.id.desc())
        )
    )
