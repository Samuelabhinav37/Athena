import json
from pathlib import Path

from athena.services.readiness import load_readiness_manifest


def test_readiness_manifest_reconciles_real_implemented_evidence() -> None:
    manifest = load_readiness_manifest(Path("governance/readiness.json"))
    manifest.verify_evidence(Path("."))

    assert manifest.implementation_ready is True
    assert manifest.production_ready is False
    assert manifest.ready is False
    assert manifest.production_status == "blocked"
    assert len(manifest.production_blockers) == 5
    assert all(item.status == "implemented" for item in manifest.workstreams)
    assert len(manifest.sha256) == 64


def test_production_evidence_template_cannot_be_mistaken_for_evidence() -> None:
    template = json.loads(
        Path("governance/production-evidence.example.json").read_text(encoding="utf-8")
    )

    assert template["status"] == "template_not_evidence"
    assert template["recovery"]["rpo_minutes"] is None
    assert template["recovery"]["rto_minutes"] is None
    assert all(
        template["supply_chain"][key].endswith("-required")
        for key in ("sbom_sha256", "api_image_digest", "web_image_digest")
    )
