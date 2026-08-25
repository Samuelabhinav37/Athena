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
