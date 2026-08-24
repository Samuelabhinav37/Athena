from pathlib import Path

from athena.services.readiness import load_readiness_manifest


def test_readiness_manifest_reconciles_real_implemented_evidence() -> None:
    manifest = load_readiness_manifest(Path("governance/readiness.json"))
    manifest.verify_evidence(Path("."))

    assert manifest.ready is True
    assert all(item.status == "implemented" for item in manifest.workstreams)
    assert len(manifest.sha256) == 64
