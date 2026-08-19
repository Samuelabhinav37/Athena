import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from athena.services.frameworks import (
    NIST_CATALOG_HREF,
    FrameworkContractError,
    build_oscal_component_definition,
    load_framework_pack,
)


def test_nist_framework_pack_is_deterministic_and_complete() -> None:
    first = load_framework_pack(Path("controls"))
    second = load_framework_pack(Path("controls"))

    assert first == second
    assert len(first.content_sha256) == 64
    assert [control.oscal_control_id for control in first.controls] == ["ac-2", "ac-5", "ac-6"]
    assert all(control.status == "partial" for control in first.controls)


def test_component_definition_uses_oscal_shape_and_preserves_evidence() -> None:
    pack = load_framework_pack(Path("controls"))
    modified = datetime(2026, 8, 19, 20, 0, tzinfo=UTC)

    first = build_oscal_component_definition(pack, last_modified=modified)
    second = build_oscal_component_definition(pack, last_modified=modified)
    payload = first.model_dump(mode="json", by_alias=True)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    definition = payload["component-definition"]
    implementation = definition["components"][0]["control-implementations"][0]

    assert first == second
    assert implementation["source"] == NIST_CATALOG_HREF
    assert [item["control-id"] for item in implementation["implemented-requirements"]] == [
        "ac-2",
        "ac-5",
        "ac-6",
    ]
    assert "Generated LLM" not in encoded
    assert "implementation-status" in encoded
    assert "partial" in encoded


def test_framework_contract_rejects_unsafe_or_invalid_sources(tmp_path: Path) -> None:
    invalid = {
        "control_id": "NIST-SP-800-53-AC-2",
        "title": "Account Management",
        "status": "partial",
        "objective": "Manage accounts.",
        "automated_checks": [
            {"type": "pytest", "reference": "../secret", "evidence": "Unsafe reference."}
        ],
        "limitations": ["Incomplete organizational evidence."],
    }
    (tmp_path / "nist-invalid.json").write_text(json.dumps(invalid), encoding="utf-8")

    with pytest.raises(FrameworkContractError, match="Invalid framework mapping"):
        load_framework_pack(tmp_path)
    with pytest.raises(FrameworkContractError, match="timezone"):
        build_oscal_component_definition(
            load_framework_pack(Path("controls")),
            last_modified=datetime(2026, 8, 19, 20, 0),
        )
