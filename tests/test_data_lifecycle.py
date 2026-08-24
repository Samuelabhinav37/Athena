import json
from pathlib import Path

import pytest
from athena.services.data_lifecycle import DataLifecycleContract, load_data_lifecycle_contract
from pydantic import ValidationError


def test_repository_data_lifecycle_contract_is_fail_closed() -> None:
    contract = load_data_lifecycle_contract(Path("governance/data-lifecycle.json"))

    assert contract.authoritative_store == "postgresql"
    assert contract.backup.encryption_required is True
    assert contract.deletion.automatic_evidence_deletion is False
    assert len(contract.sha256) == 64


def test_lifecycle_contract_rejects_automatic_evidence_deletion() -> None:
    payload = json.loads(Path("governance/data-lifecycle.json").read_text(encoding="utf-8"))
    payload["deletion"]["automatic_evidence_deletion"] = True

    with pytest.raises(ValidationError, match="cannot be deleted automatically"):
        DataLifecycleContract.model_validate(payload)
