import hashlib
import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, model_validator


class BackupContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    rpo_minutes: int = Field(gt=0, le=1440)
    rto_minutes: int = Field(gt=0, le=1440)
    encryption_required: bool
    restore_test_interval_days: int = Field(gt=0, le=90)


class ResidencyContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    allowed_regions: tuple[str, ...] = Field(min_length=1)
    cross_region_replication: str


class RetentionContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    immutable_evidence_days: int = Field(ge=365)
    operational_control_days: int = Field(ge=1)
    security_gate_artifact_days: int = Field(ge=1)


class DeletionContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    automatic_evidence_deletion: bool
    requires_approval_reference: bool
    requires_export_digest: bool
    requires_audit_event: bool


class DataLifecycleContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: str
    authoritative_store: str
    backup: BackupContract
    residency: ResidencyContract
    retention: RetentionContract
    deletion: DeletionContract

    @model_validator(mode="after")
    def preserve_evidence_controls(self) -> "DataLifecycleContract":
        if self.authoritative_store != "postgresql":
            raise ValueError("PostgreSQL must remain the authoritative store")
        if not self.backup.encryption_required:
            raise ValueError("Backups must be encrypted")
        if self.deletion.automatic_evidence_deletion:
            raise ValueError("Immutable evidence cannot be deleted automatically")
        if not all(
            (
                self.deletion.requires_approval_reference,
                self.deletion.requires_export_digest,
                self.deletion.requires_audit_event,
            )
        ):
            raise ValueError("Deletion requires approval, export digest, and audit evidence")
        return self

    @property
    def sha256(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
        return hashlib.sha256(canonical).hexdigest()


def load_data_lifecycle_contract(path: Path) -> DataLifecycleContract:
    return DataLifecycleContract.model_validate_json(path.read_text(encoding="utf-8"))
