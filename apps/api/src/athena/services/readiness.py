import hashlib
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class WorkstreamReadiness(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(min_length=1)
    status: Literal["implemented", "pending_migration", "blocked"]
    evidence: tuple[Path, ...] = Field(min_length=1)


class ReadinessManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.1"]
    production_status: Literal["ready", "blocked"]
    production_blockers: tuple[str, ...]
    workstreams: tuple[WorkstreamReadiness, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def require_unique_workstreams(self) -> "ReadinessManifest":
        identifiers = [item.id for item in self.workstreams]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("Readiness workstream IDs must be unique")
        if self.production_status == "ready" and self.production_blockers:
            raise ValueError("Production-ready manifests cannot retain blockers")
        if self.production_status == "blocked" and not self.production_blockers:
            raise ValueError("Blocked production manifests must explain their blockers")
        return self

    @property
    def implementation_ready(self) -> bool:
        return all(item.status == "implemented" for item in self.workstreams)

    @property
    def production_ready(self) -> bool:
        return self.implementation_ready and self.production_status == "ready"

    @property
    def ready(self) -> bool:
        return self.production_ready

    @property
    def sha256(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
        return hashlib.sha256(canonical).hexdigest()

    def verify_evidence(self, root: Path) -> None:
        missing = [
            str(path)
            for item in self.workstreams
            for path in item.evidence
            if not (root / path).is_file()
        ]
        if missing:
            raise ValueError("Missing readiness evidence: " + ", ".join(sorted(missing)))


def load_readiness_manifest(path: Path) -> ReadinessManifest:
    return ReadinessManifest.model_validate_json(path.read_text(encoding="utf-8"))
