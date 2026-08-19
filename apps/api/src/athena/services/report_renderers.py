import hashlib
import json
from dataclasses import dataclass
from typing import Literal, Protocol

from pydantic import BaseModel, ConfigDict

from athena.schemas import EvidenceReportResponse
from athena.services.evidence_report import verify_evidence_report


class EvidenceRenderError(ValueError):
    pass


class RendererManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1.0"] = "1.0"
    renderer_id: str
    format: Literal["json", "markdown", "oscal", "pdf", "docx"]
    media_type: str
    file_extension: str
    deterministic: Literal[True] = True
    authoritative_facts_only: Literal[True] = True


@dataclass(frozen=True)
class RenderedEvidenceArtifact:
    manifest: RendererManifest
    source_evidence_digest: str
    content: bytes
    content_sha256: str


class EvidenceRenderer(Protocol):
    manifest: RendererManifest

    def render(self, report: EvidenceReportResponse) -> RenderedEvidenceArtifact: ...


def _validated(report: EvidenceReportResponse) -> EvidenceReportResponse:
    validated = EvidenceReportResponse.model_validate(report.model_dump())
    if not verify_evidence_report(validated):
        raise EvidenceRenderError("Evidence report digest does not match authoritative facts")
    return validated


def _artifact(
    manifest: RendererManifest, report: EvidenceReportResponse, content: bytes
) -> RenderedEvidenceArtifact:
    return RenderedEvidenceArtifact(
        manifest=manifest,
        source_evidence_digest=report.evidence_digest,
        content=content,
        content_sha256=hashlib.sha256(content).hexdigest(),
    )


class JSONEvidenceRenderer:
    manifest = RendererManifest(
        renderer_id="athena.evidence.json",
        format="json",
        media_type="application/json",
        file_extension=".json",
    )

    def render(self, report: EvidenceReportResponse) -> RenderedEvidenceArtifact:
        validated = _validated(report)
        content = (
            json.dumps(
                validated.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode()
            + b"\n"
        )
        return _artifact(self.manifest, validated, content)


class MarkdownEvidenceRenderer:
    manifest = RendererManifest(
        renderer_id="athena.evidence.markdown",
        format="markdown",
        media_type="text/markdown; charset=utf-8",
        file_extension=".md",
    )

    def render(self, report: EvidenceReportResponse) -> RenderedEvidenceArtifact:
        validated = _validated(report)
        lines = [
            "# Athena Authorization Evidence Report",
            "",
            f"**Generated:** {validated.generated_at.isoformat()}",
            f"**Evidence digest:** `{validated.evidence_digest}`",
            f"**Scope:** {validated.scope}",
            "",
            "## Inventory",
            "",
            "| Measure | Value |",
            "|---|---:|",
        ]
        lines.extend(
            f"| {name.replace('_', ' ').title()} | {value if value is not None else 'N/A'} |"
            for name, value in validated.inventory.items()
        )
        lines.extend(
            [
                "",
                "## NIST control mappings",
                "",
                "| Control | Status | Checks |",
                "|---|---|---:|",
            ]
        )
        lines.extend(
            f"| {control.control_id} — {control.title} | {control.status} | "
            f"{control.automated_checks} |"
            for control in validated.controls
        )
        lines.extend(["", "## Limitations", ""])
        lines.extend(f"- {limitation}" for limitation in validated.limitations)
        lines.extend(["", "Generated LLM explanations are not authoritative report evidence.", ""])
        return _artifact(self.manifest, validated, "\n".join(lines).encode())


RENDERERS: dict[str, EvidenceRenderer] = {
    "json": JSONEvidenceRenderer(),
    "markdown": MarkdownEvidenceRenderer(),
}
