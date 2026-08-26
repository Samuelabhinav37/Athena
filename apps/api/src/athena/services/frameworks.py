import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

FRAMEWORK_CONTRACT_VERSION = "1.0"
ATHENA_OSCAL_NAMESPACE = "https://athena.example/ns/oscal"
NIST_CATALOG_HREF = "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
_UUID_NAMESPACE = uuid.UUID("3de39af4-931d-5c30-a78d-b003ae5b6155")


class FrameworkContractError(ValueError):
    pass


class AutomatedEvidenceLink(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    type: Literal["pytest", "database", "rego_rule", "policy_fixture"]
    reference: str = Field(min_length=1, max_length=500)
    evidence: str = Field(min_length=1, max_length=2000)

    @field_validator("reference")
    @classmethod
    def reject_unsafe_file_reference(cls, value: str) -> str:
        if value.startswith(("/", "\\")) or ".." in PurePosixPath(value.replace("\\", "/")).parts:
            raise ValueError("evidence reference must not be absolute or traverse directories")
        return value


class FrameworkControlMapping(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    control_id: str = Field(pattern=r"^NIST-SP-800-53-[A-Z]{2}-[0-9]+(?:\([0-9]+\))?$")
    title: str = Field(min_length=1, max_length=256)
    status: Literal["partial", "implemented", "not_applicable"]
    objective: str = Field(min_length=1, max_length=2000)
    automated_checks: tuple[AutomatedEvidenceLink, ...] = Field(min_length=1)
    limitations: tuple[str, ...] = Field(min_length=1)

    @property
    def oscal_control_id(self) -> str:
        return self.control_id.removeprefix("NIST-SP-800-53-").lower()


class FrameworkPack(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal[FRAMEWORK_CONTRACT_VERSION] = FRAMEWORK_CONTRACT_VERSION
    framework_id: Literal["nist-sp-800-53-rev5"] = "nist-sp-800-53-rev5"
    title: Literal["NIST SP 800-53 Revision 5"] = "NIST SP 800-53 Revision 5"
    catalog_href: Literal[NIST_CATALOG_HREF] = NIST_CATALOG_HREF
    controls: tuple[FrameworkControlMapping, ...]
    content_sha256: str


class OscalProperty(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str
    value: str
    ns: Literal[ATHENA_OSCAL_NAMESPACE] = ATHENA_OSCAL_NAMESPACE


class OscalLink(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    href: str
    rel: str
    text: str


class OscalImplementedRequirement(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    uuid: uuid.UUID
    control_id: str = Field(serialization_alias="control-id")
    description: str
    props: tuple[OscalProperty, ...]
    links: tuple[OscalLink, ...]


class OscalControlImplementation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    uuid: uuid.UUID
    source: str
    description: str
    implemented_requirements: tuple[OscalImplementedRequirement, ...] = Field(
        serialization_alias="implemented-requirements"
    )


class OscalComponent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    uuid: uuid.UUID
    type: Literal["software"] = "software"
    title: Literal["Athena Identity Governance"] = "Athena Identity Governance"
    description: str
    props: tuple[OscalProperty, ...]
    control_implementations: tuple[OscalControlImplementation, ...] = Field(
        serialization_alias="control-implementations"
    )


class OscalMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    title: str
    last_modified: datetime = Field(serialization_alias="last-modified")
    version: str
    oscal_version: str = Field(serialization_alias="oscal-version")


class OscalComponentDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    uuid: uuid.UUID
    metadata: OscalMetadata
    components: tuple[OscalComponent, ...]


class OscalComponentDocument(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    component_definition: OscalComponentDefinition = Field(
        serialization_alias="component-definition"
    )


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _stable_uuid(name: str) -> uuid.UUID:
    return uuid.uuid5(_UUID_NAMESPACE, name)


def load_framework_pack(directory: Path) -> FrameworkPack:
    controls = []
    for path in sorted(directory.glob("nist-*.json")):
        try:
            controls.append(FrameworkControlMapping.model_validate_json(path.read_bytes()))
        except (OSError, ValueError) as error:
            raise FrameworkContractError(f"Invalid framework mapping: {path.name}") from error
    if not controls:
        raise FrameworkContractError("Framework pack must contain at least one control")
    controls.sort(key=lambda item: item.control_id)
    ids = [item.control_id for item in controls]
    if len(ids) != len(set(ids)):
        raise FrameworkContractError("Framework pack contains duplicate control IDs")
    facts = {
        "contract_version": FRAMEWORK_CONTRACT_VERSION,
        "framework_id": "nist-sp-800-53-rev5",
        "title": "NIST SP 800-53 Revision 5",
        "catalog_href": NIST_CATALOG_HREF,
        "controls": [item.model_dump(mode="json") for item in controls],
    }
    return FrameworkPack(
        **facts,
        content_sha256=hashlib.sha256(_canonical(facts)).hexdigest(),
    )


def build_oscal_component_definition(
    pack: FrameworkPack, *, last_modified: datetime
) -> OscalComponentDocument:
    if last_modified.tzinfo is None or last_modified.utcoffset() is None:
        raise FrameworkContractError("OSCAL last-modified must include a timezone")
    requirements = []
    for control in pack.controls:
        links = tuple(
            OscalLink(
                href=_evidence_href(item),
                rel="evidence",
                text=item.evidence,
            )
            for item in control.automated_checks
        )
        props = (
            OscalProperty(name="implementation-status", value=control.status),
            *(OscalProperty(name="limitation", value=item) for item in control.limitations),
        )
        requirements.append(
            OscalImplementedRequirement(
                uuid=_stable_uuid(f"{pack.content_sha256}:{control.control_id}"),
                control_id=control.oscal_control_id,
                description=control.objective,
                props=props,
                links=links,
            )
        )
    implementation = OscalControlImplementation(
        uuid=_stable_uuid(f"{pack.content_sha256}:control-implementation"),
        source=pack.catalog_href,
        description="Athena automated identity-governance control evidence mappings.",
        implemented_requirements=tuple(requirements),
    )
    component = OscalComponent(
        uuid=_stable_uuid(f"{pack.content_sha256}:component"),
        description=(
            "Athena continuously evaluates identity-governance evidence. Partial mappings do not "
            "represent certification or complete control implementation."
        ),
        props=(OscalProperty(name="evidence-authority", value="deterministic-only"),),
        control_implementations=(implementation,),
    )
    return OscalComponentDocument(
        component_definition=OscalComponentDefinition(
            uuid=_stable_uuid(f"{pack.content_sha256}:document"),
            metadata=OscalMetadata(
                title="Athena NIST SP 800-53 Control Evidence",
                last_modified=last_modified,
                version=pack.content_sha256[:12],
                oscal_version="1.1.3",
            ),
            components=(component,),
        )
    )


def _evidence_href(item: AutomatedEvidenceLink) -> str:
    if item.type in {"pytest", "policy_fixture"}:
        return item.reference.replace("\\", "/")
    return f"urn:athena:{item.type.replace('_', '-')}:{item.reference}"
