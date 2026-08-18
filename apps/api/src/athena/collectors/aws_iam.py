import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

from athena.config import Settings


class AwsIamCollectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class AwsIamSnapshot:
    account_id: str
    users: list[dict]
    groups: list[dict]
    roles: list[dict]
    policies: list[dict]
    access_keys: list[dict]
    endpoint_cache: dict
    fingerprint: str


class AwsIamCollector:
    """Collect account authorization details using read-only AWS APIs."""

    def __init__(
        self,
        settings: Settings,
        iam_client: Any | None = None,
        sts_client: Any | None = None,
    ) -> None:
        self.settings = settings
        if iam_client is None or sts_client is None:
            try:
                import boto3
            except ImportError as error:  # pragma: no cover - packaging guard
                raise AwsIamCollectionError("boto3 is required for AWS collection") from error
            session_args = {}
            if settings.aws_profile.strip():
                session_args["profile_name"] = settings.aws_profile.strip()
            session = boto3.Session(region_name=settings.aws_region, **session_args)
            iam_client = iam_client or session.client("iam")
            sts_client = sts_client or session.client("sts")
        self.iam = iam_client
        self.sts = sts_client

    def __enter__(self) -> "AwsIamCollector":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def collect(self, _endpoint_cache: dict | None = None) -> AwsIamSnapshot:
        try:
            account_id = str(self.sts.get_caller_identity()["Account"])
            details = self._authorization_details()
            users = details["UserDetailList"]
            groups = details["GroupDetailList"]
            roles = self._role_posture(details["RoleDetailList"])
            policies = details["Policies"]
            access_keys = self._access_keys(users)
        except (KeyError, TypeError, ValueError) as error:
            raise AwsIamCollectionError("AWS IAM response was missing required data") from error
        except Exception as error:
            raise AwsIamCollectionError("AWS IAM read-only collection failed") from error

        inventory = {
            "users": users,
            "groups": groups,
            "roles": roles,
            "policies": policies,
            "access_keys": access_keys,
        }
        canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":"), default=_json)
        fingerprint = hashlib.sha256(canonical.encode()).hexdigest()
        cache = {
            "inventory": {
                "fingerprint": fingerprint,
                "counts": {key: len(value) for key, value in inventory.items()},
            }
        }
        return AwsIamSnapshot(
            account_id, users, groups, roles, policies, access_keys, cache, fingerprint
        )

    def _authorization_details(self) -> dict[str, list[dict]]:
        combined = {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }
        marker = None
        while True:
            parameters = {
                "Filter": ["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]
            }
            if marker:
                parameters["Marker"] = marker
            response = self.iam.get_account_authorization_details(**parameters)
            for key in combined:
                payload = response.get(key, [])
                if not isinstance(payload, list):
                    raise AwsIamCollectionError(f"AWS IAM {key} was not a list")
                combined[key].extend(payload)
            if not response.get("IsTruncated"):
                break
            marker = response.get("Marker")
            if not marker:
                raise AwsIamCollectionError("AWS IAM pagination omitted Marker")
        return combined

    def _access_keys(self, users: list[dict]) -> list[dict]:
        keys = []
        for user in users:
            username = user["UserName"]
            marker = None
            while True:
                parameters = {"UserName": username}
                if marker:
                    parameters["Marker"] = marker
                response = self.iam.list_access_keys(**parameters)
                for key in response.get("AccessKeyMetadata", []):
                    created_at = key.get("CreateDate")
                    age_days = None
                    if isinstance(created_at, datetime):
                        if created_at.tzinfo is None:
                            created_at = created_at.replace(tzinfo=UTC)
                        age_days = max(0, (datetime.now(UTC) - created_at).days)
                    keys.append({**key, "UserName": username, "AgeDays": age_days})
                if not response.get("IsTruncated"):
                    break
                marker = response.get("Marker")
                if not marker:
                    raise AwsIamCollectionError("AWS access-key pagination omitted Marker")
        return keys

    def _role_posture(self, roles: list[dict]) -> list[dict]:
        enriched = []
        for role in roles:
            response = self.iam.get_role(RoleName=role["RoleName"])
            detail = response.get("Role")
            if not isinstance(detail, dict):
                raise AwsIamCollectionError("AWS IAM get_role response omitted Role")
            last_used = detail.get("RoleLastUsed", {})
            tags = detail.get("Tags", [])
            owner = next(
                (
                    tag.get("Value")
                    for tag in tags
                    if isinstance(tag, dict)
                    and str(tag.get("Key", "")).lower() in {"owner", "athena:owner"}
                    and isinstance(tag.get("Value"), str)
                    and tag["Value"].strip()
                ),
                None,
            )
            used_at = last_used.get("LastUsedDate") if isinstance(last_used, dict) else None
            enriched.append(
                {
                    **role,
                    "AthenaPosture": {
                        "Owner": owner,
                        "LastUsedAt": used_at,
                        "LastUsedRegion": (
                            last_used.get("Region") if isinstance(last_used, dict) else None
                        ),
                    },
                }
            )
        return enriched


def _json(value: Any) -> str:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    raise TypeError(f"Unsupported AWS response value: {type(value).__name__}")
