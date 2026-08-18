from datetime import UTC, datetime

from athena.collectors.aws_iam import AwsIamCollector, AwsIamSnapshot
from athena.config import Settings
from athena.models import AccessGrant, Base, EffectiveEntitlement, Identity
from athena.services.aws_iam_sync import AwsIamSyncService
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker


class FakeSts:
    def get_caller_identity(self) -> dict:
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/collector"}


class FakeIam:
    def __init__(self) -> None:
        self.authorization_calls = []
        self.key_calls = []
        self.role_calls = []

    def get_account_authorization_details(self, **parameters: object) -> dict:
        self.authorization_calls.append(parameters)
        if "Marker" not in parameters:
            return {
                "UserDetailList": [
                    {
                        "Path": "/",
                        "UserName": "alice",
                        "UserId": "AIDAALICE",
                        "Arn": "arn:aws:iam::123456789012:user/alice",
                        "GroupList": ["Security"],
                        "UserPolicyList": [],
                        "AttachedManagedPolicies": [],
                    }
                ],
                "GroupDetailList": [],
                "RoleDetailList": [
                    {
                        "Path": "/",
                        "RoleName": "SecurityAudit",
                        "RoleId": "AROASECURITY",
                        "Arn": "arn:aws:iam::123456789012:role/SecurityAudit",
                        "RolePolicyList": [],
                        "AttachedManagedPolicies": [],
                    }
                ],
                "Policies": [],
                "IsTruncated": True,
                "Marker": "page-2",
            }
        return {
            "UserDetailList": [],
            "GroupDetailList": [
                {
                    "Path": "/",
                    "GroupName": "Security",
                    "GroupId": "AGPASECURITY",
                    "Arn": "arn:aws:iam::123456789012:group/Security",
                    "GroupPolicyList": [],
                    "AttachedManagedPolicies": [],
                }
            ],
            "RoleDetailList": [],
            "Policies": [],
            "IsTruncated": False,
        }

    def list_access_keys(self, **parameters: object) -> dict:
        self.key_calls.append(parameters)
        return {
            "AccessKeyMetadata": [
                {
                    "UserName": "alice",
                    "AccessKeyId": "AKIATEST",
                    "Status": "Active",
                    "CreateDate": datetime(2026, 1, 1, tzinfo=UTC),
                }
            ],
            "IsTruncated": False,
        }

    def get_role(self, **parameters: object) -> dict:
        self.role_calls.append(parameters)
        return {
            "Role": {
                "RoleName": parameters["RoleName"],
                "Tags": [{"Key": "Owner", "Value": "platform-team"}],
                "RoleLastUsed": {
                    "LastUsedDate": datetime(2026, 8, 1, tzinfo=UTC),
                    "Region": "us-east-1",
                },
            }
        }


def test_collector_paginates_authorization_inventory_and_collects_key_age_evidence() -> None:
    iam = FakeIam()
    collector = AwsIamCollector(Settings(database_url="sqlite://"), iam, FakeSts())

    snapshot = collector.collect()

    assert snapshot.account_id == "123456789012"
    assert [user["UserName"] for user in snapshot.users] == ["alice"]
    assert [group["GroupName"] for group in snapshot.groups] == ["Security"]
    assert snapshot.access_keys[0]["AccessKeyId"] == "AKIATEST"
    assert snapshot.access_keys[0]["AgeDays"] >= 0
    assert len(iam.authorization_calls) == 2
    assert iam.authorization_calls[1]["Marker"] == "page-2"
    assert iam.key_calls == [{"UserName": "alice"}]
    assert iam.role_calls == [{"RoleName": "SecurityAudit"}]
    assert snapshot.roles[0]["AthenaPosture"]["Owner"] == "platform-team"
    assert snapshot.roles[0]["AthenaPosture"]["LastUsedRegion"] == "us-east-1"
    assert snapshot.endpoint_cache["inventory"]["counts"]["users"] == 1
    assert len(snapshot.fingerprint) == 64


def snapshot(fingerprint: str, include_policies: bool = True) -> AwsIamSnapshot:
    inline = [
        {
            "PolicyName": "AssumeSecurityRole",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": {
                    "Sid": "AssumeRole",
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:iam::123456789012:role/SecurityAudit",
                },
            },
        }
    ] if include_policies else []
    attached = [
        {"PolicyName": "ReadAuditBucket", "PolicyArn": "arn:aws:iam::123456789012:policy/ReadAudit"}
    ] if include_policies else []
    policies = [
        {
            "PolicyName": "ReadAuditBucket",
            "PolicyId": "ANPAREAD",
            "Arn": "arn:aws:iam::123456789012:policy/ReadAudit",
            "PolicyVersionList": [
                {
                    "VersionId": "v1",
                    "IsDefaultVersion": True,
                    "Document": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["s3:GetObject"],
                                "Resource": "arn:aws:s3:::audit/*",
                            },
                            {"Effect": "Deny", "Action": "s3:DeleteObject", "Resource": "*"},
                        ]
                    },
                }
            ],
        }
    ] if include_policies else []
    return AwsIamSnapshot(
        account_id="123456789012",
        users=[
            {
                "UserName": "alice",
                "UserId": "AIDAALICE",
                "Arn": "arn:aws:iam::123456789012:user/alice",
                "Path": "/",
                "GroupList": ["Security"],
                "UserPolicyList": inline,
                "AttachedManagedPolicies": [],
            }
        ],
        groups=[
            {
                "GroupName": "Security",
                "GroupId": "AGPASECURITY",
                "Path": "/",
                "GroupPolicyList": [],
                "AttachedManagedPolicies": attached,
            }
        ],
        roles=[
            {
                "RoleName": "SecurityAudit",
                "RoleId": "AROASECURITY",
                "Arn": "arn:aws:iam::123456789012:role/SecurityAudit",
                "Path": "/",
                "AssumeRolePolicyDocument": {"Statement": []},
                "RolePolicyList": [],
                "AttachedManagedPolicies": [],
                "AthenaPosture": {
                    "Owner": "platform-team",
                    "LastUsedAt": datetime(2026, 8, 1, tzinfo=UTC),
                    "LastUsedRegion": "us-east-1",
                },
            }
        ],
        policies=policies,
        access_keys=[
            {
                "UserName": "alice",
                "AccessKeyId": "AKIATEST",
                "Status": "Active",
                "CreateDate": datetime(2026, 1, 1, tzinfo=UTC),
                "AgeDays": 228,
            }
        ],
        endpoint_cache={"inventory": {"fingerprint": fingerprint}},
        fingerprint=fingerprint,
    )


def test_sync_materializes_policy_lineage_is_idempotent_and_revokes_removed_access() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    with factory() as session:
        service = AwsIamSyncService(session)
        initial = snapshot("a" * 64)
        first = service.sync(initial)
        second = service.sync(initial)

        alice = session.scalar(
            select(Identity).where(Identity.source == "aws_iam", Identity.username == "alice")
        )
        role = session.scalar(
            select(Identity).where(
                Identity.source == "aws_iam", Identity.username == "SecurityAudit"
            )
        )
        grants = list(session.scalars(select(AccessGrant).where(AccessGrant.source == "aws_iam")))
        entitlements = list(
            session.scalars(
                select(EffectiveEntitlement).where(EffectiveEntitlement.identity_id == alice.id)
            )
        )
        checkpoint = service.checkpoint("123456789012")

        assert alice is not None and role is not None and checkpoint is not None
        key_evidence = alice.source_metadata["access_keys"][0]
        assert key_evidence["status"] == "Active"
        assert key_evidence["created_at"] == "2026-01-01T00:00:00+00:00"
        assert key_evidence["age_days"] == 228
        assert role.identity_type.value == "service_account"
        assert role.source_metadata["owner"] == "platform-team"
        assert role.source_metadata["role_last_used_at"] == "2026-08-01T00:00:00+00:00"
        assert role.source_metadata["role_last_used_region"] == "us-east-1"
        assert "AthenaPosture" not in role.source_metadata
        assert "Tags" not in role.source_metadata
        assert first.grants_created == 2
        assert first.allowed_statements == 2
        assert second.unchanged is True
        assert len(grants) == 2
        assert len(entitlements) == 2
        relationships = {
            edge.relationship_type
            for entitlement in entitlements
            for edge in entitlement.provenance_edges
        }
        assert {"direct_grant", "member_of", "grants", "applies_to"} <= relationships
        assert all(grant.source_metadata["lineage_complete"] is False for grant in grants)

        removed = service.sync(snapshot("b" * 64, include_policies=False))
        assert removed.grants_revoked == 2
        assert all(grant.revoked_at is not None for grant in grants)
        assert all(not entitlement.active for entitlement in entitlements)

    engine.dispose()
