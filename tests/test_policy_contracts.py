import json

import httpx
from athena.policy.contracts import (
    CanonicalPolicyRequest,
    PolicyAction,
    PolicyAuthenticationContext,
    PolicyGovernanceContext,
    PolicyPrincipal,
    PolicyRequestContext,
    PolicyResource,
)
from athena.policy.opa import OpaAuthorizationAdapter, OpaClient


def _request() -> CanonicalPolicyRequest:
    return CanonicalPolicyRequest(
        principal=PolicyPrincipal(
            id="identity-1",
            type="human",
            username="alice",
            department="engineering",
            roles=("developer",),
            groups=("/engineering",),
        ),
        action=PolicyAction(
            id="permission-1", verb="write", name="Repository Write", privileged=False
        ),
        resource=PolicyResource(
            id="resource-1",
            external_id="github",
            name="GitHub",
            type="repository",
            sensitivity="moderate",
        ),
        context=PolicyRequestContext(
            governance=PolicyGovernanceContext(
                requested_by="alice",
                approved_by="bob",
                business_reason="Application development",
                policy_reference="POL-IAM-DEV-001",
                granted_at="2026-08-19T12:00:00+00:00",
            ),
            authentication=PolicyAuthenticationContext(
                method="webauthn", phishing_resistant=True
            ),
        ),
    )


def test_canonical_request_maps_to_existing_opa_semantics() -> None:
    mapped = _request().to_opa_v1_input()

    assert mapped["schema_version"] == "1.0"
    assert mapped["identity"]["username"] == "alice"
    assert mapped["permission"]["action"] == "write"
    assert mapped["resource"]["external_id"] == "github"
    assert mapped["governance"]["approved_by"] == "bob"
    assert mapped["authentication"]["phishing_resistant"] is True


def test_opa_adapter_sends_only_translated_request() -> None:
    def handler(http_request: httpx.Request) -> httpx.Response:
        payload = json.loads(http_request.read())
        assert payload["input"] == _request().to_opa_v1_input()
        assert "principal" not in payload["input"]
        return httpx.Response(200, json={"result": {"allow": True, "violations": []}})

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        decision = OpaAuthorizationAdapter(OpaClient("http://opa.test", http_client)).evaluate(
            _request()
        )

    assert decision.allow is True
