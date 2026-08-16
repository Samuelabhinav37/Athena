import httpx
import pytest
from athena.policy.opa import OpaClient, OpaEvaluationError


def test_opa_client_validates_and_sorts_structured_decision() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/data/athena/authorization/evaluate"
        assert request.method == "POST"
        assert request.read()
        return httpx.Response(
            200,
            json={
                "result": {
                    "allow": False,
                    "violations": [
                        {"code": "Z_RULE", "message": "second"},
                        {"code": "A_RULE", "message": "first"},
                    ],
                }
            },
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = OpaClient("http://opa.test", client).evaluate({"schema_version": "1.0"})

    assert result.allow is False
    assert [violation["code"] for violation in result.violations] == ["A_RULE", "Z_RULE"]


def test_opa_client_rejects_undefined_decision() -> None:
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json={}))
    with (
        httpx.Client(transport=transport) as client,
        pytest.raises(OpaEvaluationError, match="valid decision"),
    ):
        OpaClient("http://opa.test", client).evaluate({})
