from dataclasses import dataclass
from typing import Any

import httpx

from athena.policy.contracts import CanonicalPolicyRequest


class OpaEvaluationError(RuntimeError):
    """Raised when OPA cannot return a complete, valid decision."""


@dataclass(frozen=True)
class OpaDecision:
    allow: bool
    violations: list[dict[str, Any]]


class OpaClient:
    policy_path = "athena/authorization/evaluate"

    def __init__(self, base_url: str, client: httpx.Client | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client or httpx.Client(timeout=httpx.Timeout(5.0))
        self._owns_client = client is None

    def __enter__(self) -> "OpaClient":
        return self

    def __exit__(self, *_: object) -> None:
        if self._owns_client:
            self.client.close()

    def evaluate(self, policy_input: dict[str, Any]) -> OpaDecision:
        url = f"{self.base_url}/v1/data/{self.policy_path}"
        try:
            response = self.client.post(url, json={"input": policy_input})
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise OpaEvaluationError(f"OPA request failed: POST {url}") from error

        result = payload.get("result") if isinstance(payload, dict) else None
        if not isinstance(result, dict) or not isinstance(result.get("allow"), bool):
            raise OpaEvaluationError("OPA response did not contain a valid decision")
        violations = result.get("violations")
        if not isinstance(violations, list) or not all(
            isinstance(violation, dict) for violation in violations
        ):
            raise OpaEvaluationError("OPA response did not contain a valid violations list")
        return OpaDecision(
            allow=result["allow"],
            violations=sorted(violations, key=lambda item: str(item.get("code", ""))),
        )


class OpaAuthorizationAdapter:
    """Translate Athena's canonical request to the existing authoritative Rego input."""

    def __init__(self, client: OpaClient) -> None:
        self.client = client
        self.policy_path = client.policy_path

    def evaluate(self, request: CanonicalPolicyRequest) -> OpaDecision:
        return self.client.evaluate(request.to_opa_v1_input())
