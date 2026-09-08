"""Verify the deployed agent-action policy, not just policy files on disk."""

from athena.config import get_settings
from athena.policy.opa import OpaClient


def main() -> None:
    cases = (
        ({"action": "allowed_override", "reason": "Known vendor false positive"}, True, set()),
        ({"action": "allowed_override", "reason": "short"}, False, {"UNJUSTIFIED_OVERRIDE"}),
        ({"action": "deleted"}, False, {"UNSUPPORTED_AGENT_ACTION"}),
    )
    with OpaClient(get_settings().opa_url) as client:
        client.policy_path = "athena/security/agent_actions/evaluate"
        for policy_input, expected_allow, expected_codes in cases:
            decision = client.evaluate(policy_input)
            codes = {violation["code"] for violation in decision.violations}
            if decision.allow != expected_allow or codes != expected_codes:
                raise RuntimeError("Deployed agent-action policy returned an unexpected decision")
    print("Deployed agent-action policy: 3/3 checks passed")


if __name__ == "__main__":
    main()
