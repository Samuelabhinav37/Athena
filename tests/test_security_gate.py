import json
from pathlib import Path
from typing import Any

from athena.policy.opa import OpaDecision
from athena.services.security_gate import SecurityGateService


class FixturePolicyEngine:
    def evaluate(self, policy_input: dict[str, Any]) -> OpaDecision:
        codes = []
        if policy_input["permission"]["privileged"]:
            if policy_input["governance"]["gaps"]:
                codes.append("UNGOVERNED_PRIVILEGED_ACCESS")
            if not policy_input["authentication"]["phishing_resistant"]:
                codes.append("PRIVILEGED_MFA_REQUIRED")
        if (
            "developer" in policy_input["identity"]["roles"]
            and policy_input["resource"]["external_id"] == "payroll"
        ):
            codes.append("DEVELOPER_PAYROLL_ACCESS")
        if (
            policy_input["governance"]["requested_by"]
            == policy_input["governance"]["approved_by"]
        ):
            codes.append("REQUESTER_APPROVER_CONFLICT")
        return OpaDecision(
            allow=not codes,
            violations=[{"code": code} for code in reversed(codes)],
        )


class UnsafeAllowEngine:
    def evaluate(self, _: dict[str, Any]) -> OpaDecision:
        return OpaDecision(allow=True, violations=[])


def test_security_gate_validates_fixtures_controls_and_reports(tmp_path: Path) -> None:
    result = SecurityGateService(
        engine=FixturePolicyEngine(),
        policy_directory=Path("policies"),
        control_directory=Path("controls"),
        output_directory=tmp_path,
    ).run()

    assert result.passed is True
    assert result.fixture_count == 4
    assert result.fixture_failures == 0
    assert result.control_count == 3
    assert result.control_failures == 0
    report = json.loads(result.report_json.read_text(encoding="utf-8"))
    assert report["status"] == "pass"
    denied = next(
        fixture for fixture in report["fixtures"] if fixture["id"] == "ungoverned-production-access"
    )
    assert denied["actual"] == {
        "allow": False,
        "violation_codes": [
            "PRIVILEGED_MFA_REQUIRED",
            "UNGOVERNED_PRIVILEGED_ACCESS",
        ],
    }
    assert "Athena Security Gate" in result.report_markdown.read_text(encoding="utf-8")


def test_security_gate_fails_when_denials_become_allowed(tmp_path: Path) -> None:
    result = SecurityGateService(
        engine=UnsafeAllowEngine(),
        policy_directory=Path("policies"),
        control_directory=Path("controls"),
        output_directory=tmp_path,
    ).run()

    assert result.passed is False
    assert result.fixture_failures == 3
    assert result.report_json.is_file()
