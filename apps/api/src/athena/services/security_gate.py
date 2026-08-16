import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from athena.policy.opa import OpaDecision
from athena.services.policy_evaluation import hash_policy_bundle


class GatePolicyEngine(Protocol):
    def evaluate(self, policy_input: dict[str, Any]) -> OpaDecision: ...


class SecurityGateError(RuntimeError):
    pass


@dataclass(frozen=True)
class SecurityGateResult:
    passed: bool
    fixture_count: int
    fixture_failures: int
    control_count: int
    control_failures: int
    policy_version: str
    report_json: Path
    report_markdown: Path


class SecurityGateService:
    def __init__(
        self,
        engine: GatePolicyEngine,
        policy_directory: Path,
        control_directory: Path,
        output_directory: Path,
    ) -> None:
        self.engine = engine
        self.policy_directory = policy_directory
        self.control_directory = control_directory
        self.output_directory = output_directory

    def run(self) -> SecurityGateResult:
        policy_version = hash_policy_bundle(self.policy_directory)
        fixture_results = [
            self._evaluate_fixture(path)
            for path in sorted((self.policy_directory / "fixtures").glob("*.json"))
        ]
        if not fixture_results:
            raise SecurityGateError("No policy fixtures were found")
        control_results = [
            self._validate_control(path)
            for path in sorted(self.control_directory.glob("*.json"))
        ]
        if not control_results:
            raise SecurityGateError("No control mappings were found")

        fixture_failures = sum(not result["matched"] for result in fixture_results)
        control_failures = sum(not result["valid"] for result in control_results)
        passed = fixture_failures == 0 and control_failures == 0
        report = {
            "schema_version": "1.0",
            "status": "pass" if passed else "fail",
            "policy_version": policy_version,
            "summary": {
                "fixtures": len(fixture_results),
                "fixture_failures": fixture_failures,
                "controls": len(control_results),
                "control_failures": control_failures,
            },
            "fixtures": fixture_results,
            "controls": control_results,
        }
        self.output_directory.mkdir(parents=True, exist_ok=True)
        json_path = self.output_directory / "security-gate-report.json"
        markdown_path = self.output_directory / "security-gate-report.md"
        json_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        markdown_path.write_text(self._markdown(report), encoding="utf-8")
        return SecurityGateResult(
            passed=passed,
            fixture_count=len(fixture_results),
            fixture_failures=fixture_failures,
            control_count=len(control_results),
            control_failures=control_failures,
            policy_version=policy_version,
            report_json=json_path,
            report_markdown=markdown_path,
        )

    def _evaluate_fixture(self, path: Path) -> dict[str, Any]:
        fixture = self._load_object(path)
        fixture_id = self._required_string(fixture, "id", path)
        policy_input = fixture.get("input")
        expected = fixture.get("expected")
        if not isinstance(policy_input, dict) or not isinstance(expected, dict):
            raise SecurityGateError(f"Fixture {path} requires object input and expected fields")
        expected_allow = expected.get("allow")
        expected_codes = expected.get("violation_codes")
        if not isinstance(expected_allow, bool) or not isinstance(expected_codes, list):
            raise SecurityGateError(f"Fixture {path} has an invalid expected decision")
        if not all(isinstance(code, str) for code in expected_codes):
            raise SecurityGateError(f"Fixture {path} has non-string violation codes")

        decision = self.engine.evaluate(policy_input)
        actual_codes = sorted(str(item.get("code", "")) for item in decision.violations)
        expected_codes = sorted(expected_codes)
        matched = decision.allow == expected_allow and actual_codes == expected_codes
        return {
            "id": fixture_id,
            "description": fixture.get("description", ""),
            "expected": {"allow": expected_allow, "violation_codes": expected_codes},
            "actual": {"allow": decision.allow, "violation_codes": actual_codes},
            "matched": matched,
        }

    def _validate_control(self, path: Path) -> dict[str, Any]:
        control = self._load_object(path)
        control_id = self._required_string(control, "control_id", path)
        checks = control.get("automated_checks")
        errors = []
        if control.get("status") not in {"partial", "implemented"}:
            errors.append("status must be partial or implemented")
        if not isinstance(checks, list) or not checks:
            errors.append("at least one automated check is required")
            checks = []
        policy_source = "\n".join(
            policy.read_text(encoding="utf-8")
            for policy in self.policy_directory.rglob("*.rego")
            if not policy.name.endswith("_test.rego")
        )
        for check in checks:
            if not isinstance(check, dict):
                errors.append("automated check must be an object")
                continue
            check_type = check.get("type")
            reference = check.get("reference")
            if not isinstance(reference, str) or not reference:
                errors.append("automated check requires a reference")
                continue
            if check_type == "rego_rule" and reference not in policy_source:
                errors.append(f"missing Rego rule: {reference}")
            elif check_type in {"pytest", "policy_fixture"} and not Path(reference).is_file():
                errors.append(f"missing evidence file: {reference}")
            elif check_type not in {"rego_rule", "pytest", "policy_fixture", "database"}:
                errors.append(f"unsupported check type: {check_type}")
        return {
            "control_id": control_id,
            "title": control.get("title", ""),
            "status": control.get("status", ""),
            "automated_checks": len(checks),
            "valid": not errors,
            "errors": errors,
            "limitations": control.get("limitations", []),
        }

    @staticmethod
    def _load_object(path: Path) -> dict[str, Any]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise SecurityGateError(f"Could not read JSON document {path}") from error
        if not isinstance(payload, dict):
            raise SecurityGateError(f"JSON document {path} must contain an object")
        return payload

    @staticmethod
    def _required_string(payload: dict[str, Any], field: str, path: Path) -> str:
        value = payload.get(field)
        if not isinstance(value, str) or not value:
            raise SecurityGateError(f"Document {path} requires string field {field}")
        return value

    @staticmethod
    def _markdown(report: dict[str, Any]) -> str:
        status = report["status"].upper()
        lines = [
            "# Athena Security Gate",
            "",
            f"**Status:** {status}",
            "",
            f"**Policy version:** `{report['policy_version']}`",
            "",
            "## Policy fixtures",
            "",
            "| Fixture | Expected | Actual | Result |",
            "|---|---|---|---|",
        ]
        for fixture in report["fixtures"]:
            expected = "ALLOW" if fixture["expected"]["allow"] else "DENY"
            actual = "ALLOW" if fixture["actual"]["allow"] else "DENY"
            result = "PASS" if fixture["matched"] else "FAIL"
            lines.append(f"| {fixture['id']} | {expected} | {actual} | {result} |")
        lines.extend(
            [
                "",
                "## Control mappings",
                "",
                "| Control | Status | Checks | Validation |",
                "|---|---|---:|---|",
            ]
        )
        for control in report["controls"]:
            validation = "PASS" if control["valid"] else "FAIL"
            lines.append(
                f"| {control['control_id']} | {control['status']} | "
                f"{control['automated_checks']} | {validation} |"
            )
        return "\n".join(lines) + "\n"
