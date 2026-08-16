package athena.authorization_test

import data.athena.authorization.evaluate
import rego.v1

baseline_input := {
    "identity": {"username": "alice", "roles": ["developer"]},
    "resource": {"external_id": "github", "sensitivity": "moderate"},
    "permission": {"action": "write", "privileged": false},
    "governance": {
        "gaps": [],
        "requested_by": "alice",
        "approved_by": "bob",
    },
    "authentication": {"method": "webauthn", "phishing_resistant": true},
}

test_governed_non_privileged_access_passes if {
    result := evaluate with input as baseline_input
    result.allow
    count(result.violations) == 0
}

test_ungoverned_privileged_access_fails if {
    scenario := object.union_n([
        baseline_input,
        {"permission": {"action": "read", "privileged": true}},
        {"governance": {
            "gaps": ["missing_business_reason", "missing_expiration"],
            "requested_by": "alice",
            "approved_by": "bob",
        }},
    ])
    result := evaluate with input as scenario
    not result.allow
    some violation in result.violations
    violation.code == "UNGOVERNED_PRIVILEGED_ACCESS"
}

test_privileged_access_without_phishing_resistant_mfa_fails if {
    scenario := object.union_n([
        baseline_input,
        {"permission": {"action": "read", "privileged": true}},
        {"authentication": {"method": "password", "phishing_resistant": false}},
    ])
    result := evaluate with input as scenario
    not result.allow
    some violation in result.violations
    violation.code == "PRIVILEGED_MFA_REQUIRED"
}

test_developer_payroll_access_fails if {
    scenario := object.union(baseline_input, {"resource": {
        "external_id": "payroll",
        "sensitivity": "high",
    }})
    result := evaluate with input as scenario
    not result.allow
    some violation in result.violations
    violation.code == "DEVELOPER_PAYROLL_ACCESS"
}

test_requester_approver_conflict_fails if {
    scenario := object.union(baseline_input, {"governance": {
        "gaps": [],
        "requested_by": "alice",
        "approved_by": "alice",
    }})
    result := evaluate with input as scenario
    not result.allow
    some violation in result.violations
    violation.code == "REQUESTER_APPROVER_CONFLICT"
}
