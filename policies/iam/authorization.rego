package athena.authorization

import rego.v1

violations contains violation if {
    input.permission.privileged
    count(input.governance.gaps) > 0
    violation := {
        "code": "UNGOVERNED_PRIVILEGED_ACCESS",
        "severity": "high",
        "rule": "privileged_access_requires_governance",
        "message": "Privileged access is missing required governance evidence",
        "evidence": {"gaps": input.governance.gaps},
    }
}

violations contains violation if {
    input.permission.privileged
    not input.authentication.phishing_resistant
    violation := {
        "code": "PRIVILEGED_MFA_REQUIRED",
        "severity": "high",
        "rule": "privileged_access_requires_phishing_resistant_mfa",
        "message": "Privileged access requires phishing-resistant authentication",
        "evidence": {"authentication": input.authentication},
    }
}

violations contains violation if {
    "developer" in input.identity.roles
    input.resource.external_id == "payroll"
    violation := {
        "code": "DEVELOPER_PAYROLL_ACCESS",
        "severity": "critical",
        "rule": "developers_cannot_access_payroll",
        "message": "Developers cannot access Payroll",
        "evidence": {"roles": input.identity.roles, "resource": input.resource.external_id},
    }
}

violations contains violation if {
    input.governance.requested_by != null
    input.governance.requested_by == input.governance.approved_by
    violation := {
        "code": "REQUESTER_APPROVER_CONFLICT",
        "severity": "high",
        "rule": "requester_cannot_approve_own_access",
        "message": "The requester cannot approve their own access",
        "evidence": {"identity": input.governance.requested_by},
    }
}

evaluate := {
    "allow": count(violations) == 0,
    "violations": violations,
}
