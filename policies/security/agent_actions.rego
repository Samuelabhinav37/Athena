package athena.security.agent_actions

import rego.v1

local_protection_actions := {"blocked", "warned", "quarantined"}

violations contains {
    "code": "UNSUPPORTED_AGENT_ACTION",
    "severity": "high",
    "message": "Security agents may only protect locally or record an approved override",
} if {
    not input.action in local_protection_actions
    input.action != "allowed_override"
}

violations contains {
    "code": "UNAPPROVED_OVERRIDE",
    "severity": "high",
    "message": "An override requires explicit human approval and a recorded reason",
} if {
    input.action == "allowed_override"
    not input.override.human_approved
}

violations contains {
    "code": "UNJUSTIFIED_OVERRIDE",
    "severity": "medium",
    "message": "An approved override requires a meaningful reason",
} if {
    input.action == "allowed_override"
    count(input.override.reason) < 10
}

evaluate := {
    "allow": count(violations) == 0,
    "violations": violations,
}
