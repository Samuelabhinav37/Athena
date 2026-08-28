package athena.security.agent_actions_test

import data.athena.security.agent_actions.evaluate
import rego.v1

test_local_block_is_allowed if {
    result := evaluate with input as {
        "action": "blocked",
        "override": {"human_approved": false, "reason": ""},
    }
    result.allow
}

test_unapproved_override_is_denied if {
    result := evaluate with input as {
        "action": "allowed_override",
        "override": {"human_approved": false, "reason": "user clicked through"},
    }
    not result.allow
    some violation in result.violations
    violation.code == "UNAPPROVED_OVERRIDE"
}

test_approved_justified_override_is_allowed if {
    result := evaluate with input as {
        "action": "allowed_override",
        "override": {"human_approved": true, "reason": "Approved business exception"},
    }
    result.allow
}

test_destructive_mail_action_is_denied if {
    result := evaluate with input as {
        "action": "deleted",
        "override": {"human_approved": true, "reason": "Approved business exception"},
    }
    not result.allow
    some violation in result.violations
    violation.code == "UNSUPPORTED_AGENT_ACTION"
}
