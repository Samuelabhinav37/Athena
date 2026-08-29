package athena.security.agent_actions_test

import data.athena.security.agent_actions.evaluate
import rego.v1

test_local_block_is_allowed if {
    result := evaluate with input as {"action": "blocked"}
    result.allow
}

test_local_warn_and_quarantine_are_allowed if {
    warned := evaluate with input as {"action": "warned"}
    warned.allow
    quarantined := evaluate with input as {"action": "quarantined"}
    quarantined.allow
}

test_override_with_no_reason_is_denied if {
    result := evaluate with input as {"action": "allowed_override"}
    not result.allow
    some violation in result.violations
    violation.code == "UNJUSTIFIED_OVERRIDE"
}

test_override_with_a_short_reason_is_denied if {
    result := evaluate with input as {"action": "allowed_override", "reason": "typo"}
    not result.allow
    some violation in result.violations
    violation.code == "UNJUSTIFIED_OVERRIDE"
}

test_override_with_a_meaningful_reason_is_allowed if {
    # Deliberately carries no "human_approved" field at all -- see this
    # policy's own comment for why ingestion doesn't gate on prior
    # approval. The reason alone, at the length threshold, is sufficient.
    result := evaluate with input as {"action": "allowed_override", "reason": "This vendor domain is a known false positive"}
    result.allow
}

test_destructive_mail_action_is_denied if {
    result := evaluate with input as {"action": "deleted", "reason": "Approved business exception"}
    not result.allow
    some violation in result.violations
    violation.code == "UNSUPPORTED_AGENT_ACTION"
}
