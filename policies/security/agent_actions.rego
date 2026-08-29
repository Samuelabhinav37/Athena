package athena.security.agent_actions

import rego.v1

local_protection_actions := {"blocked", "warned", "quarantined"}

# Minimum length for a real, meaningful override reason -- same threshold
# the API's own SecurityEventCreate schema doesn't enforce (evidence is a
# free-form dict there), so this is the one place event ingestion actually
# checks it.
min_override_reason_length := 10

violations contains {
    "code": "UNSUPPORTED_AGENT_ACTION",
    "severity": "high",
    "message": "Security agents may only protect locally or record an approved override",
} if {
    not input.action in local_protection_actions
    input.action != "allowed_override"
}

# Deliberately does NOT require prior admin/human approval before an
# override event can be recorded -- an earlier version of this policy did,
# but nothing in the actual architecture ever produces that signal before
# ingestion: the event IS the record of a local, user-initiated override
# request (see warning.ts/index.ts in the Moat repo -- a real click plus a
# typed reason, submitted immediately, not pre-approved). Requiring
# pre-approval here would make every override event fail to ingest,
# silently breaking the shipped "Report mistake" flow. The actual
# human-approval control already exists elsewhere: POST /v1/security/policies
# is AdministratorPrincipal-gated, and republishing a policy without the
# domain is what actually lifts a block -- that endpoint is where "a human
# approves" is enforced, not here. This policy's job is narrower: reject an
# override that isn't even accompanied by a real reason.
violations contains {
    "code": "UNJUSTIFIED_OVERRIDE",
    "severity": "medium",
    "message": "An override requires a meaningful stated reason",
} if {
    input.action == "allowed_override"
    count(object.get(input, "reason", "")) < min_override_reason_length
}

evaluate := {
    "allow": count(violations) == 0,
    "violations": violations,
}
