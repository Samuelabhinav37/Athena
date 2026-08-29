# Athena browser and mailbox security agents

Athena models browser and mailbox protection as a bounded domain separate from IAM connectors and
generic telemetry. Moat and Clutter are local-first agents: they protect the user before reporting
privacy-minimized evidence, and Athena availability never participates in a block or quarantine.

## Trust and authentication

An Athena administrator enrolls an agent through `POST /v1/security/agents`. The enrollment secret
is returned once; Athena stores only a salted scrypt verifier. The agent exchanges that secret at
`POST /v1/security/agent-token` for a short-lived, audience-restricted token containing only
`events:write` and `policies:read`. These credentials are separate from human OIDC and bind the
agent to exactly one tenant and agent type.

Enable the flow only after setting a random token secret of at least 32 characters and an Ed25519
policy verification public key. Enrollment secrets and tokens must not be written to extension
logs or persistent browser sync storage.

## Event contract

`POST /v1/security/events` accepts an idempotent `source_event_id`, action, severity, rule and policy
references, pseudonymous subject, minimized domain or digest, and at most 16 KiB of bounded
evidence. Full URLs, email addresses, message bodies, subjects, passwords, authorization values,
and tokens are rejected. Events are tenant-scoped and append-only in both SQLAlchemy and PostgreSQL.

The local-first sequence is non-negotiable:

```text
local deterministic rule acts -> event enters bounded local queue -> Athena receives evidence
```

## Signed policy distribution

Administrators publish immutable policy versions through `POST /v1/security/policies`. Athena
checks the canonical SHA-256 digest and verifies the supplied Ed25519 signature before accepting a
version. An authenticated agent retrieves only the latest policy for its own type through
`GET /v1/security/policies/latest`. Agents must independently verify the signature before applying
the artifact and retain a last-known-good policy for rollback.

The policy payload is intentionally opaque to Athena's transport layer. Organizational configuration
such as tenant enrollment and reporting activation changes slowly through managed browser policy;
fast threat rules use this signed pull channel.

## Human and policy boundary

The `athena.security.agent_actions` OPA package, evaluated by `POST /v1/security/events` before an
`allowed_override` event is accepted, allows local block, warning, and quarantine actions, rejects
destructive ones outright, and requires a real, meaningful stated reason for an override -- there is
no shorter path. It deliberately does not require the override to already be pre-approved before
it can be *recorded*: the event is itself the record of a human (the browser/mailbox user) clicking
through a local warning and typing that reason, not something an agent can synthesize or approve on
its own. The actual organizational approval boundary is `POST /v1/security/policies`, gated to
administrators only -- republishing a signed policy without the domain is the one thing that
actually lifts a block, and machine learning or an LLM can no more do that than they can enact a
block, deletion, or access change directly.

## Analyst view

The dashboard's **Email & web security** page shows enrolled agents, local blocks, critical events,
overrides, rule identifiers, minimized indicators, and event time. It does not expose enrollment
credentials, raw browsing history, or email content.

## Publishing the optional add-ons

The web and desktop dashboard read `VITE_MOAT_STORE_URL` and `VITE_CLUTTER_STORE_URL`. Leave either
value empty before its extension is published; Athena displays **Store listing coming soon**. After
publication, set the matching Chrome Web Store URL and rebuild Athena. The card becomes an external
install button automatically, with no code change or hard-coded extension identifier.

Installing an extension and connecting it are separate trust steps. A personal installation gains
the extension's local protection but cannot silently receive Athena credentials. An organization
enrolls the extension as a security agent, places the returned agent id and enrollment secret in
Chrome managed policy, and grants the extension access to its Athena HTTPS origin. Athena displays
**Enrolled** only after the tenant contains a matching agent; a clicked install button is never
treated as connection or heartbeat evidence.
