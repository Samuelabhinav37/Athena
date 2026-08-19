# Policy interoperability contract

Athena policy request contract `2.0` separates the platform's authorization facts from any policy
engine's native input shape. Every request has four explicit parts:

- `principal`: stable identity, type, username, department, roles, and groups;
- `action`: stable permission identity, verb, display name, and privileged classification;
- `resource`: stable resource identity, source identifier, type, name, and sensitivity; and
- `context`: governance evidence, authentication posture, and ordered provenance edges.

Models are frozen, reject unknown fields, and carry a versioned schema URL. Policy evaluations store
this canonical request as their immutable input snapshot. The contract contains facts only: it does
not include an allow/deny recommendation, model output, remediation instruction, or credentials.

## OPA adapter

OPA/Rego remains Athena's sole authoritative policy engine. `OpaAuthorizationAdapter` translates the
canonical request into the existing Rego input schema `1.0`; the policies, policy path, decision
shape, violation ordering, and fail-closed behavior are unchanged. Security-gate fixtures continue
to exercise that native OPA shape directly so translation and policy semantics are tested as
separate boundaries.

Additional engines must receive their own explicit adapters and conformance suites. Passing the
same principal-action-resource-context facts to another engine does not imply that its policy
language, combining algorithms, missing-data behavior, or decisions are semantically equivalent to
OPA. No alternate adapter may silently translate Rego policies or override an OPA decision.
