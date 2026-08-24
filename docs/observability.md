# Operational observability

Athena emits structured JSON request logs with a bounded request ID and exposes Prometheus text
metrics at `/metrics`. Metric labels are deliberately limited to HTTP method and status class; tenant,
subject, connector scope, request ID, and external metadata are excluded to prevent sensitive data
leakage and unbounded cardinality.

Production alerting should page on readiness failures lasting five minutes, monitoring lease expiry,
three consecutive monitoring failures, any security-gate failure, sustained 5xx responses above one
percent, or connector evidence older than twice its scheduled interval. Warning alerts cover rate
limit saturation, recovery-point lag above ten minutes, and a restore-test deadline within seven
days. Alert delivery and escalation adapters are deployment responsibilities and must not mutate
Athena evidence or connector access.
