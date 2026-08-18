# Authorization evidence reports

Athena produces deterministic, point-in-time authorization evidence reports for administrators.
Reports summarize authoritative database records and version-controlled NIST mappings; generated
LLM prose is explicitly excluded from report facts.

## Endpoints

| Endpoint | Representation |
|---|---|
| `GET /v1/reports/evidence` | Structured JSON contract |
| `GET /v1/reports/evidence.md` | Downloadable Markdown report |

Both endpoints require `athena-administrator`. The React System Operations view exposes the
Markdown download only to a principal carrying that role.

## Contents

The report includes:

- identity and active-account counts;
- active entitlement and policy-evaluation counts;
- policy decisions grouped by deterministic result;
- risk assessment count and maximum recorded risk score;
- anomaly, review, execution, monitoring, connector, and audit-event counts;
- review, execution, and monitoring status distributions; and
- version-controlled NIST AC-2, AC-5, and AC-6 mapping status, check counts, and limitations.

Every report includes a SHA-256 digest calculated over canonical JSON containing the facts, control
mappings, authoritative source list, and limitations. Generation time and the digest itself are
excluded from that digest, so unchanged evidence produces the same value across JSON and Markdown
representations.

## Boundaries and limitations

- Report generation performs no database write and does not modify evidence.
- A report describes what is currently retained by Athena; it is not certification by itself.
- Connector completeness depends on configured read scopes and successful synchronization.
- NIST mappings remain partial where organizational or procedural evidence is required.
- LLM explanations are advisory presentation and never authoritative report evidence.
