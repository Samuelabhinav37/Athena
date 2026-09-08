# Activity evidence contract — access-decay-v2

Implemented for new risk assessments on 2026-09-08. Risk remains advisory;
this contract neither approves access nor triggers upstream changes.

## Meaning and score treatment

Activity freshness is distinct from the age of last use. An observation must
be at most 24 hours old to support the current activity-age calculation.
This is a versioned local assessment threshold, not a provider coverage guarantee.

| Status | Evidence at assessment time | Existing 15-point activity budget |
|---|---|---|
| recent | Valid observation within 24 hours; last use less than 90 whole days ago | 15 × whole days / 90, with factor rounded to four decimals |
| stale | Valid observation within 24 hours; last use at least 90 whole days ago | 15 points for observed age |
| unknown | No observation, no last-use timestamp, or observation older than 24 hours | 15-point uncertainty reserve |
| invalid | Observation in the future, or last use later than its observation | 15-point uncertainty reserve |

Invalid timestamp ordering takes precedence over missing/stale observation quality.
Naive stored timestamps follow the existing UTC convention. The latest observation
is selected by observation time, then ID to make ties deterministic. An invalid
latest observation is surfaced; the service does not silently choose an older one.

For example, last use 10 days ago observed today contributes about 1.67 points;
last use 120 days ago observed today contributes 15 observed-age points. The same
last-use timestamp observed two days ago contributes 15 uncertainty points.
Missing activity also contributes 15 uncertainty points, never a proven-stale reason.

The uncertainty reserve preserves the conservative treatment of missing activity
without claiming that unavailable telemetry proves inactivity or safety. A score
is a prioritization measure, not a probability or evidence-completeness score.
Other factors and overall maximum-finding aggregation retain their existing rules.

## Stored and displayed evidence

`factors.time_since_use` preserves numeric `value` and `weight`, adding `status`,
`reason`, `treatment` (`observed_age` or `uncertainty_reserve`), `observation_id`,
`observed_at`, and `last_used_at`. Absent references are null. These fields fit
the existing JSON/API contract and require no schema migration.

The explanation excludes uncertain activity from measured primary contributors
and explicitly describes the reserve. The dashboard displays that stored
explanation and assessment model version. `stale_access` requires status `stale`;
retained-access and policy findings keep their existing precedence.

Historical v1 assessments remain immutable and retain their original semantics.
No backfill or relabeling occurs. Consumers should interpret added metadata only
when present and distinguish versions when comparing assessments.

## Limits and follow-on work

These statuses describe recorded activity timestamps, not complete source coverage
or proof that access was unused throughout an interval. Provider-specific activity
semantics and collection completeness remain connector work. The existing coarse
finding taxonomy still falls back to `peer_deviation`; expanding it to represent
uncertainty and non-peer factors independently requires a separate enum/migration
design. Authentication, peer, and policy evidence quality are not changed here.
