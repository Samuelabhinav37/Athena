# Athena identity governance

Athena distinguishes the person or workload behind access from each account that
holds that access. Correlation describes that relationship without replacing
source-specific evidence.

## Language

**Provider account**: An account identified within its provider's authority or
directory. One person can have multiple provider accounts.
_Avoid_: Person, universal identity

**Person**: A human whose relationship to provider accounts has independently
supported evidence. A shared email address does not establish the same person.
_Avoid_: Username, email identity

**Correlation candidate**: A possible person/account relationship requiring
independent confirmation. A candidate is not a confirmed link.
_Avoid_: Match, merged identity

**Confirmed link**: An explicitly approved relationship between a person and a
provider account, supported by recorded evidence for a defined period.
_Avoid_: Email match

**Workload ownership**: Responsibility for a non-human account or workload.
Ownership does not make the owner and workload the same identity.
_Avoid_: Person link
