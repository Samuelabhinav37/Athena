# Branch protection recommendations

Protect `main` in GitHub repository settings with the following minimum rules:

- require a pull request before merging;
- require at least one approving review;
- dismiss stale approvals when new commits are pushed;
- require conversation resolution;
- require the `security-gate` status check;
- require branches to be up to date before merging;
- block force pushes and branch deletion; and
- restrict bypass permission to a small maintainer group.

The workflow uses read-only repository permissions and does not require repository secrets. Pull requests from forks can therefore run the deterministic checks without receiving privileged credentials.

Branch protection is a GitHub repository setting and cannot be enforced by files in this repository alone. A maintainer must enable it after the first successful workflow run establishes the `security-gate` check name.
