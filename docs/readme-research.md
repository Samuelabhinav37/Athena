# README structure research

## Scope

This note distills primary guidance from GitHub and structural patterns in first-party open-source security, identity, and platform projects. It is intended to guide a professional rewrite of Athena's root `README.md`; it is not a general documentation style guide.

## Primary-source findings

GitHub describes a repository README as the project's first orientation layer. It should explain what the project does, why it is useful, how to get started, where to get help, and who maintains or contributes to it. GitHub also recommends moving longer material out of the README and using relative links so documentation continues to work across branches and forks. [GitHub: About the repository README file](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes)

GitHub treats `CONTRIBUTING.md`, the license, code of conduct, and security policy as distinct community-health artifacts. The README should link to those contracts rather than duplicate them. GitHub surfaces a recognized `CONTRIBUTING.md` automatically, including beside the README in the repository UI. [GitHub: Setting guidelines for repository contributors](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/setting-guidelines-for-repository-contributors)

Established first-party projects lead with a concise product definition and quickly separate user journeys from maintainer journeys:

- Keycloak opens with one outcome-focused description, then routes readers to documentation, security reporting, issue reporting, a minimal development-mode launch, source builds, tests, contribution guidance, governance, and licensing. [Keycloak README](https://github.com/keycloak/keycloak/blob/main/README.md)
- Open Policy Agent opens with a precise category statement, prioritizes task-based entry points (learn, run, integrate, get support, contribute), explains its decision model, and places security reporting in an explicit section. [OPA README](https://github.com/open-policy-agent/opa/blob/main/README.md)
- OpenFGA, a close authorization-domain analogue, provides a copyable quick start with a verification step and places an explicit production-safety warning beside its local defaults. It also separates limitations and production guidance from the introductory value proposition. [OpenFGA README](https://github.com/openfga/openfga/blob/main/README.md)
- Backstage uses a short value proposition, a bounded feature summary, and prominent routes to getting started, architecture, roadmap, community, governance, security, and licensing instead of embedding all subordinate documentation. [Backstage README](https://github.com/backstage/backstage/blob/master/README.md)
- Vault puts the responsible-disclosure route near the top, defines the product in operational terms, enumerates a small number of core capabilities, and separates user documentation from source-development instructions. [Vault README](https://github.com/hashicorp/vault/blob/main/README.md)

These projects do not share a rigid template. Their common pattern is progressive disclosure: establish identity and trust first, prove value with a short path to success, disclose important boundaries, and direct specialized readers to maintained documents.

## Recommended Athena information architecture

1. **Product header** — name, one-sentence category and outcome, a restrained set of meaningful badges, and links to documentation, security, and contributing.
2. **What Athena is** — two short paragraphs defining the problem, intended operators, and differentiator: evidence-backed authorization provenance and governance.
3. **Status and safety boundary** — plainly distinguish implemented capabilities from production readiness; state that connectors are read-only and destructive actions require human approval or an explicitly configured executor.
4. **Core capabilities** — six to eight outcome-oriented bullets or a compact table. Group related features instead of presenting an exhaustive implementation inventory.
5. **How it works** — one architecture diagram plus a short explanation of the collection, normalization, policy, review, and evidence flow.
6. **Quick start** — prerequisites, exact commands, expected success signal, and the local-only/security caveat. Keep the primary path short; link advanced setup to deployment and authentication documentation.
7. **Representative workflow** — one compact identity-drift example showing input, decision, review, and preserved evidence. Avoid a second conceptual introduction.
8. **Documentation map** — task-oriented links for architecture, connectors, authentication, tenant isolation, operations, deployment, evidence, and readiness.
9. **Development and verification** — the smallest reproducible build/test commands, supported runtime versions, and links to deeper contributor guidance.
10. **Security, support, and contribution** — link to `SECURITY.md`, issue/support channels, `CONTRIBUTING.md`, code of conduct, governance/maintainers if present, and the license.

## Athena-specific editorial actions

- Lead with Athena's outcome and audience; move the rhetorical “five questions” below the concrete product definition or compress it into a single sentence.
- Replace the long “What Athena Does Today” inventory with grouped capabilities. Detailed implementation status belongs in the readiness and feature documents.
- Keep one architecture diagram. Explain its trust boundaries in prose and link the full architecture document.
- Put the current readiness statement above installation so evaluators cannot mistake a locally validated system for a production deployment.
- Make the first-run instructions testable: declare prerequisites, use copyable commands, state which URLs or health responses confirm success, and identify which credentials are development-only.
- Use consistent terms from the domain model: identity, entitlement, authorization provenance, policy decision, review, remediation request, and evidence.
- Separate facts from aspirations. Label planned write adapters and report formats as roadmap items rather than mixing them with delivered functionality.
- Prefer relative repository links and descriptive link text. Remove navigation links to headings or files that do not exist.
- Limit badges to signals readers can act on: CI/security gate, supported runtime, release/version if available, and license. Each badge should target its evidence page.
- End with clear routes for vulnerability reports, ordinary support/issues, contributions, and licensing; never direct vulnerability reports to a public issue.

## Quality bar for the rewrite

The rewritten README should let a new evaluator answer, without opening another file: what Athena is, who it serves, what is operational today, what its safety boundary is, whether it is production-ready, and how to run one verified local workflow. It should then make every deeper task reachable through a clearly named relative link.
