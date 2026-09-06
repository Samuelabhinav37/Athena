# Athena versus enterprise identity-governance platforms

Research date: 2026-09-06. Vendor claims below are drawn only from official product, documentation,
trust, and investor sources. Directional judgments are analysis, not independently benchmarked facts.

## Executive conclusion

Athena is not currently an enterprise IGA replacement. It is pre-release software with four narrow,
read-only collection paths, no mature request catalog or certification campaigns, no production
write-back, no published SLA, no independent security attestation, and no demonstrated support or
implementation ecosystem. SailPoint, Saviynt, Microsoft, and Okta sell operating platforms; Veza
and ConductorOne already productize much of the modern authorization-visibility and workflow story.

Athena's credible wedge is narrower: independently reproducible authorization provenance,
deterministic policy evaluation, digest-verified evidence, explicit partial-data boundaries, and
bounded attack-path analysis. It should be positioned as an open authorization-assurance layer,
not as a drop-in SailPoint or Saviynt competitor.

## Comparative assessment

| Platform | Documented strength | Brutally honest comparison with Athena |
|---|---|---|
| SailPoint ISC | Roles, lifecycle provisioning, requests, certifications, automatic/manual remediation, non-employees and machine identities; extensive certifications and major-enterprise adoption | The full enterprise benchmark. Athena is multiple product generations behind on operating workflows, integrations, assurance and commercial maturity. SailPoint is also suite/add-on-heavy and its exact per-connector semantics still require diligence. |
| Saviynt EIC | Broad converged IGA, PAM, application/data governance, NHI and AI-agent positioning; major app marketplace; FedRAMP and mature attestations | Far broader than Athena, but public messaging is sweeping and less technically precise. Exact GA status, connector write semantics, scale and SLA need contractual proof. |
| Microsoft Entra ID Governance | Mature access packages, approvals, reviews, JML workflows, SaaS/on-prem provisioning and a public 99.99% Entra SLA | Decisive choice for Microsoft-centered estates. Outside Microsoft, depth depends on gallery/SCIM/Logic Apps, and some custom-resource capabilities remain preview. Athena has more vendor-neutral provenance ambition, not comparable operational maturity. |
| Okta Identity Governance | Lifecycle Management, Workflows, requests, certifications, entitlements, SoD, automatic remediation, collaboration/ITSM channels and AI recommendations | Strong extension of an established IdP. Modular subscriptions, feature limitations and Early Access dependencies matter. Athena's AI/policy boundary is clearer, but buyers need workflows more than architectural elegance. |
| CyberArk Identity Security | Privileged access, secrets and machine identity; official assurance material also describes lifecycle and compliance/certification services | CyberArk is overwhelmingly stronger in real privileged operations. Its current unified IGA details were less openly documented in this review, so buyers should verify the integrated experience and SKU boundaries. |
| Veza | Access Graph, effective authorization search, NHI visibility, reviews, lifecycle, requests and write integrations | The closest conceptual threat to Athena. It already commercializes the graph story and adds workflows. Athena must prove that immutable source-linked provenance is materially more accurate or auditable than Veza's proprietary graph. |
| ConductorOne | Cloud-first requests, reviews, JIT, lifecycle automation, SoD, connectors, provisioning and ticketed manual fulfillment | Substantially more usable for daily governance. Coverage and write support vary by connector, and public SLA/certification detail is thinner than incumbents. Athena currently has stronger formal evidence architecture but much less product. |

## Primary-source evidence

### SailPoint

- Access types, roles, access requests, lifecycle-state provisioning and deprovisioning:
  <https://documentation.sailpoint.com/saas/help/access/index.html>
- Certification safeguards and automatic versus manual remediation:
  <https://documentation.sailpoint.com/saas/help/certs/understanding_certifications_la.html>
- Non-employee governance, including the base module's limits:
  <https://documentation.sailpoint.com/saas/help/common/non-employee-mgmt.html>
- Machine/agent and secrets-oriented products: <https://documentation.sailpoint.com/>
- ISO 27001, SOC 1/2 Type II, SOC 3, FedRAMP Moderate and other assurance:
  <https://trust.sailpoint.com/>
- Vendor-reported adoption (53% of Fortune 500):
  <https://www.sailpoint.com/en-au/products/identity-security-cloud>

### Saviynt

- Product domains and named enterprise ecosystems: <https://saviynt.com/>
- Integration marketplace: <https://exchange.saviynt.com/pages/apps>
- Trust claims including SOC 1/2 Type II, ISO and FedRAMP Moderate:
  <https://saviynt.com/trust-compliance-security>
- Detailed assurance artifacts (some gated): <https://trust.saviynt.com/>

Saviynt's official pages establish breadth but do not publicly settle exact connector object-level
read/write behavior, scale ceilings, governance-function SLA, or which newest AI-agent capabilities
are generally available. Treat “every identity/every app” as positioning, not proof.

### Microsoft Entra ID Governance

- Entitlement management: access packages, multi-stage approval, assignment, expiration, reviews,
  connected organizations and supported Microsoft resource classes:
  <https://learn.microsoft.com/en-us/entra/id-governance/entitlement-management-overview>
- Joiner/mover/leaver lifecycle workflows and published workflow limits:
  <https://learn.microsoft.com/en-us/entra/id-governance/what-are-lifecycle-workflows>
- Recurring access reviews and recommendations:
  <https://learn.microsoft.com/en-us/entra/id-governance/access-reviews-overview>
- Provisioning and governance licensing matrix:
  <https://learn.microsoft.com/en-us/entra/fundamentals/licensing>
- Published 99.99% Entra SLA and historical attainment:
  <https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-sla-performance>

### Okta Identity Governance

- OIG composition and capabilities: <https://help.okta.com/oie/en-us/content/topics/identity-governance/iga.htm>
- Multi-step requests, delegation, escalation and Slack/Teams/ITSM integration:
  <https://help.okta.com/oie/en-us/content/topics/identity-governance/access-requests/ar-overview.htm>
- Certifications, automatic remediation, compliance evidence and AI-agent subscription dependency:
  <https://help.okta.com/en-us/Content/Topics/identity-governance/access-certification/iga-access-cert.htm>
- Governable AI recommendation/summary settings:
  <https://help.okta.com/en-us/content/topics/identity-governance/settings.htm>
- Request limitations and Early Access dependencies:
  <https://help.okta.com/oie/en-us/Content/Topics/identity-governance/access-requests/ar-request-types.htm>

### CyberArk

- Official SOC 3 report describing Identity Lifecycle Management and Identity Compliance, including
  access discovery and certifications:
  <https://www.cyberark.com/CyberArk-Identity-2023-Type-2-SOC-3-Final-Report.pdf>

This source proves that the services existed in the audited scope; it does not prove that today's
post-acquisition product experience is seamless. Current connector semantics, SLA, HA and assurance
scope should be validated directly with CyberArk.

### Veza

- Access Graph and product portfolio: <https://veza.com/>
- Open Authorization API for unsupported systems:
  <https://developer.veza.com/oaa/guide/getting-started>
- Native, SCIM and OAA Write provisioning/deprovisioning:
  <https://veza.com/product/access-authz/>
- Access-review and revocation-confirmation claims:
  <https://cdn.veza.com/content/uploads/Access-Reviews_2023-10-18-224823_kqot.pdf>
- SOC 2 and ISO 27001: <https://veza.com/company/trust-and-security/>

### ConductorOne

- Connector model, graph ingestion, variable provisioning capabilities, ticketing, hosting and
  failover: <https://www.conductorone.com/docs/product/integrations/faq/>
- Salesforce UAR/JIT and deprovisioning example:
  <https://www.conductorone.com/docs/baton/salesforce-v2>
- SoD monitoring, audit logs and reports:
  <https://www.conductorone.com/docs/product/manage-access/access-conflicts/>
- Product claims for automated reviews, JIT, lifecycle and AI:
  <https://www.conductorone.com/product-tour/>

## Priority roadmap implied by the comparison

1. Publish per-object semantic and read/write conformance matrices for five deep connectors instead
   of chasing connector-logo count.
2. Build a real request catalog, multi-stage approvals, time-bound/JIT access, recurring campaigns,
   delegation/escalation and independently confirmed fulfillment.
3. Prove graph correctness on nested/inherited access, deny and conditional policy, and multi-hop
   attack paths against vendor-native expected results.
4. Complete production gates: HA, backup/PITR restore exercises, RTO/RPO, sustained load evidence,
   data residency, signed releases/SBOM, support model, SLO/SLA and an independent assurance roadmap.
5. Preserve Athena's strongest choices: deterministic policy, advisory-only AI, immutable evidence,
   explicit incompleteness and fail-closed tenant boundaries.

## Questions marketing pages cannot answer

For every shortlisted product, require a contractual per-connector object/read/write/delete/JIT
matrix, tested scale and freshness limits, governance-specific SLA, RPO/RTO, residency choices, AI
retention/training/subprocessor terms, exportability, API limits, SKU/add-ons, failed-remediation and
rollback behavior, implementation effort, and customer references using the same target systems.
