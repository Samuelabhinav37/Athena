import type { Connector, ConnectorManifest, Identity } from "./types";
import { freshness } from "./assessment";

export function ConnectorCoverage({ manifests, checkpoints, identities, source }: {
  manifests: ConnectorManifest[]; checkpoints: Connector[]; identities: Identity[]; source?: string;
}) {
  const sources = source ? [source] : [...new Set([
    "github", "azure", "keycloak", ...manifests.map((item) => item.connector_id),
    ...checkpoints.map((item) => item.connector), ...identities.map((item) => item.source)
  ])];
  return <section className="coverage-section" aria-label="Source coverage and freshness">
    <p className="coverage-note">Recent evidence is not proof of complete access coverage. “Recent” means observed within 24 hours. Missing checkpoints do not establish whether a source is configured.</p>
    {sources.map((id) => {
      const manifest = manifests.find((item) => item.connector_id === id);
      const observations = checkpoints.filter((item) => item.connector === id);
      const observedIdentities = identities.filter((item) => item.source === id);
      return <article className="coverage-card" key={id}>
        <header><h3>{manifest?.display_name ?? id}</h3><span>{observations.length} recorded scopes · {observedIdentities.length} identities in loaded inventory</span></header>
        {observations.length ? <ul className="scope-observations">{observations.map((item) => <li key={item.id}>
          <strong>{item.scope}</strong><span className={`badge badge--${freshness(item.observed_at)}`}>{freshness(item.observed_at)}</span>
          <time>{Number.isFinite(Date.parse(item.observed_at)) ? new Date(item.observed_at).toLocaleString() : "Observation time unknown"}</time>
        </li>)}</ul> : <p>No checkpoint recorded in this page. {observedIdentities.length ? "Identity observations are available; collection completeness is unknown." : "No source evidence is present in the loaded inventory."}</p>}
        {manifest ? <details><summary>Coverage and limitations · contract {manifest.contract_version}</summary>
          <dl className="capability-list">{Object.entries(manifest.capabilities).map(([name, capability]) => <div key={name}>
            <dt>{name.replaceAll("_", " ")} <span className={`badge badge--${capability.support}`}>{capability.support}</span></dt><dd>{capability.detail}</dd>
          </div>)}</dl>
        </details> : <p className="coverage-warning">Capability declaration unavailable. Do not infer support for inheritance, deny rules, or activity.</p>}
      </article>;
    })}
  </section>;
}
