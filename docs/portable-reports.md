# Portable evidence renderers

Athena renderer contract `1.0` separates evidence collection from presentation. A renderer accepts
one completed `EvidenceReportResponse`, revalidates its schema and authoritative evidence digest,
and returns an immutable artifact containing exact bytes, a content digest, the source evidence
digest, and a secret-free capability manifest.

Implemented formats are deterministic canonical JSON and Markdown. Rendering the same report
produces byte-identical output. The existing Markdown API delegates to the contract, while the
existing JSON API response remains backward compatible. Renderer manifests state media type, file
extension, deterministic behavior, and the invariant that only authoritative report facts are
inputs.

Tampered inventory, decisions, controls, sources, or limitations fail digest verification before
rendering. Generated AI explanations are never accepted as report inputs; the standard disclaimer
remains presentation text rather than evidence.

OSCAL, PDF, and Word appear in the format vocabulary but are not registered as implemented
renderers. OSCAL Assessment Results require portable assessment-plan and system context. PDF and
Word require reviewed generation dependencies plus render-and-visual-verification workflows. The
contract does not write files, select destinations, sign artifacts, or change retention policy.
