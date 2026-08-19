# Portable compliance framework contracts

Athena framework contract `1.0` loads the existing NIST SP 800-53 Revision 5 mappings into a
validated, deterministic `FrameworkPack`. It preserves each control objective, implementation
status, typed automated-evidence reference, and limitation. A content digest changes whenever any
of those authoritative mapping facts changes.

## OSCAL compatibility

`build_oscal_component_definition` renders the pack as the core JSON structure of an OSCAL
Component Definition: metadata, one Athena software component, a control implementation linked to
the NIST catalog, and implemented requirements for AC-2, AC-5, and AC-6. Stable UUIDv5 identifiers
are derived from the framework digest, and callers must supply a timezone-aware `last-modified`
value so repeated rendering of the same evidence context remains deterministic.

Automated test and policy-fixture evidence use repository-relative links. Database fields and Rego
rules use Athena URNs. Each requirement carries the source mapping's status and limitations as
Athena-namespaced OSCAL properties. Partial mappings therefore remain visibly partial and cannot be
mistaken for full implementation or certification. Generated AI explanations are not inputs to the
framework pack or component definition.

This initial slice is intentionally a Component Definition, not an OSCAL Assessment Results
document. Assessment Results require an Assessment Plan, assessed-system context, subjects,
activities, observations, findings, and risks that Athena does not yet model as a portable package.
The renderer does not download the referenced catalog, validate against an external OSCAL schema,
write a file, sign a document, or modify stored evidence.
