# Vendor-neutral security-event telemetry

Athena defines a versioned transport-neutral security-event envelope before implementing any
receiver or exporter. The contract aligns with OpenTelemetry log-record concepts without requiring
the OpenTelemetry SDK as a runtime dependency.

## Contract

`SecurityEventEnvelope` version `1.0` contains:

- event and observed timestamps as Unix nanoseconds;
- OpenTelemetry severity number and text;
- normalized body and attributes;
- service resource attributes and instrumentation scope;
- optional paired W3C-compatible hexadecimal trace and span identifiers; and
- immutable original-event provenance.

Original provenance records the source type, source name, source locator, optional source event ID,
source format, receive time, exact byte count, and SHA-256 digest of the original bytes. Athena does
not treat normalized fields as a substitute for the original event. Two byte-distinct source events
retain different provenance even if they normalize to the same body.

## Safety and compatibility rules

- Original events are limited to 1 MiB; normalized body plus attributes are limited to 64 KiB.
- Event and resource attributes are bounded to 64 entries each.
- Normalized structures reject keys associated with authorization headers, cookies, credentials,
  passwords, secrets, and tokens. Raw source bytes are digested, not copied into labels or logs.
- Source locators reject embedded credentials, query strings, and fragments.
- Event names use lowercase dotted semantic names. Severity numbers use the OpenTelemetry 1–24
  range. Trace IDs and span IDs must be supplied together in lowercase hexadecimal form.
- Timestamps must be timezone-aware and are normalized to UTC with integer nanosecond conversion.
- Models are frozen and reject unknown fields. Receivers may map vendor fields only into explicit
  normalized body, attributes, resource fields, or original provenance.

The envelope is not authoritative policy or authorization evidence by itself. Ingestion, durable
storage, retention, export, and any mapping into Athena's append-only evidence store require
separate reviewed adapters and threat models.

## Planned adapters

Future receivers may accept OTLP, syslog, JSON, or authenticated webhooks. Future exporters may emit
OTLP or bounded vendor-neutral JSON. Every adapter must preserve the original digest and provenance,
declare its supported capabilities, reject malformed or oversized input, and prove through
conformance tests that vendor-specific fields cannot replace Athena's canonical semantics.
