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

## JSON receiver

`POST /v1/telemetry/events/json` provides the first bounded normalization adapter. It requires the
existing Athena administrator role, accepts only `application/json`, stream-reads at most 1 MiB,
and applies the envelope's independent normalized-content validation. Transport provenance is
derived by Athena; callers cannot supply a locator or source format. Invalid input returns a generic
error that never echoes source content.

The receiver permits 60 requests per authenticated subject per 60-second window and returns `429`
with `Retry-After` when exceeded. The limiter is bounded to 10,000 subjects and is intentionally
process-local; production multi-worker or distributed deployments require an external shared rate
limit before exposing this endpoint. Successful responses use `Cache-Control: no-store` and return
the normalized envelope with the original-byte digest. A `200` response means validation and
normalization succeeded—it does not mean the event was queued, persisted, or exported.

## Planned adapters

Future receivers may accept OTLP, syslog, JSON, or authenticated webhooks. Future exporters may emit
OTLP or bounded vendor-neutral JSON. Every adapter must preserve the original digest and provenance,
declare its supported capabilities, reject malformed or oversized input, and prove through
conformance tests that vendor-specific fields cannot replace Athena's canonical semantics.
