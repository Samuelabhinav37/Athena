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

## OTLP/HTTP JSON normalization

`POST /v1/telemetry/events/otlp-json` accepts the JSON protobuf representation of an OTLP
`ExportLogsServiceRequest`. It follows the stable OTLP log hierarchy
`resourceLogs → scopeLogs → logRecords`, accepts decimal strings or integers for 64-bit
nanosecond fields, requires integer severity enums, and normalizes hexadecimal trace and span IDs.
Unknown protobuf fields are ignored as OTLP requires, but Athena returns bounded warnings so mapping
loss remains visible.

The adapter supports scalar resource and record attributes plus structured `AnyValue` log bodies.
Non-scalar attributes are dropped with warnings, duplicate attribute keys reject the record, and
missing event names or timestamps receive explicit documented fallback values. Each event carries a
digest of its canonical serialized resource/scope/record tuple; the response separately carries the
SHA-256 digest and exact byte count of the complete request. Up to 100 records and 1 MiB are accepted
per request. Records that violate Athena's envelope are rejected individually without echoing their
content.

This is deliberately not mounted at the standard OTLP `/v1/logs` path and does not return an
`ExportLogsServiceResponse`: Athena has no durable telemetry acceptance boundary yet. It is an
authenticated normalization and compatibility endpoint, not a production OpenTelemetry Collector.
Binary protobuf, gzip, gRPC, persistence, retries, and export are not supported in this slice.

## RFC 5424 syslog normalization

`POST /v1/telemetry/events/syslog` accepts one UTF-8 RFC 5424 message using
`application/syslog` or `text/plain`. It supports either an unframed message body or one exact RFC
6587 octet-counted frame. Delimiter framing, multiple frames, RFC 3164 guessing, invalid priorities,
non-version-1 headers, timestamps beyond RFC 5424's six fractional digits, and malformed structured
data fail closed.

The adapter maps facility, severity, timestamp, hostname, application, process, message ID,
structured-data elements, and message text into the canonical envelope. RFC severity is mapped to
the corresponding OpenTelemetry severity band. The response preserves the digest and byte count of
the complete request and, for octet-counted input, separately preserves the enclosed RFC 5424
message digest. NIL timestamps use receipt time with an explicit warning.

This HTTP endpoint requires an Athena administrator token and shares the bounded process-local
limiter. It is a parser and normalization boundary—not a UDP/TCP syslog listener. Athena does not
bind port 514, terminate syslog TLS, authenticate devices, persist messages, or acknowledge durable
delivery. A future network listener must use a reviewed TLS transport and bind authenticated peer
identity to provenance rather than trusting the message's HOSTNAME.

## Signed generic webhook normalization

`POST /v1/telemetry/webhooks/athena-generic` is disabled by default. When enabled, it authenticates
the exact JSON request body with `HMAC-SHA256(secret, timestamp + "." + delivery_id + "." + body)`
using `X-Athena-Webhook-Timestamp`, `X-Athena-Webhook-ID`, and
`X-Athena-Webhook-Signature: sha256=<lowercase-hex>`. Timestamps must be canonical Unix seconds
within the configured five-minute window, delivery IDs are bounded safe identifiers, and signature
comparison is constant-time.

The only supported mapping is `athena.generic.v1`. Its response declares capabilities for structured
body, scalar attributes, resource identity, trace context, and original-request digest. Unknown
mappings and fields fail closed. Exact body bytes become webhook provenance; secrets and signatures
are never returned. A verified delivery ID is consumed even when its signed payload fails schema
validation, preventing repeated processing attempts with the same authenticated delivery.

Replay tracking is bounded to 10,000 IDs but is process-local. Multi-worker or multi-instance
deployments must use a shared atomic replay store and gateway rate limit before enabling this route.
The HMAC secret must contain at least 32 characters and must be provisioned separately to each
authorized sender. This slice does not provide secret rotation overlap, provider-specific mappings,
mutual TLS, persistence, queues, or durable delivery acknowledgement.

## Planned adapters

Future receivers may accept authenticated webhooks. Future exporters may emit
OTLP or bounded vendor-neutral JSON. Every adapter must preserve the original digest and provenance,
declare its supported capabilities, reject malformed or oversized input, and prove through
conformance tests that vendor-specific fields cannot replace Athena's canonical semantics.
