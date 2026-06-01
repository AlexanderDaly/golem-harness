# Golem-Harness Architecture

Project Golem-Harness is an internal, consent-based Android automation research harness for operator-owned devices, controlled emulators, and explicitly consenting test users. Phase 1 implements only the Go-side server foundation.

## Data Flow

1. A test client builds a synthetic telemetry frame in memory.
2. The client serializes the frame payload and signs a canonical representation with Ed25519.
3. `golem-proxy` receives the signed envelope over gRPC. The current implementation uses a bounded JSON gRPC codec because protobuf generation tools are not installed locally.
4. The proxy verifies payload size, timestamp freshness, replay status, device authorization, payload hash, and detached signature.
5. The raw payload is decoded only in request scope and immediately passed through the sanitizer.
6. Accepted sanitized frames are written to the storage sink. Dropped or quarantined frames are not persisted.

## Trust Boundaries

- Transport boundary: gRPC can run with mTLS. When enabled, TLS 1.3 and client certificate verification are configured from local files.
- Signature boundary: Ed25519 verifies that the payload came from an allowed device key.
- Sanitizer boundary: raw telemetry may exist only before the sanitizer returns. Storage accepts only `trajectory.SanitizedFrame`.
- Storage boundary: Phase 1 writes sanitized JSONL. Parquet is intentionally deferred.

## Telemetry Lifecycle

- Pre-sanitization: raw UI text and content descriptions may exist only in bounded request memory.
- Sanitization: allowlist/kill-switch checks run first, then structural attrition, regex redaction, local NER placeholder, and vision-redaction placeholder.
- Post-sanitization: raw text fields are absent. Text is represented as a hash for non-sensitive synthetic values or redaction status for sensitive matches.

## Protobuf Contract

The schema lives at `proto/golem/v1/telemetry.proto`. It includes the intended versioned contract for generated clients and servers.

Generation command once tools are installed:

```bash
cd golem-harness
protoc -I proto \
  --go_out=server/gen --go_opt=module=golem-harness/server/gen \
  --go-grpc_out=server/gen --go-grpc_opt=module=golem-harness/server/gen \
  proto/golem/v1/telemetry.proto
```

Current local tool gap:

- `protoc` is not installed.
- `protoc-gen-go` is not installed.
- `protoc-gen-go-grpc` is not installed.
- `buf` is not installed.

## Phase 1 Limitations

- No Android driver or AccessibilityService is implemented.
- No OCR, screenshots bytes, cloud NER, cloud OCR, telemetry processing API, or model inference is implemented.
- JSONL is the safe test sink. Parquet is the next storage milestone.
- mTLS code is present, but local certificate generation is documented rather than bundled.
