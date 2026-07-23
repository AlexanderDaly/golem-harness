# MVP

## Implemented

- Versioned protobuf telemetry contract with Buf-generated Go stubs under `server/gen/golem/v1/`.
- Go server module with auth, config, ingest, sanitizer, storage, trajectory, test utility, and client helper packages.
- gRPC ingestion over protobuf (`IngestFrameRequest` / generated service); signed payload body remains JSON `RawFrame`.
- `/healthz` and `/readyz` HTTP endpoints.
- mTLS-capable server configuration.
- Ed25519 detached signature verification.
- Device id to public key authorization.
- Expiry, durable SQLite replay, payload hash, and payload size checks.
- Fail-closed sanitizer with package allowlist, sensitive-package kill switch, structural attrition, regex redaction, local NER interface, and vision redaction interface.
- Sanitized-only JSONL storage sink.
- Mock signed client with synthetic accepted and sensitive-package frames.
- Tests for auth, sanitizer, storage, config, and gRPC ingest flow.

## Run Tests

```bash
cd server
go test ./...
```

## Run Proxy Locally

1. Start the mock client once to generate a test public key:

```bash
cd mock-client
go run . -addr 127.0.0.1:7443
```

This first run will fail if the proxy is not running, but it prints a test device public key. Place that key into a copy of `server/testdata/dev-config.example.json`.

2. Run the proxy:

```bash
cd server
mkdir -p data
go run ./cmd/golem-proxy -config /path/to/dev-config.json
```

3. Run the mock client again:

```bash
cd mock-client
go run . -addr 127.0.0.1:7443
```

Expected result: the allowed `com.android.settings` frame is accepted and stored as sanitized JSONL; the synthetic sensitive package frame is quarantined and not stored.

## Local Development Certificates

For mTLS testing, generate a local CA, server cert, and client cert with OpenSSL or `mkcert`, then set:

- `mtls.enabled: true`
- `mtls.cert_file`
- `mtls.key_file`
- `mtls.client_ca_file`
- `mtls.require_client: true`

Do not commit generated certificates or keys.

## Storage decision: Parquet

**Decision (recorded):** Parquet is **not** an online ingest path. Phase 1 live storage remains sanitized JSONL (rotation + fsync). Parquet is an **offline compaction** concern only.

**Trigger to implement:** build a batch/compaction job (or equivalent) when **either**:

1. cumulative accepted sanitized JSONL volume or query/scan cost makes day-partitioned columnar storage worth the pipeline, **or**
2. a consumer explicitly requires Parquet (training export, warehouse load, etc.)

Until then, do not block Android/Kotlin driver work on Parquet. Day-stamped JSONL archives (`frames-YYYYMMDD.jsonl`) are the intended compaction input layout.

## Before Kotlin Driver Work

Go server foundation is stable enough to begin an Android AccessibilityService scaffold when ready. Parquet is not a gate (see above).
