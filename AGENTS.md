# AGENTS.md

Consent-based Android automation research harness (operator-owned devices / emulators / consenting testers only). Phase 1 is **Go server foundation only** — no Android driver, AccessibilityService, OCR, cloud APIs, or model inference.

## Hard rules (do not violate)

- Never log or persist raw telemetry, raw XML, screenshots, raw UI text, credentials, signatures, private keys, auth headers, or PII.
- Unsanitized telemetry may exist **only** in bounded in-memory request/test scope. Disk fixtures must be sanitized-only (`server/testdata/`).
- Never use cloud APIs for sanitization, NER, OCR, telemetry, screenshots, or inference.
- No stealth, persistence, anti-detection, credential capture, Android security bypasses, or third-party/unauthorized automation.
- Phase 1: do not automate banking, password managers, private messaging, email, medical, or other sensitive apps.
- Fail closed: sanitizer errors → drop, **never** write storage. Storage accepts only `trajectory.SanitizedFrame`.

## Layout

| Path | Role |
|------|------|
| `proto/golem/v1/telemetry.proto` | Versioned contract |
| `server/gen/golem/v1/` | Buf-generated Go stubs (committed; used by ingest gRPC) |
| `buf.yaml` / `buf.gen.yaml` / `Makefile` | `make proto` → `buf generate` |
| `server/` | Module `golem-harness/server` — proxy + packages |
| `server/cmd/golem-proxy` | Entrypoint: gRPC ingest + `/healthz` `/readyz` |
| `server/internal/{auth,config,ingest,sanitize,storage,trajectory,testutil}` | Core logic |
| `server/pkg/client` | Shared signed-client helpers (re-exports internal types) |
| `mock-client/` | Separate module; `replace` → `../server` |
| `docs/` | ARCHITECTURE, MVP, SECURITY |

Two Go modules. Change server APIs carefully — mock-client depends via replace.

## Commands

```bash
cd server && go test ./...
cd mock-client && go test ./...

# single package
cd server && go test ./internal/sanitize/

# regenerate protobuf Go stubs (requires buf CLI)
make proto
make lint-proto

# proxy (needs config with real device pubkey)
cd server && mkdir -p data && go run ./cmd/golem-proxy -config /path/to/dev-config.json

# mock client (prints Ed25519 pubkey; keys under .devkeys/)
cd mock-client && go run . -addr 127.0.0.1:7443
```

Config template: `server/testdata/dev-config.example.json`. Copy it; paste mock-client’s base64 public key into `allowed_devices`.

No root go.work or CI. Lint/typecheck beyond `go test`: `make lint-proto` only.

## Critical implementation quirks

- **Wire is protobuf gRPC.** Ingest registers `golemv1.TelemetryIngestService` via `ingest.Register` / `GRPCServer`. Request is `IngestFrameRequest{ envelope }`; envelope payload field is proto `canonical_payload` → domain `auth.SignedEnvelope.Payload`.
- **Inner frame payload is still JSON** of `trajectory.RawFrame` (not protobuf `TelemetryFrame`). Domain types of record for sanitize/storage remain `trajectory` + `auth.SignedEnvelope`.
- **Proto convert:** `envelopeFromProto` must reject `pb.SignedAt == nil` **before** `AsTime()` — nil timestamps become Unix epoch, not Go zero time, and would mis-route as expired/unauthenticated.
- **bufconn + `grpc.NewClient`:** use target `passthrough:///bufnet` (not bare `"bufnet"`). `NewClient` DNS-resolves bare targets; `DialContext` did not. See `ingest_test.go`.
- **Signing:** Ed25519 over `auth.CanonicalBytes` (`golem-harness-signature-v1\n` + metadata lines + raw payload). Use `auth.SignEnvelope` / `client.BuildSignedEnvelope`; do not invent a new canonical form.
- **Package policy:** default-deny allowlist; built-in sensitive packages in `sanitize.defaultSensitivePackages` (plus config). Sensitive → quarantine (not stored); non-allowlisted → drop.
- **Replay:** in-memory only (`MemoryReplayGuard`); resets on restart.
- **NER / vision:** local interfaces with no-op/conservative placeholders — keep local; do not call external services.
- **Logging:** hashed device/trajectory ids + decisions/reason codes only (`ingest.safeLog`).

## Do not commit

`.devkeys/`, `certs/`, `*.key`, `*.pem`, `data/`, local `*.jsonl` (except `server/testdata/*.jsonl`). Keys are test-only.

## Scope discipline

Stabilize server foundation before any Kotlin/Android driver work: durable replay next; storage direction (JSONL now; Parquet deferred). Document measurable gaps; do not imply unfinished capabilities are done.
