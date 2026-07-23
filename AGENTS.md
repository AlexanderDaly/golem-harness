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
| `server/pkg/{signing,trajectory,client}` | Public packages (signing + frame types + mock client helpers) |
| `server/internal/{auth,config,ingest,sanitize,storage,testutil}` | Core server logic |
| `mock-client/` | Separate module; `replace` → `../server` |
| `docs/` | ARCHITECTURE, MVP, SECURITY |

Two Go modules. External code should import `pkg/*` only — not `internal/*`.

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

Config template: `server/testdata/dev-config.example.json`. Copy it; paste mock-client’s base64 public key into `allowed_devices`. Use matching `public_key_id` with `client.BuildSignedEnvelopeWithKey`.

No root go.work or CI. Lint/typecheck beyond `go test`: `make lint-proto` only.

## Critical implementation quirks

- **Wire is protobuf gRPC.** Ingest registers `golemv1.TelemetryIngestService` via `ingest.Register` / `GRPCServer`. Request is `IngestFrameRequest{ envelope }`; envelope payload field is proto `canonical_payload` → domain `signing.SignedEnvelope.Payload`.
- **Inner frame payload is still JSON** of `trajectory.RawFrame` (not protobuf `TelemetryFrame`).
- **Proto convert:** `signing.EnvelopeFromProto` must reject `pb.SignedAt == nil` **before** `AsTime()` — nil timestamps become Unix epoch, not Go zero time.
- **bufconn + `grpc.NewClient`:** use target `passthrough:///bufnet` (not bare `"bufnet"`). See `ingest_test.go`.
- **Signing:** Ed25519 over `signing.CanonicalBytes` only (`golem-harness-signature-v2` + fixed field lines). Do not duplicate the prefix. See `docs/SECURITY.md`.
- **Cert binding:** if registry and/or envelope set a client cert fingerprint, peer cert is required and must match. Config enables `mtls.require_client` when any device has a fingerprint.
- **Package policy:** default-deny allowlist; built-in sensitive packages in `sanitize.defaultSensitivePackages` (plus config). Sensitive → quarantine; non-allowlisted → drop.
- **Replay:** proxy uses `SQLiteReplayGuard`. Tests may use `MemoryReplayGuard` (bounded; fails closed at cap). Rules: unique `(device_id, frame_id)` + strictly increasing sequence per device. SQLite `seen_frames` is **intentionally unbounded** (catches frame_id reuse at a new sequence; sequence check alone is not enough for that case). Do not prune without a design.
- **NER / vision:** local no-op placeholders — keep local; no external services.
- **Logging:** hashed device/trajectory ids + decisions/reason codes only (`ingest.safeLog`).

## Do not commit

`.devkeys/`, `certs/`, `*.key`, `*.pem`, `data/`, local `*.jsonl` (except `server/testdata/*.jsonl`). Keys are test-only.

## Scope discipline

Stabilize server foundation before any Kotlin/Android driver work: storage direction (JSONL now; Parquet deferred). Document measurable gaps; do not imply unfinished capabilities are done.
