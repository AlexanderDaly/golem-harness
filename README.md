# Golem-Harness

Consent-based Android automation **research harness** for operator-owned devices, controlled emulators, and explicitly consenting test users only.

**Phase 1 (this repo today):** Go server foundation — signed telemetry ingest, fail-closed sanitization, durable replay, sanitized JSONL storage. No Android driver or AccessibilityService yet.

## Safety

- Not for unauthorized automation, third-party devices/accounts, stealth, credential capture, or security bypasses.
- Phase 1 does not target banking, password managers, private messaging, email, medical, or other sensitive app categories.
- Raw UI text, screenshots, credentials, and PII must never be logged or written to disk. Storage accepts only sanitized frames.
- Details: [`docs/SECURITY.md`](docs/SECURITY.md).

## What’s implemented

| Area | Status |
|------|--------|
| Protobuf contract + Buf-generated Go stubs | `proto/`, `server/gen/` |
| gRPC ingest (`TelemetryIngestService`) | protobuf wire |
| Ed25519 envelopes (`golem-harness-signature-v2`) | `server/pkg/signing` |
| Device allowlist, optional mTLS + cert fingerprint binding | config-driven |
| Durable replay (SQLite) | `replay_path` |
| Fail-closed sanitizer (allowlist, sensitive packages, regex redaction) | `server/internal/sanitize` |
| Sanitized JSONL + size/day rotation + fsync | `server/internal/storage` |
| Mock signed client | `mock-client/` |
| HTTP `/healthz`, `/readyz` | `golem-proxy` |

Inner signed payload is still JSON `RawFrame` (not protobuf `TelemetryFrame`). Parquet is **offline compaction only** — see [`docs/MVP.md`](docs/MVP.md).

## Repository layout

```
proto/golem/v1/          # telemetry.proto
server/                  # module golem-harness/server
  cmd/golem-proxy/       # proxy entrypoint
  gen/golem/v1/          # committed generated stubs
  pkg/{signing,trajectory,client}/   # public packages
  internal/{auth,config,ingest,sanitize,storage,testutil}/
  testdata/              # sanitized fixtures + config example only
mock-client/             # separate module; replace → ../server
docs/                    # ARCHITECTURE, MVP, SECURITY
AGENTS.md                # agent/contributor hard rules and quirks
```

## Prerequisites

- Go (see `server/go.mod`)
- [Buf](https://buf.build) CLI only if regenerating protos (`brew install bufbuild/buf/buf`)

## Tests

```bash
cd server && go test ./...
cd mock-client && go test ./...   # no package tests yet; go build . works
```

## Local proxy + mock client

1. **Generate a device key** (prints base64 public key; stores private key under `.devkeys/` — gitignored):

```bash
cd mock-client
go run . -addr 127.0.0.1:7443
# first run may fail if proxy is down; copy the printed public key
```

2. **Config:** copy `server/testdata/dev-config.example.json`, set `ed25519_public_key_base64`, keep `public_key_id` as `mock-key` (must match the client).

3. **Proxy:**

```bash
cd server
mkdir -p data
go run ./cmd/golem-proxy -config /path/to/dev-config.json
```

4. **Client again** (safe to run multiple times against the same data dir — fresh trajectory/frame ids and sequences each run):

```bash
cd mock-client
go run . -addr 127.0.0.1:7443
```

**Expected:** `com.android.settings` → accept + line in sanitized JSONL; synthetic bank package → quarantine, not stored.

Replay state lives in `replay_path` (default `data/replay.db`). JSONL path, rotation, and fsync are config fields — see the example config.

mTLS: generate local certs (OpenSSL/`mkcert`); do not commit keys. See [`docs/MVP.md`](docs/MVP.md).

## Protobuf codegen

```bash
make proto       # buf dep update && buf generate
make lint-proto
```

Commit regenerated files under `server/gen/` after schema changes.

## Documentation

| Doc | Contents |
|-----|----------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Data flow, trust boundaries, codegen |
| [`docs/MVP.md`](docs/MVP.md) | Implemented surface, local run, Parquet decision |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Threat model, canonical signature v2, known gaps |
| [`AGENTS.md`](AGENTS.md) | Hard rules and implementation quirks for contributors/agents |
| [`server/testdata/README.md`](server/testdata/README.md) | Fixture policy (sanitized-only on disk) |

## Out of scope / deferred

- Android AccessibilityService / device driver
- Cloud NER, OCR, inference, or telemetry APIs
- Multi-node shared replay
- Online Parquet ingest (offline compaction only, when triggered)
- Production key lifecycle / HSM

## License / use

Internal research tooling. Authorized use only — operator-owned or explicitly consenting environments.
