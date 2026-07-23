# Golem-Harness

Golem-Harness is a consent-based Android automation research harness for operator-owned devices, controlled emulators, and explicitly consenting test users.

This repository currently contains only the Go-side server foundation:

- a versioned protobuf telemetry contract (Buf-generated Go stubs in `server/gen/`)
- an mTLS-capable ingestion proxy scaffold
- Ed25519 signed payload verification
- fail-closed sanitizer interfaces and implementation
- sanitized-only storage boundary
- synthetic fixtures and tests
- a mock signed client

## Safety Scope

This project is not for unauthorized automation. It does not implement stealth, persistence, anti-detection, credential capture, Android security bypasses, or automation against third-party accounts or devices.

Phase 1 avoids sensitive app categories such as banking apps, password managers, private messaging, email, and medical apps.

## Quick Start

Run the server tests:

```bash
cd server
go test ./...
```

Run the mock client tests:

```bash
cd mock-client
go test ./...
```

See `docs/MVP.md` for local proxy and mock-client usage.

Replay state persists in the proxy’s `replay_path` SQLite file (default `data/replay.db` beside storage). The mock client uses a fresh trajectory id, unique frame ids, and time-based sequences each run so a second run against the same proxy data dir does not hit replay rejection.

## Codegen

```bash
# requires buf CLI
make proto
```

## Current Limitations

- Signed frame payload is still JSON `RawFrame` (envelope/RPC are protobuf).
- Storage is sanitized JSONL, not Parquet.
- Replay protection is local SQLite (single process); not multi-node.
- Local NER and vision redaction are placeholder interfaces.
- No Android driver or AccessibilityService implementation is included.
