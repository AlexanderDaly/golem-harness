# AGENTS.md

You are working on Project Golem-Harness, an internal, consent-based Android automation research harness for operator-owned devices, controlled emulators, and explicitly consenting test users only.

## Hard Rules

- Never log or persist raw telemetry, raw XML, screenshots, raw UI text, credentials, signatures, private keys, auth headers, or PII.
- Unsanitized telemetry may exist only in bounded in-memory request scope.
- Never use cloud APIs for sanitization, NER, OCR, telemetry processing, screenshots, or model inference.
- Preserve authorized-use-only scope. Do not add stealth, persistence, anti-detection, credential capture, Android security bypasses, or automation against third-party accounts/devices without authorization.
- Do not automate banking apps, password managers, private messaging, email, medical apps, or other sensitive apps in Phase 1.
- Prefer fail-closed behavior. Sanitizer failures must prevent storage.

## Engineering Practice

- Always run relevant tests before finishing; for server work, run `go test ./...` from `server/`.
- Keep security-sensitive code small, readable, and dependency-injected.
- Add tests for failure paths, not only happy paths.
- Keep fixtures synthetic. Store only sanitized fixture data on disk.
- Document measurable gaps honestly instead of implying future capabilities are complete.
- Keep Phase 1 scoped to safe native/system surfaces and synthetic fixtures.

## Current Shape

- Protobuf contract: `proto/golem/v1/telemetry.proto`
- Go server module: `server/`
- Mock signed client: `mock-client/`
- Documentation: `docs/`

Generated protobuf Go bindings are not committed yet because the local protobuf toolchain is not currently installed.

## Cursor Cloud specific instructions

Two Go modules: `server/` (the `golem-proxy` gRPC/HTTP ingestion service) and `mock-client/` (a signed test client). Standard commands live in `README.md` and `docs/MVP.md`; test with `go test ./...` in each module.

Non-obvious caveats:

- Go toolchain: both `go.mod` files pin `go 1.25.0`, but the base VM ships an older `go`. The default `GOTOOLCHAIN=auto` transparently downloads `go1.25.0` on the first `go` command (needs network once); no manual Go install is required.
- End-to-end proxy run: `mock-client` writes its Ed25519 keypair to `mock-client/.devkeys/` and prints the public key. Copy that key into a config derived from `server/testdata/dev-config.example.json` (the `device_id` must stay `mock-device` to match the synthetic frames). Start the proxy from `server/` with `go run ./cmd/golem-proxy -config <config>`; the `storage_path` dir (e.g. `data/`) is gitignored.
- Replay guard is in-memory only: re-running `mock-client` against the same proxy process returns `AlreadyExists: replayed_frame`. Restart the proxy to reset replay state for a fresh demo.
- Expected end-to-end result: the `com.android.settings` frame is `accept`ed and appended to the sanitized JSONL (raw text stored only as hashes); the `com.example.bank` frame is `quarantine`d and never persisted.
