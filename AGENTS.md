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
