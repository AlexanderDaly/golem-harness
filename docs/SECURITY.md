# Security Notes

## Authorized Use Only

Golem-Harness is for operator-owned Android devices, controlled emulators, and explicitly consenting test users only. It must not be used against third-party accounts, third-party devices, or services without authorization.

## Non-Goals

Phase 1 does not implement stealth, persistence, anti-detection, credential capture, Android security bypasses, banking automation, password-manager automation, private messaging automation, email automation, or medical-app automation.

## Threat Model

Primary risks in Phase 1 are unsafe telemetry persistence, unauthorized device submission, replayed frames, overbroad package collection, accidental logging of sensitive content, and weak key handling.

Mitigations implemented:

- Ed25519 detached signatures over canonical payload bytes.
- Device id to public key registry.
- Payload hash verification.
- Timestamp expiry.
- In-memory replay guard for sequence and frame ids.
- Bounded gRPC receive size and bounded payload checks.
- Default-deny package allowlist.
- Sensitive-package kill switch.
- Sanitized-only storage type.
- Safe metadata logging only.

## Sensitive Packages

Sensitive packages are quarantined before storage. Built-ins include synthetic banking, password manager, medical, Gmail, WhatsApp, and Signal package identifiers. Config can add more package names.

## Log Safety

Logs must never include raw XML, screenshots, text values, content descriptions, credentials, signatures, private keys, auth headers, or PII. The proxy logs hashed device and trajectory identifiers plus decisions and reason codes.

## Key Handling

Mock-client keys are test-only and generated under `.devkeys/` by default. Do not commit generated private keys. Production-like key lifecycle, rotation, revocation, and hardware-backed key storage remain future work.

## Sanitizer Failure

Sanitizer errors fail closed. The ingest service returns a drop decision and does not call storage.

## Known Gaps

- Replay state is in-memory only and resets on proxy restart.
- Local NER is an interface with a conservative no-op placeholder.
- Vision redaction is an interface and bounding-box model only.
- Parquet storage is not yet implemented.
- Signed frame payload remains JSON inside the protobuf envelope; full `TelemetryFrame` protobuf payload is not used yet.
