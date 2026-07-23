# Security Notes

## Authorized Use Only

Golem-Harness is for operator-owned Android devices, controlled emulators, and explicitly consenting test users only. It must not be used against third-party accounts, third-party devices, or services without authorization.

## Non-Goals

Phase 1 does not implement stealth, persistence, anti-detection, credential capture, Android security bypasses, banking automation, password-manager automation, private messaging automation, email automation, or medical-app automation.

## Threat Model

Primary risks in Phase 1 are unsafe telemetry persistence, unauthorized device submission, replayed frames, overbroad package collection, accidental logging of sensitive content, and weak key handling.

Mitigations implemented:

- Ed25519 detached signatures over canonical payload bytes, including `signature_alg`, `public_key_id`, and `client_cert_fingerprint_sha256`.
- Device id to public key registry; `public_key_id` must match when either registry or envelope sets it.
- Payload hash verification.
- Timestamp expiry.
- Durable SQLite replay guard for sequence and frame ids (survives proxy restart).
- Bounded gRPC receive size and bounded payload checks.
- Default-deny package allowlist.
- Sensitive-package kill switch.
- Sanitized-only storage type.
- Safe metadata logging only.
- Client certificate binding: when registry and/or envelope declare a fingerprint, peer cert is required and must match (fail closed). Config forces `mtls.require_client` when any device sets a fingerprint.
- `MemoryReplayGuard` fails closed when per-device seen-frame cap is exceeded (tests only; proxy uses SQLite).

## Sensitive Packages

Sensitive packages are quarantined before storage. Built-ins include synthetic banking, password manager, medical, Gmail, WhatsApp, and Signal package identifiers. Config can add more package names.

## Log Safety

Logs must never include raw XML, screenshots, text values, content descriptions, credentials, signatures, private keys, auth headers, or PII. The proxy logs hashed device and trajectory identifiers plus decisions and reason codes.

## Key Handling

Mock-client keys are test-only and generated under `.devkeys/` by default. Do not commit generated private keys. Production-like key lifecycle, rotation, revocation, and hardware-backed key storage remain future work.

## Sanitizer Failure

Sanitizer errors fail closed. The ingest service returns a drop decision and does not call storage.

## Canonical signature (v2)

`signing.CanonicalBytes` is the **only** implementation of the signed prefix. Do not reimplement it.

Layout (line by line), then a blank line, then raw payload bytes:

```
golem-harness-signature-v2
protocol_version=<string>
device_id=<string>
trajectory_id=<string>
frame_id=<string>
sequence=<decimal uint64>
signed_at=<RFC3339Nano UTC>
payload_sha256_hex=<hex sha256 of payload>
signature_alg=<string, currently Ed25519>
public_key_id=<string, may be empty>
client_cert_fingerprint_sha256=<string, may be empty>

<raw payload bytes>
```

Empty optional strings still appear as `public_key_id=\n` and `client_cert_fingerprint_sha256=\n` so the signed surface is fixed-width in field set.

### Historical note (v1)

`golem-harness-signature-v1` was the original domain separator (metadata through `payload_sha256_hex` only). During pre-release hardening, additional fields (`signature_alg`, `public_key_id`, `client_cert_fingerprint_sha256`) were briefly added under the **v1** label without bumping the separator — that intermediate form never shipped to devices and is **retired**. Current code speaks **v2** only. Clients built against an older separator will fail verification with `invalid_signature`; that indicates format skew, not a bad device key.

## Known Gaps

- Replay SQLite is local single-process only (no multi-node shared replay).
- Local NER is an interface with a conservative no-op placeholder.
- Vision redaction is an interface and bounding-box model only.
- Parquet is offline compaction only (not implemented); live storage is sanitized JSONL.
- Signed frame payload remains JSON inside the protobuf envelope; full `TelemetryFrame` protobuf payload is not used yet.
- Adding a second signature algorithm still requires deliberate verifier + client work (alg is signed, but only Ed25519 is accepted today).
