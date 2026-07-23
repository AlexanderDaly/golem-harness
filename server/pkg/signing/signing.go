package signing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const SignatureAlgEd25519 = "Ed25519"

var (
	ErrMissingSignature = errors.New("missing signature")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrMalformed        = errors.New("malformed signed envelope")
)

// SignedEnvelope is the domain form of a device-signed ingest envelope.
// CanonicalBytes covers the fields below through ClientCertFingerprintSHA256
// (empty optional strings are still included) plus the raw Payload bytes.
type SignedEnvelope struct {
	ProtocolVersion             string
	DeviceID                    string
	TrajectoryID                string
	FrameID                     string
	Sequence                    uint64
	SignedAt                    time.Time
	Payload                     []byte
	DetachedSignature           []byte
	PayloadSHA256Hex            string
	SignatureAlg                string
	PublicKeyID                 string
	ClientCertFingerprintSHA256 string
}

func CanonicalBytes(envelope SignedEnvelope) ([]byte, error) {
	if envelope.ProtocolVersion == "" || envelope.DeviceID == "" || envelope.TrajectoryID == "" || envelope.FrameID == "" {
		return nil, fmt.Errorf("%w: canonical envelope fields are required", ErrMalformed)
	}
	if envelope.PayloadSHA256Hex == "" {
		return nil, fmt.Errorf("%w: payload hash is required", ErrMalformed)
	}
	if envelope.SignatureAlg == "" {
		return nil, fmt.Errorf("%w: signature_alg is required", ErrMalformed)
	}

	// Domain separator v2. Single source of truth — do not duplicate this layout.
	prefix := "golem-harness-signature-v2\n" +
		"protocol_version=" + envelope.ProtocolVersion + "\n" +
		"device_id=" + envelope.DeviceID + "\n" +
		"trajectory_id=" + envelope.TrajectoryID + "\n" +
		"frame_id=" + envelope.FrameID + "\n" +
		"sequence=" + strconv.FormatUint(envelope.Sequence, 10) + "\n" +
		"signed_at=" + envelope.SignedAt.UTC().Format(time.RFC3339Nano) + "\n" +
		"payload_sha256_hex=" + envelope.PayloadSHA256Hex + "\n" +
		"signature_alg=" + envelope.SignatureAlg + "\n" +
		"public_key_id=" + envelope.PublicKeyID + "\n" +
		"client_cert_fingerprint_sha256=" + envelope.ClientCertFingerprintSHA256 + "\n\n"

	out := make([]byte, 0, len(prefix)+len(envelope.Payload))
	out = append(out, []byte(prefix)...)
	out = append(out, envelope.Payload...)
	return out, nil
}

func HashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func SignEnvelope(privateKey ed25519.PrivateKey, envelope SignedEnvelope) (SignedEnvelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedEnvelope{}, fmt.Errorf("ed25519 private key must be %d bytes", ed25519.PrivateKeySize)
	}
	if envelope.SignatureAlg == "" {
		envelope.SignatureAlg = SignatureAlgEd25519
	}
	if envelope.SignatureAlg != SignatureAlgEd25519 {
		return SignedEnvelope{}, fmt.Errorf("%w: unsupported signature algorithm", ErrMalformed)
	}
	envelope.PayloadSHA256Hex = HashPayload(envelope.Payload)
	canonical, err := CanonicalBytes(envelope)
	if err != nil {
		return SignedEnvelope{}, err
	}
	envelope.DetachedSignature = ed25519.Sign(privateKey, canonical)
	return envelope, nil
}

func SafeHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
