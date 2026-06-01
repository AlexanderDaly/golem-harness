package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

const (
	SignatureAlgEd25519 = "Ed25519"
	defaultClockSkew    = 30 * time.Second
)

var (
	ErrMissingSignature = errors.New("missing signature")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrExpiredPayload   = errors.New("expired payload")
	ErrFuturePayload    = errors.New("payload timestamp is too far in the future")
	ErrOversizedPayload = errors.New("oversized payload")
	ErrUnauthorized     = errors.New("unauthorized device")
	ErrReplay           = errors.New("replayed frame")
	ErrMalformed        = errors.New("malformed signed envelope")
)

type SignedEnvelope struct {
	ProtocolVersion             string    `json:"protocol_version"`
	DeviceID                    string    `json:"device_id"`
	TrajectoryID                string    `json:"trajectory_id"`
	FrameID                     string    `json:"frame_id"`
	Sequence                    uint64    `json:"sequence"`
	SignedAt                    time.Time `json:"signed_at"`
	Payload                     []byte    `json:"payload"`
	DetachedSignature           []byte    `json:"detached_signature"`
	PayloadSHA256Hex            string    `json:"payload_sha256_hex"`
	SignatureAlg                string    `json:"signature_alg"`
	PublicKeyID                 string    `json:"public_key_id,omitempty"`
	ClientCertFingerprintSHA256 string    `json:"client_cert_fingerprint_sha256,omitempty"`
}

type Device struct {
	DeviceID                    string
	PublicKey                   ed25519.PublicKey
	PublicKeyID                 string
	ClientCertFingerprintSHA256 string
}

type DeviceRegistry interface {
	LookupDevice(ctx context.Context, deviceID string) (Device, bool)
}

type StaticDeviceRegistry struct {
	devices map[string]Device
}

func NewStaticDeviceRegistry(devices []Device) (*StaticDeviceRegistry, error) {
	registry := &StaticDeviceRegistry{devices: make(map[string]Device, len(devices))}
	for _, device := range devices {
		if device.DeviceID == "" {
			return nil, fmt.Errorf("%w: device id is required", ErrMalformed)
		}
		if len(device.PublicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: device %q public key must be %d bytes", ErrMalformed, device.DeviceID, ed25519.PublicKeySize)
		}
		registry.devices[device.DeviceID] = device
	}
	return registry, nil
}

func (r *StaticDeviceRegistry) LookupDevice(_ context.Context, deviceID string) (Device, bool) {
	device, ok := r.devices[deviceID]
	return device, ok
}

type ReplayGuard interface {
	CheckAndRecord(deviceID, frameID string, sequence uint64) error
}

type MemoryReplayGuard struct {
	mu      sync.Mutex
	devices map[string]*replayState
}

type replayState struct {
	maxSequence uint64
	seenFrames  map[string]struct{}
}

func NewMemoryReplayGuard() *MemoryReplayGuard {
	return &MemoryReplayGuard{devices: make(map[string]*replayState)}
}

func (g *MemoryReplayGuard) CheckAndRecord(deviceID, frameID string, sequence uint64) error {
	if deviceID == "" || frameID == "" {
		return fmt.Errorf("%w: device id and frame id are required", ErrMalformed)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	state := g.devices[deviceID]
	if state == nil {
		state = &replayState{seenFrames: make(map[string]struct{})}
		g.devices[deviceID] = state
	}
	if _, ok := state.seenFrames[frameID]; ok {
		return ErrReplay
	}
	if sequence <= state.maxSequence {
		return ErrReplay
	}

	state.seenFrames[frameID] = struct{}{}
	state.maxSequence = sequence
	return nil
}

type Verifier struct {
	Registry        DeviceRegistry
	ReplayGuard     ReplayGuard
	MaxPayloadBytes int
	TTL             time.Duration
	Now             func() time.Time
}

func (v *Verifier) Verify(ctx context.Context, envelope SignedEnvelope, peerCertFingerprintSHA256 string) error {
	if v.Registry == nil || v.ReplayGuard == nil {
		return errors.New("auth verifier is missing required dependencies")
	}
	if envelope.ProtocolVersion == "" || envelope.DeviceID == "" || envelope.TrajectoryID == "" || envelope.FrameID == "" {
		return fmt.Errorf("%w: protocol version, device id, trajectory id, and frame id are required", ErrMalformed)
	}
	if envelope.SignatureAlg != SignatureAlgEd25519 {
		return fmt.Errorf("%w: unsupported signature algorithm", ErrMalformed)
	}
	if len(envelope.DetachedSignature) == 0 {
		return ErrMissingSignature
	}
	if len(envelope.DetachedSignature) != ed25519.SignatureSize {
		return ErrInvalidSignature
	}
	if len(envelope.Payload) == 0 {
		return fmt.Errorf("%w: payload is required", ErrMalformed)
	}
	if v.MaxPayloadBytes > 0 && len(envelope.Payload) > v.MaxPayloadBytes {
		return ErrOversizedPayload
	}

	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	ttl := v.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	signedAt := envelope.SignedAt
	if signedAt.IsZero() {
		return fmt.Errorf("%w: signed_at is required", ErrMalformed)
	}
	if signedAt.After(now().Add(defaultClockSkew)) {
		return ErrFuturePayload
	}
	if now().Sub(signedAt) > ttl {
		return ErrExpiredPayload
	}

	payloadHash := sha256.Sum256(envelope.Payload)
	payloadHashHex := hex.EncodeToString(payloadHash[:])
	if envelope.PayloadSHA256Hex == "" || envelope.PayloadSHA256Hex != payloadHashHex {
		return fmt.Errorf("%w: payload hash mismatch", ErrMalformed)
	}

	device, ok := v.Registry.LookupDevice(ctx, envelope.DeviceID)
	if !ok {
		return ErrUnauthorized
	}
	if device.PublicKeyID != "" && envelope.PublicKeyID != "" && device.PublicKeyID != envelope.PublicKeyID {
		return ErrUnauthorized
	}
	if device.ClientCertFingerprintSHA256 != "" && peerCertFingerprintSHA256 != "" && device.ClientCertFingerprintSHA256 != peerCertFingerprintSHA256 {
		return ErrUnauthorized
	}

	canonical, err := CanonicalBytes(envelope)
	if err != nil {
		return err
	}
	if !ed25519.Verify(device.PublicKey, canonical, envelope.DetachedSignature) {
		return ErrInvalidSignature
	}
	if err := v.ReplayGuard.CheckAndRecord(envelope.DeviceID, envelope.FrameID, envelope.Sequence); err != nil {
		return err
	}
	return nil
}

func CanonicalBytes(envelope SignedEnvelope) ([]byte, error) {
	if envelope.ProtocolVersion == "" || envelope.DeviceID == "" || envelope.TrajectoryID == "" || envelope.FrameID == "" {
		return nil, fmt.Errorf("%w: canonical envelope fields are required", ErrMalformed)
	}
	if envelope.PayloadSHA256Hex == "" {
		return nil, fmt.Errorf("%w: payload hash is required", ErrMalformed)
	}

	prefix := "golem-harness-signature-v1\n" +
		"protocol_version=" + envelope.ProtocolVersion + "\n" +
		"device_id=" + envelope.DeviceID + "\n" +
		"trajectory_id=" + envelope.TrajectoryID + "\n" +
		"frame_id=" + envelope.FrameID + "\n" +
		"sequence=" + strconv.FormatUint(envelope.Sequence, 10) + "\n" +
		"signed_at=" + envelope.SignedAt.UTC().Format(time.RFC3339Nano) + "\n" +
		"payload_sha256_hex=" + envelope.PayloadSHA256Hex + "\n\n"

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
	envelope.SignatureAlg = SignatureAlgEd25519
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
