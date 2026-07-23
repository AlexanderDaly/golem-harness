package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golem-harness/server/pkg/signing"
)

const (
	SignatureAlgEd25519 = signing.SignatureAlgEd25519
	defaultClockSkew    = 30 * time.Second
	// MaxMemorySeenFrames caps per-device frame ID retention in MemoryReplayGuard.
	// Fail closed when exceeded (tests / short runs only; proxy uses SQLite).
	MaxMemorySeenFrames = 100_000
)

var (
	ErrMissingSignature = signing.ErrMissingSignature
	ErrInvalidSignature = signing.ErrInvalidSignature
	ErrExpiredPayload   = errors.New("expired payload")
	ErrFuturePayload    = errors.New("payload timestamp is too far in the future")
	ErrOversizedPayload = errors.New("oversized payload")
	ErrUnauthorized     = errors.New("unauthorized device")
	ErrReplay           = errors.New("replayed frame")
	ErrMalformed        = signing.ErrMalformed
	ErrReplayStateFull  = errors.New("replay state full")
	ErrCertMismatch     = errors.New("client certificate fingerprint mismatch")
)

type SignedEnvelope = signing.SignedEnvelope

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

// RequiresClientCert reports whether any registered device binds a client cert fingerprint.
func (r *StaticDeviceRegistry) RequiresClientCert() bool {
	if r == nil {
		return false
	}
	for _, d := range r.devices {
		if d.ClientCertFingerprintSHA256 != "" {
			return true
		}
	}
	return false
}

type ReplayGuard interface {
	CheckAndRecord(deviceID, frameID string, sequence uint64) error
}

type MemoryReplayGuard struct {
	mu             sync.Mutex
	devices        map[string]*replayState
	maxSeenFrames  int
}

type replayState struct {
	maxSequence uint64
	seenFrames  map[string]struct{}
}

func NewMemoryReplayGuard() *MemoryReplayGuard {
	return &MemoryReplayGuard{
		devices:       make(map[string]*replayState),
		maxSeenFrames: MaxMemorySeenFrames,
	}
}

// SetMaxSeenFramesForTest overrides the per-device frame-ID cap (tests only).
func (g *MemoryReplayGuard) SetMaxSeenFramesForTest(n int) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.maxSeenFrames = n
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
	limit := g.maxSeenFrames
	if limit <= 0 {
		limit = MaxMemorySeenFrames
	}
	if len(state.seenFrames) >= limit {
		return ErrReplayStateFull
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
	// Public key id is signed; registry id must match when either side sets it.
	if device.PublicKeyID != "" || envelope.PublicKeyID != "" {
		if device.PublicKeyID == "" || envelope.PublicKeyID == "" || device.PublicKeyID != envelope.PublicKeyID {
			return ErrUnauthorized
		}
	}
	if err := bindClientCert(device, envelope, peerCertFingerprintSHA256); err != nil {
		return err
	}

	canonical, err := signing.CanonicalBytes(envelope)
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

// bindClientCert enforces fail-closed cert binding when the registry and/or
// envelope claims a fingerprint. Peer fingerprint is required whenever either
// side declares a binding.
func bindClientCert(device Device, envelope SignedEnvelope, peerCertFingerprintSHA256 string) error {
	wantRegistry := device.ClientCertFingerprintSHA256
	wantEnvelope := envelope.ClientCertFingerprintSHA256
	if wantRegistry == "" && wantEnvelope == "" {
		return nil
	}
	if peerCertFingerprintSHA256 == "" {
		return ErrCertMismatch
	}
	if wantRegistry != "" && wantRegistry != peerCertFingerprintSHA256 {
		return ErrCertMismatch
	}
	if wantEnvelope != "" && wantEnvelope != peerCertFingerprintSHA256 {
		return ErrCertMismatch
	}
	// When both registry and envelope declare fingerprints, they must agree.
	if wantRegistry != "" && wantEnvelope != "" && wantRegistry != wantEnvelope {
		return ErrCertMismatch
	}
	return nil
}

func CanonicalBytes(envelope SignedEnvelope) ([]byte, error) {
	return signing.CanonicalBytes(envelope)
}

func HashPayload(payload []byte) string {
	return signing.HashPayload(payload)
}

func SignEnvelope(privateKey ed25519.PrivateKey, envelope SignedEnvelope) (SignedEnvelope, error) {
	return signing.SignEnvelope(privateKey, envelope)
}

func SafeHash(value string) string {
	return signing.SafeHash(value)
}
