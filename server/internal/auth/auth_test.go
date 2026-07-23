package auth_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golem-harness/server/internal/auth"
	"golem-harness/server/internal/testutil"
)

func TestVerifierAcceptsValidEd25519Signature(t *testing.T) {
	publicKey, privateKey := testutil.KeyPair(1)
	verifier := newVerifier(t, publicKey)
	envelope := testutil.SignedEnvelope(t, privateKey, testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings"), fixedNow())

	if err := verifier.Verify(context.Background(), envelope, ""); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifierRejectsInvalidSignature(t *testing.T) {
	publicKey, privateKey := testutil.KeyPair(1)
	verifier := newVerifier(t, publicKey)
	envelope := testutil.SignedEnvelope(t, privateKey, testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings"), fixedNow())
	envelope.DetachedSignature[0] ^= 0xff

	err := verifier.Verify(context.Background(), envelope, "")
	if !errors.Is(err, auth.ErrInvalidSignature) {
		t.Fatalf("expected invalid signature, got %v", err)
	}
}

func TestVerifierRejectsMissingSignature(t *testing.T) {
	publicKey, privateKey := testutil.KeyPair(1)
	verifier := newVerifier(t, publicKey)
	envelope := testutil.SignedEnvelope(t, privateKey, testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings"), fixedNow())
	envelope.DetachedSignature = nil

	err := verifier.Verify(context.Background(), envelope, "")
	if !errors.Is(err, auth.ErrMissingSignature) {
		t.Fatalf("expected missing signature, got %v", err)
	}
}

func TestVerifierRejectsExpiredTimestamp(t *testing.T) {
	publicKey, privateKey := testutil.KeyPair(1)
	verifier := newVerifier(t, publicKey)
	envelope := testutil.SignedEnvelope(t, privateKey, testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings"), fixedNow().Add(-10*time.Minute))

	err := verifier.Verify(context.Background(), envelope, "")
	if !errors.Is(err, auth.ErrExpiredPayload) {
		t.Fatalf("expected expired payload, got %v", err)
	}
}

func TestVerifierRejectsReplayedFrameAndSequence(t *testing.T) {
	publicKey, privateKey := testutil.KeyPair(1)
	verifier := newVerifier(t, publicKey)
	frame := testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings")
	envelope := testutil.SignedEnvelope(t, privateKey, frame, fixedNow())

	if err := verifier.Verify(context.Background(), envelope, ""); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if err := verifier.Verify(context.Background(), envelope, ""); !errors.Is(err, auth.ErrReplay) {
		t.Fatalf("expected replayed frame rejection, got %v", err)
	}

	next := testutil.SignedEnvelope(t, privateKey, testutil.RawFrame(testutil.AllowedPkg, "frame-2", 1, "Settings"), fixedNow())
	if err := verifier.Verify(context.Background(), next, ""); !errors.Is(err, auth.ErrReplay) {
		t.Fatalf("expected replayed sequence rejection, got %v", err)
	}
}

func TestVerifierRejectsUnauthorizedDeviceIDAndWrongPublicKey(t *testing.T) {
	publicKey, privateKey := testutil.KeyPair(1)
	verifier := newVerifier(t, publicKey)
	frame := testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings")
	frame.Device.DeviceID = "unknown-device"
	envelope := testutil.SignedEnvelope(t, privateKey, frame, fixedNow())

	err := verifier.Verify(context.Background(), envelope, "")
	if !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("expected unauthorized device, got %v", err)
	}

	_, wrongPrivateKey := testutil.KeyPair(2)
	wrongKeyEnvelope := testutil.SignedEnvelope(t, wrongPrivateKey, testutil.RawFrame(testutil.AllowedPkg, "frame-2", 2, "Settings"), fixedNow())
	err = verifier.Verify(context.Background(), wrongKeyEnvelope, "")
	if !errors.Is(err, auth.ErrInvalidSignature) {
		t.Fatalf("expected wrong public key signature rejection, got %v", err)
	}
}

func TestVerifierRejectsOversizedPayload(t *testing.T) {
	publicKey, privateKey := testutil.KeyPair(1)
	verifier := newVerifier(t, publicKey)
	verifier.MaxPayloadBytes = 128
	frame := testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, strings.Repeat("A", 1024))
	envelope := testutil.SignedEnvelope(t, privateKey, frame, fixedNow())

	err := verifier.Verify(context.Background(), envelope, "")
	if !errors.Is(err, auth.ErrOversizedPayload) {
		t.Fatalf("expected oversized payload, got %v", err)
	}
}

func TestVerifierRejectsMissingPublicKeyIDWhenRegistryRequiresIt(t *testing.T) {
	publicKey, privateKey := testutil.KeyPair(1)
	verifier := newVerifier(t, publicKey)
	frame := testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings")
	payload, err := jsonMarshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := auth.SignEnvelope(privateKey, auth.SignedEnvelope{
		ProtocolVersion: frame.ProtocolVersion,
		DeviceID:        frame.Device.DeviceID,
		TrajectoryID:    frame.TrajectoryID,
		FrameID:         frame.FrameID,
		Sequence:        frame.Sequence,
		SignedAt:        fixedNow(),
		Payload:         payload,
		SignatureAlg:    auth.SignatureAlgEd25519,
		// PublicKeyID intentionally empty while registry has test-key
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), envelope, ""); !errors.Is(err, auth.ErrUnauthorized) {
		t.Fatalf("expected unauthorized for missing public_key_id, got %v", err)
	}
}

func TestVerifierEnforcesClientCertFingerprint(t *testing.T) {
	publicKey, privateKey := testutil.KeyPair(1)
	registry, err := auth.NewStaticDeviceRegistry([]auth.Device{{
		DeviceID:                    testutil.DeviceID,
		PublicKey:                   publicKey,
		PublicKeyID:                 "test-key",
		ClientCertFingerprintSHA256: "abc123",
	}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := &auth.Verifier{
		Registry:        registry,
		ReplayGuard:     auth.NewMemoryReplayGuard(),
		MaxPayloadBytes: 64 * 1024,
		TTL:             5 * time.Minute,
		Now:             fixedNow,
	}
	frame := testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings")
	payload, err := jsonMarshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := auth.SignEnvelope(privateKey, auth.SignedEnvelope{
		ProtocolVersion:             frame.ProtocolVersion,
		DeviceID:                    frame.Device.DeviceID,
		TrajectoryID:                frame.TrajectoryID,
		FrameID:                     frame.FrameID,
		Sequence:                    frame.Sequence,
		SignedAt:                    fixedNow(),
		Payload:                     payload,
		SignatureAlg:                auth.SignatureAlgEd25519,
		PublicKeyID:                 "test-key",
		ClientCertFingerprintSHA256: "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(context.Background(), envelope, ""); !errors.Is(err, auth.ErrCertMismatch) {
		t.Fatalf("expected cert mismatch without peer, got %v", err)
	}
	if err := verifier.Verify(context.Background(), envelope, "wrong"); !errors.Is(err, auth.ErrCertMismatch) {
		t.Fatalf("expected cert mismatch for wrong peer, got %v", err)
	}
	if err := verifier.Verify(context.Background(), envelope, "abc123"); err != nil {
		t.Fatalf("matching peer cert should accept: %v", err)
	}
}

func TestMemoryReplayGuardFailsClosedWhenFull(t *testing.T) {
	guard := auth.NewMemoryReplayGuard()
	guard.SetMaxSeenFramesForTest(2)
	if err := guard.CheckAndRecord("d", "f1", 1); err != nil {
		t.Fatal(err)
	}
	if err := guard.CheckAndRecord("d", "f2", 2); err != nil {
		t.Fatal(err)
	}
	if err := guard.CheckAndRecord("d", "f3", 3); !errors.Is(err, auth.ErrReplayStateFull) {
		t.Fatalf("expected full, got %v", err)
	}
}

func TestCanonicalBytesIncludesAlgKeyAndCert(t *testing.T) {
	payload := []byte(`{}`)
	envelope := auth.SignedEnvelope{
		ProtocolVersion:             "golem.v1",
		DeviceID:                    "d",
		TrajectoryID:                "t",
		FrameID:                     "f",
		Sequence:                    1,
		SignedAt:                    fixedNow(),
		Payload:                     payload,
		PayloadSHA256Hex:            auth.HashPayload(payload),
		SignatureAlg:                auth.SignatureAlgEd25519,
		PublicKeyID:                 "k",
		ClientCertFingerprintSHA256: "fp",
	}
	canonical, err := auth.CanonicalBytes(envelope)
	if err != nil {
		t.Fatal(err)
	}
	s := string(canonical)
	for _, want := range []string{
		"golem-harness-signature-v2\n",
		"signature_alg=Ed25519\n",
		"public_key_id=k\n",
		"client_cert_fingerprint_sha256=fp\n",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("canonical missing %q in %q", want, s)
		}
	}
}

func jsonMarshal(v any) ([]byte, error) {
	return json.Marshal(v)
}

func newVerifier(t *testing.T, publicKey ed25519.PublicKey) *auth.Verifier {
	t.Helper()
	registry, err := auth.NewStaticDeviceRegistry([]auth.Device{
		{DeviceID: testutil.DeviceID, PublicKey: publicKey, PublicKeyID: "test-key"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &auth.Verifier{
		Registry:        registry,
		ReplayGuard:     auth.NewMemoryReplayGuard(),
		MaxPayloadBytes: 64 * 1024,
		TTL:             5 * time.Minute,
		Now:             fixedNow,
	}
}

func fixedNow() time.Time {
	return time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
}
