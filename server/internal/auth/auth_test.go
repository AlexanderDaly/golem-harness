package auth_test

import (
	"context"
	"crypto/ed25519"
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
