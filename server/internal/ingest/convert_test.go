package ingest

import (
	"bytes"
	"errors"
	"testing"
	"time"

	golemv1 "golem-harness/server/gen/golem/v1"
	"golem-harness/server/pkg/signing"
	"golem-harness/server/pkg/trajectory"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestEnvelopeFromProtoRejectsNilSignedAt(t *testing.T) {
	pb := &golemv1.SignatureEnvelope{
		ProtocolVersion:  "golem.v1",
		DeviceId:         "device",
		TrajectoryId:     "traj",
		FrameId:          "frame",
		Sequence:         1,
		SignedAt:         nil,
		CanonicalPayload: []byte(`{}`),
		PayloadSha256Hex: "abc",
		SignatureAlg:     signing.SignatureAlgEd25519,
	}
	_, err := envelopeFromProto(pb)
	if err == nil {
		t.Fatal("expected error for nil signed_at")
	}
	if !errors.Is(err, signing.ErrMalformed) {
		t.Fatalf("expected ErrMalformed, got %v", err)
	}
}

func TestEnvelopeFromProtoRejectsNilEnvelope(t *testing.T) {
	_, err := envelopeFromProto(nil)
	if !errors.Is(err, signing.ErrMalformed) {
		t.Fatalf("expected ErrMalformed, got %v", err)
	}
}

func TestEnvelopeRoundTripPreservesPayloadAndSignedAt(t *testing.T) {
	signedAt := time.Date(2026, 5, 31, 12, 0, 0, 123456789, time.UTC)
	payload := []byte(`{"protocol_version":"golem.v1"}`)
	in := signing.SignedEnvelope{
		ProtocolVersion:   "golem.v1",
		DeviceID:          "device",
		TrajectoryID:      "traj",
		FrameID:           "frame",
		Sequence:          7,
		SignedAt:          signedAt,
		Payload:           payload,
		DetachedSignature: []byte{1, 2, 3},
		PayloadSHA256Hex:  signing.HashPayload(payload),
		SignatureAlg:      signing.SignatureAlgEd25519,
		PublicKeyID:       "key-1",
	}
	pb := signing.EnvelopeToProto(in)
	if pb.GetSignedAt() == nil {
		t.Fatal("expected signed_at set on proto")
	}
	if !bytes.Equal(pb.GetCanonicalPayload(), payload) {
		t.Fatalf("payload mismatch")
	}
	out, err := envelopeFromProto(pb)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Payload, payload) {
		t.Fatalf("round-trip payload mismatch")
	}
	if !out.SignedAt.Equal(signedAt) {
		t.Fatalf("signed_at: got %v want %v", out.SignedAt, signedAt)
	}
	if out.Sequence != 7 || out.DeviceID != "device" || out.PublicKeyID != "key-1" {
		t.Fatalf("metadata mismatch: %+v", out)
	}
}

func TestDecisionRoundTrip(t *testing.T) {
	cases := []trajectory.Decision{
		trajectory.DecisionAccept,
		trajectory.DecisionDrop,
		trajectory.DecisionQuarantine,
	}
	for _, d := range cases {
		got := signing.DecisionFromProto(signing.DecisionToProto(d))
		if got != d {
			t.Fatalf("decision round-trip: got %q want %q", got, d)
		}
	}
	if signing.DecisionToProto("") != golemv1.Decision_DECISION_UNSPECIFIED {
		t.Fatal("empty decision should map to UNSPECIFIED")
	}
}

func TestEnvelopeFromProtoDoesNotTreatEpochAsMissing(t *testing.T) {
	pb := &golemv1.SignatureEnvelope{
		ProtocolVersion:  "golem.v1",
		DeviceId:         "device",
		TrajectoryId:     "traj",
		FrameId:          "frame",
		Sequence:         1,
		SignedAt:         timestamppb.New(time.Unix(0, 0).UTC()),
		CanonicalPayload: []byte(`{}`),
		PayloadSha256Hex: "abc",
		SignatureAlg:     signing.SignatureAlgEd25519,
	}
	out, err := envelopeFromProto(pb)
	if err != nil {
		t.Fatalf("explicit epoch should convert: %v", err)
	}
	if out.SignedAt.IsZero() {
		t.Fatal("epoch must not become Go zero time")
	}
}
