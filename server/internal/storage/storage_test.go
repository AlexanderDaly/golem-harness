package storage_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"golem-harness/server/internal/storage"
	"golem-harness/server/pkg/trajectory"
)

func TestJSONLSinkAcceptsOnlySanitizedFrames(t *testing.T) {
	sink, err := storage.NewJSONLSink(t.TempDir() + "/frames.jsonl")
	if err != nil {
		t.Fatal(err)
	}

	err = sink.WriteSanitizedFrame(context.Background(), trajectory.SanitizedFrame{})
	if err == nil {
		t.Fatalf("expected unsafe frame rejection")
	}

	frame := sanitizedFrame()
	if err := sink.WriteSanitizedFrame(context.Background(), frame); err != nil {
		t.Fatalf("expected sanitized frame accepted: %v", err)
	}
}

func TestJSONLSinkDoesNotWriteRawSyntheticPII(t *testing.T) {
	path := t.TempDir() + "/frames.jsonl"
	sink, err := storage.NewJSONLSink(path)
	if err != nil {
		t.Fatal(err)
	}
	frame := sanitizedFrame()
	frame.UIRoot.TextRedactionStatus = trajectory.RedactionRedacted
	frame.UIRoot.TextHash = ""

	if err := sink.WriteSanitizedFrame(context.Background(), frame); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, pii := range []string{"alice@example.test", "415-555-1212", "123 Main St", "123-45-6789", "4111 1111 1111 1111"} {
		if strings.Contains(string(data), pii) {
			t.Fatalf("storage output leaked raw synthetic PII %q: %s", pii, string(data))
		}
	}
}

func sanitizedFrame() trajectory.SanitizedFrame {
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	return trajectory.SanitizedFrame{
		ProtocolVersion: "golem.v1",
		TrajectoryID:    "test-trajectory",
		FrameID:         "frame-1",
		Sequence:        1,
		EventTimestamp:  now,
		Device:          trajectory.DeviceMetadata{DeviceID: "test-device", AndroidSDKVersion: "35"},
		ForegroundApp:   trajectory.ForegroundApp{PackageName: "com.android.settings"},
		UIRoot: trajectory.SanitizedNode{
			StableNodeID:        "root",
			TextHash:            "sha256:synthetic",
			TextRedactionStatus: trajectory.RedactionHashed,
			Enabled:             true,
		},
		Sanitizer: trajectory.SanitizerMetadata{
			SanitizerVersion: "sanitize-v0.1.0",
			Decision:         trajectory.DecisionAccept,
			ReasonCodes:      []string{"sanitized"},
		},
		SanitizedAt: now,
	}
}
