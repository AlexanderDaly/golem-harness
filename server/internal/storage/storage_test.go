package storage_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	t.Cleanup(func() { _ = sink.Close() })

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
	t.Cleanup(func() { _ = sink.Close() })
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

func TestJSONLSinkRotatesBySize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "frames.jsonl")
	sink, err := storage.NewJSONLSinkWithOptions(path, storage.JSONLOptions{
		MaxBytes: 200,
		Sync:     true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	for i := 0; i < 5; i++ {
		frame := sanitizedFrame()
		frame.FrameID = fmt.Sprintf("frame-%d", i)
		frame.Sequence = uint64(i + 1)
		if err := sink.WriteSanitizedFrame(context.Background(), frame); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	_ = sink.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var archives int
	for _, e := range entries {
		name := e.Name()
		if name != "frames.jsonl" && strings.HasPrefix(name, "frames-") {
			archives++
		}
	}
	if archives < 1 {
		t.Fatalf("expected at least one rotated archive, dir=%v", names(entries))
	}
	// Active path should still exist or be recreated empty-capable.
	if _, err := os.Stat(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestJSONLSinkRotatesByDay(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "frames.jsonl")
	sink, err := storage.NewJSONLSinkWithOptions(path, storage.JSONLOptions{
		RotateDaily: true,
		Sync:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })

	day1 := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 7, 23, 1, 0, 0, 0, time.UTC)
	sink.SetNowForTest(func() time.Time { return day1 })
	if err := sink.WriteSanitizedFrame(context.Background(), sanitizedFrame()); err != nil {
		t.Fatal(err)
	}
	sink.SetNowForTest(func() time.Time { return day2 })
	frame2 := sanitizedFrame()
	frame2.FrameID = "frame-2"
	frame2.Sequence = 2
	if err := sink.WriteSanitizedFrame(context.Background(), frame2); err != nil {
		t.Fatal(err)
	}
	_ = sink.Close()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Day-boundary archive must be stamped with the data day (20260722), not rotation day.
	wantArchive := "frames-20260722.jsonl"
	found := false
	for _, e := range entries {
		if e.Name() == wantArchive {
			found = true
		}
		if strings.Contains(e.Name(), "20260723") && e.Name() != "frames.jsonl" {
			t.Fatalf("day archive must not use rotation-day stamp: %v", names(entries))
		}
	}
	if !found {
		t.Fatalf("expected archive %q, dir=%v", wantArchive, names(entries))
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

func names(entries []os.DirEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}
