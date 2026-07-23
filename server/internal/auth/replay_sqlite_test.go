package auth_test

import (
	"errors"
	"path/filepath"
	"testing"

	"golem-harness/server/internal/auth"
)

func TestSQLiteReplayGuardRejectsReplayWithinProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.db")
	guard, err := auth.NewSQLiteReplayGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Close() })

	if err := guard.CheckAndRecord("dev-1", "frame-1", 1); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if err := guard.CheckAndRecord("dev-1", "frame-1", 1); !errors.Is(err, auth.ErrReplay) {
		t.Fatalf("expected frame replay, got %v", err)
	}
	if err := guard.CheckAndRecord("dev-1", "frame-2", 1); !errors.Is(err, auth.ErrReplay) {
		t.Fatalf("expected sequence replay, got %v", err)
	}
	if err := guard.CheckAndRecord("dev-1", "frame-2", 2); err != nil {
		t.Fatalf("next sequence should accept: %v", err)
	}
}

func TestSQLiteReplayGuardSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.db")

	guard1, err := auth.NewSQLiteReplayGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := guard1.CheckAndRecord("dev-1", "frame-1", 5); err != nil {
		t.Fatalf("first record: %v", err)
	}
	if err := guard1.Close(); err != nil {
		t.Fatal(err)
	}

	guard2, err := auth.NewSQLiteReplayGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard2.Close() })

	if err := guard2.CheckAndRecord("dev-1", "frame-1", 5); !errors.Is(err, auth.ErrReplay) {
		t.Fatalf("expected replayed frame after reopen, got %v", err)
	}
	if err := guard2.CheckAndRecord("dev-1", "frame-2", 4); !errors.Is(err, auth.ErrReplay) {
		t.Fatalf("expected sequence regression after reopen, got %v", err)
	}
	if err := guard2.CheckAndRecord("dev-1", "frame-2", 6); err != nil {
		t.Fatalf("higher sequence after reopen should accept: %v", err)
	}
}

func TestSQLiteReplayGuardIsolatesDevices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.db")
	guard, err := auth.NewSQLiteReplayGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Close() })

	if err := guard.CheckAndRecord("dev-a", "frame-1", 10); err != nil {
		t.Fatal(err)
	}
	// Same frame id and lower sequence is fine on another device.
	if err := guard.CheckAndRecord("dev-b", "frame-1", 1); err != nil {
		t.Fatalf("other device should accept: %v", err)
	}
}

func TestSQLiteReplayGuardRejectsEmptyIDs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.db")
	guard, err := auth.NewSQLiteReplayGuard(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = guard.Close() })

	if err := guard.CheckAndRecord("", "frame-1", 1); !errors.Is(err, auth.ErrMalformed) {
		t.Fatalf("expected malformed, got %v", err)
	}
	if err := guard.CheckAndRecord("dev", "", 1); !errors.Is(err, auth.ErrMalformed) {
		t.Fatalf("expected malformed, got %v", err)
	}
}
