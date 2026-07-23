package auth

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// SQLiteReplayGuard persists seen frame IDs and per-device max sequence so
// replay protection survives process restart.
type SQLiteReplayGuard struct {
	db *sql.DB
	mu sync.Mutex
}

func NewSQLiteReplayGuard(path string) (*SQLiteReplayGuard, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: replay path is required", ErrMalformed)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create replay directory: %w", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open replay db: %w", err)
	}
	// Single-writer process; serialize at app level too.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA journal_mode=WAL;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("replay db wal: %w", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000;`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("replay db busy_timeout: %w", err)
	}
	// seen_frames is intentionally unbounded: one row per accepted (device_id, frame_id).
	// Strictly increasing sequence already rejects true replays of prior sequences; this
	// table only catches reused frame_ids at a new sequence. Pruning would reopen that
	// hole. Phase 1 single-process harness accepts growth; do not prune without a design.
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS device_state (
  device_id TEXT PRIMARY KEY NOT NULL,
  max_sequence INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS seen_frames (
  device_id TEXT NOT NULL,
  frame_id TEXT NOT NULL,
  PRIMARY KEY (device_id, frame_id)
);
`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("replay db schema: %w", err)
	}
	return &SQLiteReplayGuard{db: db}, nil
}

func (g *SQLiteReplayGuard) Close() error {
	if g == nil || g.db == nil {
		return nil
	}
	return g.db.Close()
}

func (g *SQLiteReplayGuard) CheckAndRecord(deviceID, frameID string, sequence uint64) error {
	if deviceID == "" || frameID == "" {
		return fmt.Errorf("%w: device id and frame id are required", ErrMalformed)
	}
	if g == nil || g.db == nil {
		return fmt.Errorf("%w: replay guard is not open", ErrMalformed)
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	tx, err := g.db.Begin()
	if err != nil {
		return fmt.Errorf("replay begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var existing string
	err = tx.QueryRow(
		`SELECT frame_id FROM seen_frames WHERE device_id = ? AND frame_id = ?`,
		deviceID, frameID,
	).Scan(&existing)
	if err == nil {
		return ErrReplay
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("replay lookup frame: %w", err)
	}

	var maxSequence uint64
	err = tx.QueryRow(
		`SELECT max_sequence FROM device_state WHERE device_id = ?`,
		deviceID,
	).Scan(&maxSequence)
	if err != nil && err != sql.ErrNoRows {
		return fmt.Errorf("replay lookup sequence: %w", err)
	}
	// ErrNoRows leaves maxSequence at 0 — same as MemoryReplayGuard for a new device.
	if sequence <= maxSequence {
		return ErrReplay
	}

	if _, err := tx.Exec(
		`INSERT INTO seen_frames (device_id, frame_id) VALUES (?, ?)`,
		deviceID, frameID,
	); err != nil {
		return fmt.Errorf("replay insert frame: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO device_state (device_id, max_sequence) VALUES (?, ?)
		 ON CONFLICT(device_id) DO UPDATE SET max_sequence = excluded.max_sequence`,
		deviceID, sequence,
	); err != nil {
		return fmt.Errorf("replay upsert sequence: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("replay commit: %w", err)
	}
	return nil
}
