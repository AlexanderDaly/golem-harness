package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golem-harness/server/pkg/trajectory"
)

var ErrUnsafeFrame = errors.New("unsafe sanitized frame")

type Sink interface {
	WriteSanitizedFrame(ctx context.Context, frame trajectory.SanitizedFrame) error
}

// JSONLOptions controls rotation and durability for JSONLSink.
type JSONLOptions struct {
	// MaxBytes rotates the active file when its size reaches this threshold.
	// Zero disables size-based rotation.
	MaxBytes int64
	// RotateDaily rotates at UTC day boundaries.
	RotateDaily bool
	// Sync fsyncs after each successful write. Default true when using
	// DefaultJSONLOptions — keeps storage durable relative to replay recording.
	Sync bool
}

// DefaultJSONLOptions enables fsync; rotation is off until configured.
func DefaultJSONLOptions() JSONLOptions {
	return JSONLOptions{Sync: true}
}

type JSONLSink struct {
	path string
	opts JSONLOptions
	mu   sync.Mutex
	file *os.File
	size int64
	day  string // UTC yyyymmdd of the open file
	now  func() time.Time
}

func NewJSONLSink(path string) (*JSONLSink, error) {
	return NewJSONLSinkWithOptions(path, DefaultJSONLOptions())
}

func NewJSONLSinkWithOptions(path string, opts JSONLOptions) (*JSONLSink, error) {
	if path == "" {
		return nil, errors.New("storage path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create storage directory: %w", err)
	}
	if opts.MaxBytes < 0 {
		return nil, errors.New("storage max bytes must be non-negative")
	}
	return &JSONLSink{
		path: path,
		opts: opts,
		now:  time.Now,
	}, nil
}

func (s *JSONLSink) WriteSanitizedFrame(ctx context.Context, frame trajectory.SanitizedFrame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSanitizedFrame(frame); err != nil {
		return err
	}

	line, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("marshal sanitized frame: %w", err)
	}
	payload := append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureWriter(int64(len(payload))); err != nil {
		return err
	}
	n, err := s.file.Write(payload)
	if err != nil {
		return fmt.Errorf("write sanitized frame: %w", err)
	}
	s.size += int64(n)
	if s.opts.Sync {
		if err := s.file.Sync(); err != nil {
			return fmt.Errorf("sync sanitized frame: %w", err)
		}
	}
	return nil
}

// Close closes the active file. Safe to call multiple times.
func (s *JSONLSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeFile()
}

func (s *JSONLSink) Path() string {
	return s.path
}

// SetNowForTest overrides the clock used for day-based rotation (tests only).
func (s *JSONLSink) SetNowForTest(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		s.now = time.Now
		return
	}
	s.now = now
}

func (s *JSONLSink) ensureWriter(nextWriteBytes int64) error {
	now := s.now().UTC()
	day := now.Format("20060102")

	if s.file != nil {
		dayBoundary := s.opts.RotateDaily && s.day != "" && day != s.day
		sizeLimit := s.opts.MaxBytes > 0 && s.size+nextWriteBytes > s.opts.MaxBytes
		if dayBoundary || sizeLimit {
			// Day-boundary archives use the closed file's data day (s.day), not now,
			// so filenames match the day of the frames (Parquet-friendly).
			if err := s.rotateLocked(archiveStamp(s.day, now, dayBoundary)); err != nil {
				return err
			}
		}
	}

	if s.file != nil {
		return nil
	}

	info, err := os.Stat(s.path)
	if err == nil {
		// Existing file: open for append; rotate first if already over limits.
		if s.opts.RotateDaily {
			// If file mtime is a prior UTC day, rotate before append.
			fileDay := info.ModTime().UTC().Format("20060102")
			if fileDay != day && info.Size() > 0 {
				if err := s.rotatePathLocked(archiveStamp(fileDay, now, true)); err != nil {
					return err
				}
				info = nil
			}
		}
		if info != nil && s.opts.MaxBytes > 0 && info.Size()+nextWriteBytes > s.opts.MaxBytes && info.Size() > 0 {
			if err := s.rotatePathLocked(archiveStamp("", now, false)); err != nil {
				return err
			}
			info = nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat storage sink: %w", err)
	}

	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open storage sink: %w", err)
	}
	size := int64(0)
	if st, err := file.Stat(); err == nil {
		size = st.Size()
	}
	s.file = file
	s.size = size
	s.day = day
	return nil
}

func (s *JSONLSink) rotateLocked(stamp string) error {
	if err := s.closeFile(); err != nil {
		return err
	}
	return s.rotatePathLocked(stamp)
}

func (s *JSONLSink) rotatePathLocked(stamp string) error {
	if _, err := os.Stat(s.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat storage sink for rotate: %w", err)
	}
	dest := rotatedPath(s.path, stamp)
	// Avoid clobbering an existing archive name.
	for i := 0; i < 100; i++ {
		candidate := dest
		if i > 0 {
			candidate = fmt.Sprintf("%s.%d", dest, i)
		}
		if _, err := os.Stat(candidate); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(s.path, candidate); err != nil {
				return fmt.Errorf("rotate storage sink: %w", err)
			}
			return nil
		} else if err != nil {
			return fmt.Errorf("stat rotated sink: %w", err)
		}
	}
	return fmt.Errorf("rotate storage sink: could not find free archive name")
}

// archiveStamp names a rotated file. Day-boundary rotations use the data day
// (yyyymmdd of the closed file). Size rotations use a full UTC timestamp.
func archiveStamp(dataDay string, now time.Time, dayBoundary bool) string {
	if dayBoundary && dataDay != "" {
		return dataDay
	}
	return now.UTC().Format("20060102T150405Z")
}

func rotatedPath(path, stamp string) string {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if ext == "" {
		ext = ".jsonl"
	}
	return filepath.Join(dir, fmt.Sprintf("%s-%s%s", name, stamp, ext))
}

func (s *JSONLSink) closeFile() error {
	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	s.size = 0
	s.day = ""
	return err
}

func validateSanitizedFrame(frame trajectory.SanitizedFrame) error {
	if frame.Sanitizer.SanitizerVersion == "" || frame.Sanitizer.Decision != trajectory.DecisionAccept {
		return ErrUnsafeFrame
	}
	if frame.SanitizedAt.IsZero() {
		return ErrUnsafeFrame
	}
	return nil
}
