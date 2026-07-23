package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golem-harness/server/pkg/trajectory"
)

var ErrUnsafeFrame = errors.New("unsafe sanitized frame")

type Sink interface {
	WriteSanitizedFrame(ctx context.Context, frame trajectory.SanitizedFrame) error
}

type JSONLSink struct {
	path string
	mu   sync.Mutex
}

func NewJSONLSink(path string) (*JSONLSink, error) {
	if path == "" {
		return nil, errors.New("storage path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create storage directory: %w", err)
	}
	return &JSONLSink{path: path}, nil
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

	s.mu.Lock()
	defer s.mu.Unlock()

	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open storage sink: %w", err)
	}
	defer file.Close()
	if _, err := file.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("write sanitized frame: %w", err)
	}
	return nil
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

func (s *JSONLSink) Path() string {
	return s.path
}
