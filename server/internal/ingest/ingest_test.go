package ingest_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	golemv1 "golem-harness/server/gen/golem/v1"
	"golem-harness/server/internal/auth"
	"golem-harness/server/internal/ingest"
	"golem-harness/server/internal/sanitize"
	"golem-harness/server/internal/testutil"
	"golem-harness/server/pkg/client"
	"golem-harness/server/pkg/signing"
	"golem-harness/server/pkg/trajectory"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestGRPCIngestStoresAcceptedSanitizedFrame(t *testing.T) {
	env := newIngestEnv(t, sanitize.NewPipeline([]string{testutil.AllowedPkg}, nil))
	defer env.cleanup()

	envelope := testutil.SignedEnvelope(t, env.privateKey, testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "alice@example.test"), env.now)
	resp, err := client.IngestFrame(context.Background(), env.conn, &envelope)
	if err != nil {
		t.Fatalf("ingest frame: %v", err)
	}
	if resp.Decision != trajectory.DecisionAccept {
		t.Fatalf("expected accept, got %s reasons=%v", resp.Decision, resp.ReasonCodes)
	}
	frames := env.sink.frames()
	if len(frames) != 1 {
		t.Fatalf("expected one stored frame, got %d", len(frames))
	}
	encoded := marshalForIngestTest(t, frames[0])
	for _, forbidden := range []string{"Open settings", "alice@example.test", "detached_signature"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("stored sanitized frame leaked forbidden value %q: %s", forbidden, encoded)
		}
		if strings.Contains(env.logs.String(), forbidden) {
			t.Fatalf("logs leaked forbidden value %q: %s", forbidden, env.logs.String())
		}
	}
}

func TestSensitivePackageDoesNotReachStorage(t *testing.T) {
	env := newIngestEnv(t, sanitize.NewPipeline([]string{testutil.AllowedPkg}, nil))
	defer env.cleanup()

	envelope := testutil.SignedEnvelope(t, env.privateKey, testutil.RawFrame(testutil.SensitivePkg, "frame-1", 1, "Settings"), env.now)
	resp, err := client.IngestFrame(context.Background(), env.conn, &envelope)
	if err != nil {
		t.Fatalf("ingest frame: %v", err)
	}
	if resp.Decision != trajectory.DecisionQuarantine {
		t.Fatalf("expected quarantine, got %s reasons=%v", resp.Decision, resp.ReasonCodes)
	}
	if len(env.sink.frames()) != 0 {
		t.Fatalf("sensitive package reached storage")
	}
}

func TestSanitizerFailurePreventsStorage(t *testing.T) {
	env := newIngestEnv(t, failingSanitizer{})
	defer env.cleanup()

	envelope := testutil.SignedEnvelope(t, env.privateKey, testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings"), env.now)
	resp, err := client.IngestFrame(context.Background(), env.conn, &envelope)
	if err != nil {
		t.Fatalf("ingest frame: %v", err)
	}
	if resp.Decision != trajectory.DecisionDrop {
		t.Fatalf("expected drop, got %s reasons=%v", resp.Decision, resp.ReasonCodes)
	}
	if len(env.sink.frames()) != 0 {
		t.Fatalf("sanitizer failure reached storage")
	}
}

func TestMissingSignedAtIsInvalidArgumentNotUnauthenticated(t *testing.T) {
	env := newIngestEnv(t, sanitize.NewPipeline([]string{testutil.AllowedPkg}, nil))
	defer env.cleanup()

	envelope := testutil.SignedEnvelope(t, env.privateKey, testutil.RawFrame(testutil.AllowedPkg, "frame-1", 1, "Settings"), env.now)
	pbEnv := signing.EnvelopeToProto(envelope)
	pbEnv.SignedAt = nil

	api := golemv1.NewTelemetryIngestServiceClient(env.conn)
	_, err := api.IngestFrame(context.Background(), &golemv1.IngestFrameRequest{Envelope: pbEnv})
	if err == nil {
		t.Fatal("expected error for nil signed_at")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status, got %v", err)
	}
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument (missing field), got %v (%v)", st.Code(), err)
	}
}

type ingestEnv struct {
	privateKey ed25519.PrivateKey
	conn       *grpc.ClientConn
	server     *grpc.Server
	listener   *bufconn.Listener
	sink       *captureSink
	logs       *bytes.Buffer
	now        time.Time
}

func newIngestEnv(t *testing.T, sanitizer ingest.Sanitizer) *ingestEnv {
	t.Helper()
	publicKey, privateKey := testutil.KeyPair(1)
	registry, err := auth.NewStaticDeviceRegistry([]auth.Device{{DeviceID: testutil.DeviceID, PublicKey: publicKey, PublicKeyID: "test-key"}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC)
	sink := &captureSink{}
	logs := new(bytes.Buffer)
	service := &ingest.Service{
		Verifier: &auth.Verifier{
			Registry:        registry,
			ReplayGuard:     auth.NewMemoryReplayGuard(),
			MaxPayloadBytes: 64 * 1024,
			TTL:             5 * time.Minute,
			Now:             func() time.Time { return now },
		},
		Sanitizer: sanitizer,
		Storage:   sink,
		Logger:    slog.New(slog.NewJSONHandler(logs, nil)),
	}
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer(ingest.ServerOptions(64*1024 + 4096)...)
	ingest.Register(server, service)
	go func() {
		_ = server.Serve(listener)
	}()

	// grpc.NewClient defaults to the DNS resolver. A bare target like "bufnet"
	// is treated as a hostname and fails. DialContext did not require a scheme;
	// passthrough:// skips resolution so WithContextDialer reaches bufconn.
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &ingestEnv{privateKey: privateKey, conn: conn, server: server, listener: listener, sink: sink, logs: logs, now: now}
}

func (e *ingestEnv) cleanup() {
	_ = e.conn.Close()
	e.server.Stop()
	_ = e.listener.Close()
}

type captureSink struct {
	mu     sync.Mutex
	stored []trajectory.SanitizedFrame
}

func (s *captureSink) WriteSanitizedFrame(ctx context.Context, frame trajectory.SanitizedFrame) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if frame.Sanitizer.Decision != trajectory.DecisionAccept || frame.Sanitizer.SanitizerVersion == "" {
		return errors.New("unsafe frame")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stored = append(s.stored, frame)
	return nil
}

func (s *captureSink) frames() []trajectory.SanitizedFrame {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]trajectory.SanitizedFrame, len(s.stored))
	copy(out, s.stored)
	return out
}

type failingSanitizer struct{}

func (failingSanitizer) Process(context.Context, trajectory.RawFrame) (sanitize.Result, error) {
	return sanitize.Result{
		Decision:         trajectory.DecisionDrop,
		ReasonCodes:      []string{"forced_failure"},
		SanitizerVersion: "test-sanitizer",
	}, errors.New("forced sanitizer failure")
}
