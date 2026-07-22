package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"

	"golem-harness/server/internal/auth"
	"golem-harness/server/internal/sanitize"
	"golem-harness/server/internal/storage"
	"golem-harness/server/internal/trajectory"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type Sanitizer interface {
	Process(ctx context.Context, frame trajectory.RawFrame) (sanitize.Result, error)
}

type Response struct {
	RequestID        string              `json:"request_id"`
	Decision         trajectory.Decision `json:"decision"`
	ReasonCodes      []string            `json:"reason_codes,omitempty"`
	SanitizerVersion string              `json:"sanitizer_version,omitempty"`
}

type Service struct {
	Verifier  *auth.Verifier
	Sanitizer Sanitizer
	Storage   storage.Sink
	Logger    *slog.Logger
}

func (s *Service) IngestFrame(ctx context.Context, envelope *auth.SignedEnvelope) (*Response, error) {
	if envelope == nil {
		return nil, status.Error(codes.InvalidArgument, "missing envelope")
	}
	if s.Verifier == nil || s.Sanitizer == nil || s.Storage == nil {
		return nil, status.Error(codes.FailedPrecondition, "ingest service is not configured")
	}
	if err := s.Verifier.Verify(ctx, *envelope, peerCertificateFingerprint(ctx)); err != nil {
		s.safeLog("ingest_rejected", envelope, "auth_failed", []string{safeReason(err)})
		return nil, mapAuthError(err)
	}

	var frame trajectory.RawFrame
	if err := json.Unmarshal(envelope.Payload, &frame); err != nil {
		s.safeLog("ingest_rejected", envelope, "malformed_payload", []string{"payload_decode_failed"})
		return nil, status.Error(codes.InvalidArgument, "malformed payload")
	}
	if err := bindEnvelopeToFrame(*envelope, &frame); err != nil {
		s.safeLog("ingest_rejected", envelope, "payload_binding_failed", []string{safeReason(err)})
		return nil, status.Error(codes.InvalidArgument, "payload metadata does not match envelope")
	}
	frame.Signature = trajectory.SignatureMetadata{
		SignatureAlg:       envelope.SignatureAlg,
		KeyID:              envelope.PublicKeyID,
		PayloadSHA256Hex:   envelope.PayloadSHA256Hex,
		VerificationStatus: "verified",
	}

	result, err := s.Sanitizer.Process(ctx, frame)
	if err != nil {
		s.safeLog("ingest_rejected", envelope, "sanitizer_failed", []string{"sanitizer_error"})
		return &Response{
			RequestID:        safeRequestID(*envelope),
			Decision:         trajectory.DecisionDrop,
			ReasonCodes:      []string{"sanitizer_error"},
			SanitizerVersion: result.SanitizerVersion,
		}, nil
	}
	if result.Decision != trajectory.DecisionAccept {
		s.safeLog("ingest_rejected", envelope, string(result.Decision), result.ReasonCodes)
		return &Response{
			RequestID:        safeRequestID(*envelope),
			Decision:         result.Decision,
			ReasonCodes:      result.ReasonCodes,
			SanitizerVersion: result.SanitizerVersion,
		}, nil
	}
	if err := s.Storage.WriteSanitizedFrame(ctx, result.Frame); err != nil {
		s.safeLog("ingest_rejected", envelope, "storage_failed", []string{"storage_failed"})
		return nil, status.Error(codes.Internal, "storage failed")
	}

	s.safeLog("ingest_accepted", envelope, "accept", result.ReasonCodes)
	return &Response{
		RequestID:        safeRequestID(*envelope),
		Decision:         trajectory.DecisionAccept,
		ReasonCodes:      result.ReasonCodes,
		SanitizerVersion: result.SanitizerVersion,
	}, nil
}

func bindEnvelopeToFrame(envelope auth.SignedEnvelope, frame *trajectory.RawFrame) error {
	// Fill empty string IDs from the envelope; never treat sequence 0 as unset.
	if frame.ProtocolVersion == "" {
		frame.ProtocolVersion = envelope.ProtocolVersion
	}
	if frame.TrajectoryID == "" {
		frame.TrajectoryID = envelope.TrajectoryID
	}
	if frame.FrameID == "" {
		frame.FrameID = envelope.FrameID
	}
	if frame.Device.DeviceID == "" {
		frame.Device.DeviceID = envelope.DeviceID
	}
	if frame.ProtocolVersion != envelope.ProtocolVersion ||
		frame.TrajectoryID != envelope.TrajectoryID ||
		frame.FrameID != envelope.FrameID ||
		frame.Sequence != envelope.Sequence ||
		frame.Device.DeviceID != envelope.DeviceID {
		return errors.New("envelope and payload identifiers differ")
	}
	return nil
}

func mapAuthError(err error) error {
	switch {
	case errors.Is(err, auth.ErrMissingSignature), errors.Is(err, auth.ErrInvalidSignature), errors.Is(err, auth.ErrUnauthorized), errors.Is(err, auth.ErrExpiredPayload), errors.Is(err, auth.ErrFuturePayload):
		return status.Error(codes.Unauthenticated, safeReason(err))
	case errors.Is(err, auth.ErrReplay):
		return status.Error(codes.AlreadyExists, safeReason(err))
	case errors.Is(err, auth.ErrOversizedPayload):
		return status.Error(codes.ResourceExhausted, safeReason(err))
	default:
		return status.Error(codes.InvalidArgument, safeReason(err))
	}
}

func peerCertificateFingerprint(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(info.State.PeerCertificates) == 0 {
		return ""
	}
	sum := sha256.Sum256(info.State.PeerCertificates[0].Raw)
	return hex.EncodeToString(sum[:])
}

func (s *Service) safeLog(event string, envelope *auth.SignedEnvelope, decision string, reasonCodes []string) {
	logger := s.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if envelope == nil {
		logger.Info(event, "decision", decision, "reason_codes", reasonCodes)
		return
	}
	logger.Info(event,
		"request_id", safeRequestID(*envelope),
		"device_hash", auth.SafeHash(envelope.DeviceID),
		"trajectory_hash", auth.SafeHash(envelope.TrajectoryID),
		"sequence", envelope.Sequence,
		"decision", decision,
		"reason_codes", reasonCodes,
	)
}

func safeRequestID(envelope auth.SignedEnvelope) string {
	return auth.SafeHash(envelope.DeviceID + ":" + envelope.TrajectoryID + ":" + envelope.FrameID)[:24]
}

func safeReason(err error) string {
	switch {
	case errors.Is(err, auth.ErrMissingSignature):
		return "missing_signature"
	case errors.Is(err, auth.ErrInvalidSignature):
		return "invalid_signature"
	case errors.Is(err, auth.ErrExpiredPayload):
		return "expired_payload"
	case errors.Is(err, auth.ErrFuturePayload):
		return "future_payload"
	case errors.Is(err, auth.ErrOversizedPayload):
		return "oversized_payload"
	case errors.Is(err, auth.ErrUnauthorized):
		return "unauthorized_device"
	case errors.Is(err, auth.ErrReplay):
		return "replayed_frame"
	case errors.Is(err, auth.ErrMalformed):
		return "malformed_envelope"
	default:
		return "request_rejected"
	}
}
