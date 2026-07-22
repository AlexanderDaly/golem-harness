package ingest

import (
	"fmt"

	golemv1 "golem-harness/server/gen/golem/v1"
	"golem-harness/server/internal/auth"
	"golem-harness/server/internal/trajectory"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func envelopeFromProto(pb *golemv1.SignatureEnvelope) (auth.SignedEnvelope, error) {
	if pb == nil {
		return auth.SignedEnvelope{}, fmt.Errorf("%w: missing envelope", auth.ErrMalformed)
	}
	// Check nil before AsTime(): nil *timestamppb.Timestamp.AsTime() is Unix epoch, not zero time.
	if pb.SignedAt == nil {
		return auth.SignedEnvelope{}, fmt.Errorf("%w: signed_at is required", auth.ErrMalformed)
	}
	return auth.SignedEnvelope{
		ProtocolVersion:             pb.GetProtocolVersion(),
		DeviceID:                    pb.GetDeviceId(),
		TrajectoryID:                pb.GetTrajectoryId(),
		FrameID:                     pb.GetFrameId(),
		Sequence:                    pb.GetSequence(),
		SignedAt:                    pb.SignedAt.AsTime().UTC(),
		Payload:                     pb.GetCanonicalPayload(),
		DetachedSignature:           pb.GetDetachedSignature(),
		PayloadSHA256Hex:            pb.GetPayloadSha256Hex(),
		SignatureAlg:                pb.GetSignatureAlg(),
		PublicKeyID:                 pb.GetPublicKeyId(),
		ClientCertFingerprintSHA256: pb.GetClientCertFingerprintSha256(),
	}, nil
}

// EnvelopeToProto maps a domain signed envelope to the wire message.
func EnvelopeToProto(envelope auth.SignedEnvelope) *golemv1.SignatureEnvelope {
	return envelopeToProto(envelope)
}

func envelopeToProto(envelope auth.SignedEnvelope) *golemv1.SignatureEnvelope {
	var signedAt *timestamppb.Timestamp
	if !envelope.SignedAt.IsZero() {
		signedAt = timestamppb.New(envelope.SignedAt.UTC())
	}
	return &golemv1.SignatureEnvelope{
		ProtocolVersion:             envelope.ProtocolVersion,
		DeviceId:                    envelope.DeviceID,
		TrajectoryId:                envelope.TrajectoryID,
		FrameId:                     envelope.FrameID,
		Sequence:                    envelope.Sequence,
		SignedAt:                    signedAt,
		CanonicalPayload:            envelope.Payload,
		DetachedSignature:           envelope.DetachedSignature,
		PayloadSha256Hex:            envelope.PayloadSHA256Hex,
		SignatureAlg:                envelope.SignatureAlg,
		PublicKeyId:                 envelope.PublicKeyID,
		ClientCertFingerprintSha256: envelope.ClientCertFingerprintSHA256,
	}
}

func decisionToProto(d trajectory.Decision) golemv1.Decision {
	switch d {
	case trajectory.DecisionAccept:
		return golemv1.Decision_DECISION_ACCEPT
	case trajectory.DecisionDrop:
		return golemv1.Decision_DECISION_DROP
	case trajectory.DecisionQuarantine:
		return golemv1.Decision_DECISION_QUARANTINE
	default:
		return golemv1.Decision_DECISION_UNSPECIFIED
	}
}

func decisionFromProto(d golemv1.Decision) trajectory.Decision {
	switch d {
	case golemv1.Decision_DECISION_ACCEPT:
		return trajectory.DecisionAccept
	case golemv1.Decision_DECISION_DROP:
		return trajectory.DecisionDrop
	case golemv1.Decision_DECISION_QUARANTINE:
		return trajectory.DecisionQuarantine
	default:
		return ""
	}
}

func responseToProto(resp *Response) *golemv1.IngestFrameResponse {
	if resp == nil {
		return &golemv1.IngestFrameResponse{}
	}
	return &golemv1.IngestFrameResponse{
		RequestId:        resp.RequestID,
		Decision:         decisionToProto(resp.Decision),
		ReasonCodes:      resp.ReasonCodes,
		SanitizerVersion: resp.SanitizerVersion,
	}
}

// ResponseFromProto maps a wire response to the domain response type.
func ResponseFromProto(pb *golemv1.IngestFrameResponse) *Response {
	return responseFromProto(pb)
}

func responseFromProto(pb *golemv1.IngestFrameResponse) *Response {
	if pb == nil {
		return &Response{}
	}
	return &Response{
		RequestID:        pb.GetRequestId(),
		Decision:         decisionFromProto(pb.GetDecision()),
		ReasonCodes:      pb.GetReasonCodes(),
		SanitizerVersion: pb.GetSanitizerVersion(),
	}
}
