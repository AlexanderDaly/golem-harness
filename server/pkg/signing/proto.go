package signing

import (
	"fmt"

	golemv1 "golem-harness/server/gen/golem/v1"
	"golem-harness/server/pkg/trajectory"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// EnvelopeFromProto maps the wire SignatureEnvelope to the domain type.
// pb.SignedAt must be checked for nil before AsTime() — nil becomes Unix epoch.
func EnvelopeFromProto(pb *golemv1.SignatureEnvelope) (SignedEnvelope, error) {
	if pb == nil {
		return SignedEnvelope{}, fmt.Errorf("%w: missing envelope", ErrMalformed)
	}
	if pb.SignedAt == nil {
		return SignedEnvelope{}, fmt.Errorf("%w: signed_at is required", ErrMalformed)
	}
	return SignedEnvelope{
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

// DecisionToProto maps a domain decision to the wire enum.
func DecisionToProto(d trajectory.Decision) golemv1.Decision {
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

// DecisionFromProto maps a wire decision enum to the domain type.
func DecisionFromProto(d golemv1.Decision) trajectory.Decision {
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

// EnvelopeToProto maps a domain signed envelope to the wire message.
func EnvelopeToProto(envelope SignedEnvelope) *golemv1.SignatureEnvelope {
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
