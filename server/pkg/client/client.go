package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	golemv1 "golem-harness/server/gen/golem/v1"
	"golem-harness/server/pkg/signing"
	"golem-harness/server/pkg/trajectory"

	"google.golang.org/grpc"
)

// Public types for external mock clients. These live under pkg/, not internal/.

type SignedEnvelope = signing.SignedEnvelope
type RawFrame = trajectory.RawFrame
type DeviceMetadata = trajectory.DeviceMetadata
type ForegroundApp = trajectory.ForegroundApp
type RawNode = trajectory.RawNode
type Bounds = trajectory.Bounds
type IntentMetadata = trajectory.IntentMetadata
type ActionMetadata = trajectory.ActionMetadata
type UISettleMetadata = trajectory.UISettleMetadata
type Decision = trajectory.Decision

// Response is the client-facing ingest result.
type Response struct {
	RequestID        string
	Decision         trajectory.Decision
	ReasonCodes      []string
	SanitizerVersion string
}

// BuildSignedEnvelope signs a JSON-serialized RawFrame. publicKeyID and
// clientCertFingerprintSHA256 are included in the canonical signed bytes;
// pass them when the device registry requires those bindings.
func BuildSignedEnvelope(privateKey ed25519.PrivateKey, signedAt time.Time, frame trajectory.RawFrame) (SignedEnvelope, error) {
	return BuildSignedEnvelopeWithKey(privateKey, signedAt, frame, "", "")
}

func BuildSignedEnvelopeWithKey(privateKey ed25519.PrivateKey, signedAt time.Time, frame trajectory.RawFrame, publicKeyID, clientCertFingerprintSHA256 string) (SignedEnvelope, error) {
	payload, err := json.Marshal(frame)
	if err != nil {
		return SignedEnvelope{}, err
	}
	envelope := signing.SignedEnvelope{
		ProtocolVersion:             frame.ProtocolVersion,
		DeviceID:                    frame.Device.DeviceID,
		TrajectoryID:                frame.TrajectoryID,
		FrameID:                     frame.FrameID,
		Sequence:                    frame.Sequence,
		SignedAt:                    signedAt.UTC(),
		Payload:                     payload,
		SignatureAlg:                signing.SignatureAlgEd25519,
		PublicKeyID:                 publicKeyID,
		ClientCertFingerprintSHA256: clientCertFingerprintSHA256,
	}
	return signing.SignEnvelope(privateKey, envelope)
}

func IngestFrame(ctx context.Context, conn grpc.ClientConnInterface, envelope *SignedEnvelope) (*Response, error) {
	if envelope == nil {
		return nil, errors.New("missing envelope")
	}
	api := golemv1.NewTelemetryIngestServiceClient(conn)
	pbResp, err := api.IngestFrame(ctx, &golemv1.IngestFrameRequest{
		Envelope: signing.EnvelopeToProto(*envelope),
	})
	if err != nil {
		return nil, err
	}
	return ResponseFromProto(pbResp), nil
}

// ResponseFromProto maps the wire response to the client Response type.
// Decision mapping is shared via signing.DecisionFromProto.
func ResponseFromProto(pb *golemv1.IngestFrameResponse) *Response {
	if pb == nil {
		return &Response{}
	}
	return &Response{
		RequestID:        pb.GetRequestId(),
		Decision:         signing.DecisionFromProto(pb.GetDecision()),
		ReasonCodes:      pb.GetReasonCodes(),
		SanitizerVersion: pb.GetSanitizerVersion(),
	}
}
