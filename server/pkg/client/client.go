package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"golem-harness/server/internal/auth"
	"golem-harness/server/internal/ingest"
	"golem-harness/server/internal/trajectory"

	"google.golang.org/grpc"
)

type SignedEnvelope = auth.SignedEnvelope
type Response = ingest.Response
type JSONCodec = ingest.JSONCodec
type RawFrame = trajectory.RawFrame
type DeviceMetadata = trajectory.DeviceMetadata
type ForegroundApp = trajectory.ForegroundApp
type RawNode = trajectory.RawNode
type Bounds = trajectory.Bounds
type IntentMetadata = trajectory.IntentMetadata
type ActionMetadata = trajectory.ActionMetadata
type UISettleMetadata = trajectory.UISettleMetadata

func BuildSignedEnvelope(privateKey ed25519.PrivateKey, signedAt time.Time, frame trajectory.RawFrame) (SignedEnvelope, error) {
	payload, err := json.Marshal(frame)
	if err != nil {
		return SignedEnvelope{}, err
	}
	envelope := auth.SignedEnvelope{
		ProtocolVersion: frame.ProtocolVersion,
		DeviceID:        frame.Device.DeviceID,
		TrajectoryID:    frame.TrajectoryID,
		FrameID:         frame.FrameID,
		Sequence:        frame.Sequence,
		SignedAt:        signedAt.UTC(),
		Payload:         payload,
		SignatureAlg:    auth.SignatureAlgEd25519,
	}
	return auth.SignEnvelope(privateKey, envelope)
}

func IngestFrame(ctx context.Context, conn grpc.ClientConnInterface, envelope *SignedEnvelope) (*Response, error) {
	return ingest.ClientIngestFrame(ctx, conn, envelope, grpc.ForceCodec(ingest.JSONCodec{}))
}
