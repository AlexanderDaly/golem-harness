package testutil

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"golem-harness/server/internal/auth"
	"golem-harness/server/pkg/trajectory"
)

const (
	DeviceID     = "test-device"
	TrajectoryID = "test-trajectory"
	AllowedPkg   = "com.android.settings"
	SensitivePkg = "com.example.bank"
)

func KeyPair(seed byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return publicKey, privateKey
}

func RawFrame(pkg, frameID string, sequence uint64, rawText string) trajectory.RawFrame {
	return trajectory.RawFrame{
		ProtocolVersion: "golem.v1",
		TrajectoryID:    TrajectoryID,
		FrameID:         frameID,
		Sequence:        sequence,
		EventTimestamp:  time.Date(2026, 5, 31, 12, 0, 0, 0, time.UTC),
		Device: trajectory.DeviceMetadata{
			DeviceID:                     DeviceID,
			AndroidSDKVersion:            "35",
			BuildFingerprintHash:         "sha256:test-build",
			BuildMetadataRedactionStatus: "hashed",
		},
		ForegroundApp: trajectory.ForegroundApp{PackageName: pkg, ActivityName: "SyntheticActivity"},
		UIRoot: trajectory.RawNode{
			StableNodeID:          "root",
			Bounds:                trajectory.Bounds{Left: 0, Top: 0, Right: 1080, Bottom: 1920},
			ClassName:             "android.widget.FrameLayout",
			PackageName:           pkg,
			ResourceIDHash:        "sha256:root",
			RawText:               rawText,
			RawContentDescription: "Synthetic root",
			Clickable:             false,
			Enabled:               true,
			Children: []trajectory.RawNode{
				{
					StableNodeID:   "button-1",
					Bounds:         trajectory.Bounds{Left: 10, Top: 10, Right: 100, Bottom: 60},
					ClassName:      "android.widget.Button",
					PackageName:    pkg,
					ResourceIDHash: "sha256:button",
					RawText:        "Open settings",
					Clickable:      true,
					Enabled:        true,
				},
			},
		},
		Intent: trajectory.IntentMetadata{
			OperatorIntentID: "synthetic-intent",
			IntentType:       "open_settings",
			Tags:             []string{"synthetic"},
		},
		Action: trajectory.ActionMetadata{
			ActionID:           "synthetic-action",
			ActionType:         "tap",
			TargetStableNodeID: "button-1",
			Deterministic:      true,
		},
		UISettle: trajectory.UISettleMetadata{Observed: true, SettleTimeoutMS: 1000, ElapsedMS: 100, SettleStatus: "settled"},
	}
}

func SignedEnvelope(t *testing.T, privateKey ed25519.PrivateKey, frame trajectory.RawFrame, signedAt time.Time) auth.SignedEnvelope {
	t.Helper()
	payload, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := auth.SignEnvelope(privateKey, auth.SignedEnvelope{
		ProtocolVersion: frame.ProtocolVersion,
		DeviceID:        frame.Device.DeviceID,
		TrajectoryID:    frame.TrajectoryID,
		FrameID:         frame.FrameID,
		Sequence:        frame.Sequence,
		SignedAt:        signedAt.UTC(),
		Payload:         payload,
		SignatureAlg:    auth.SignatureAlgEd25519,
		PublicKeyID:     "test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
