package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golem-harness/server/pkg/client"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "mock-client: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	addr := flag.String("addr", "127.0.0.1:7443", "golem-proxy gRPC address")
	keyDir := flag.String("key-dir", ".devkeys", "directory for test-only Ed25519 keys")
	flag.Parse()

	publicKey, privateKey, err := loadOrCreateKeypair(*keyDir)
	if err != nil {
		return err
	}
	fmt.Printf("test device public key base64: %s\n", base64.StdEncoding.EncodeToString(publicKey))

	conn, err := grpc.NewClient(*addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// public_key_id must match device registry when configured (signed field).
	const publicKeyID = "mock-key"

	// Fresh trajectory + frame IDs each run. Sequences must strictly increase per
	// device across process restarts (SQLite replay), so base them on time.
	trajectoryID, err := newTrajectoryID()
	if err != nil {
		return err
	}
	seqBase := uint64(time.Now().UnixNano())
	fmt.Printf("trajectory_id: %s seq_base=%d\n", trajectoryID, seqBase)

	allowed := syntheticFrame(trajectoryID, trajectoryID+"-allowed", seqBase, "com.android.settings")
	allowedEnvelope, err := client.BuildSignedEnvelopeWithKey(privateKey, time.Now(), allowed, publicKeyID, "")
	if err != nil {
		return err
	}
	allowedResp, err := client.IngestFrame(ctx, conn, &allowedEnvelope)
	if err != nil {
		return fmt.Errorf("send allowed frame: %w", err)
	}
	fmt.Printf("allowed frame decision: %s reasons=%v\n", allowedResp.Decision, allowedResp.ReasonCodes)

	sensitive := syntheticFrame(trajectoryID, trajectoryID+"-sensitive", seqBase+1, "com.example.bank")
	sensitiveEnvelope, err := client.BuildSignedEnvelopeWithKey(privateKey, time.Now(), sensitive, publicKeyID, "")
	if err != nil {
		return err
	}
	sensitiveResp, err := client.IngestFrame(ctx, conn, &sensitiveEnvelope)
	if err != nil {
		return fmt.Errorf("send sensitive frame: %w", err)
	}
	fmt.Printf("sensitive frame decision: %s reasons=%v\n", sensitiveResp.Decision, sensitiveResp.ReasonCodes)
	return nil
}

func newTrajectoryID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("mock-trajectory-%d-%s", time.Now().UnixNano(), hex.EncodeToString(b[:])), nil
}

func loadOrCreateKeypair(dir string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	privatePath := filepath.Join(dir, "device_ed25519_private.base64")
	data, err := os.ReadFile(privatePath)
	if err == nil {
		raw, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return nil, nil, err
		}
		if len(raw) != ed25519.PrivateKeySize {
			return nil, nil, errors.New("stored private key has invalid length")
		}
		privateKey := ed25519.PrivateKey(raw)
		publicKey, ok := privateKey.Public().(ed25519.PublicKey)
		if !ok {
			return nil, nil, errors.New("derive public key")
		}
		return publicKey, privateKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(privatePath, []byte(base64.StdEncoding.EncodeToString(privateKey)), 0o600); err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

func syntheticFrame(trajectoryID, frameID string, sequence uint64, pkg string) client.RawFrame {
	return client.RawFrame{
		ProtocolVersion: "golem.v1",
		TrajectoryID:    trajectoryID,
		FrameID:         frameID,
		Sequence:        sequence,
		EventTimestamp:  time.Now().UTC(),
		Device: client.DeviceMetadata{
			DeviceID:                     "mock-device",
			AndroidSDKVersion:            "35",
			BuildFingerprintHash:         "sha256:test-build",
			BuildMetadataRedactionStatus: "hashed",
		},
		ForegroundApp: client.ForegroundApp{PackageName: pkg, ActivityName: "SyntheticActivity"},
		UIRoot: client.RawNode{
			StableNodeID:   "root",
			ClassName:      "android.widget.FrameLayout",
			PackageName:    pkg,
			ResourceIDHash: "sha256:synthetic-root",
			RawText:        "Settings",
			Enabled:        true,
			Children: []client.RawNode{
				{
					StableNodeID:   "button-1",
					ClassName:      "android.widget.Button",
					PackageName:    pkg,
					ResourceIDHash: "sha256:synthetic-button",
					RawText:        "Open Wi-Fi",
					Clickable:      true,
					Enabled:        true,
				},
			},
		},
		Intent: client.IntentMetadata{
			OperatorIntentID: "synthetic-intent",
			IntentType:       "open_settings",
			Tags:             []string{"synthetic"},
		},
		Action: client.ActionMetadata{
			ActionID:           "synthetic-action",
			ActionType:         "tap",
			TargetStableNodeID: "button-1",
			Deterministic:      true,
		},
		UISettle: client.UISettleMetadata{Observed: true, SettleTimeoutMS: 1000, ElapsedMS: 100, SettleStatus: "settled"},
	}
}
