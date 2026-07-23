package config_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"golem-harness/server/internal/config"
	"golem-harness/server/internal/testutil"
)

func TestLoadMissingConfigFailsClearly(t *testing.T) {
	_, err := config.Load("")
	if err == nil || !strings.Contains(err.Error(), "config path is required") {
		t.Fatalf("expected clear missing config error, got %v", err)
	}
}

func TestInvalidKeyMaterialFailsClearly(t *testing.T) {
	cfg := validConfig(t)
	cfg.AllowedDevices[0].Ed25519PublicKeyBase64 = base64.StdEncoding.EncodeToString([]byte("short"))
	path := writeConfig(t, cfg)

	_, err := config.Load(path)
	if err == nil || !strings.Contains(err.Error(), "public key must be") {
		t.Fatalf("expected invalid key error, got %v", err)
	}
}

func TestAllowedPackageConfigParses(t *testing.T) {
	cfg := validConfig(t)
	path := writeConfig(t, cfg)

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(loaded.AllowedPackages) != 1 || loaded.AllowedPackages[0] != testutil.AllowedPkg {
		t.Fatalf("allowed packages not parsed: %#v", loaded.AllowedPackages)
	}
	devices, err := loaded.AuthDevices()
	if err != nil {
		t.Fatalf("auth devices: %v", err)
	}
	if len(devices) != 1 || len(devices[0].PublicKey) != ed25519.PublicKeySize {
		t.Fatalf("unexpected devices: %#v", devices)
	}
}

func TestReplayPathDefaultsBesideStorage(t *testing.T) {
	cfg := validConfig(t)
	cfg.ReplayPath = ""
	cfg.StoragePath = t.TempDir() + "/nested/frames.jsonl"
	path := writeConfig(t, cfg)

	loaded, err := config.Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	wantSuffix := "/nested/replay.db"
	if !strings.HasSuffix(loaded.ReplayPath, wantSuffix) && !strings.HasSuffix(loaded.ReplayPath, "nested/replay.db") {
		t.Fatalf("expected default replay beside storage, got %q", loaded.ReplayPath)
	}
}

func validConfig(t *testing.T) config.Config {
	t.Helper()
	publicKey, _ := testutil.KeyPair(1)
	return config.Config{
		GRPCAddr:            "127.0.0.1:7443",
		HTTPAddr:            "127.0.0.1:8080",
		StoragePath:         t.TempDir() + "/frames.jsonl",
		MaxPayloadBytes:     4096,
		SignatureTTLSeconds: 300,
		AllowedPackages:     []string{testutil.AllowedPkg},
		SensitivePackages:   []string{testutil.SensitivePkg},
		AllowedDevices: []config.DeviceConfig{
			{
				DeviceID:               testutil.DeviceID,
				Ed25519PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey),
				PublicKeyID:            "test-key",
			},
		},
	}
}

func writeConfig(t *testing.T, cfg config.Config) string {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/config.json"
	if err := osWriteFile(path, data); err != nil {
		t.Fatal(err)
	}
	return path
}
