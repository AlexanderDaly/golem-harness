package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golem-harness/server/internal/auth"
)

const (
	DefaultMaxPayloadBytes = 64 * 1024
	DefaultSignatureTTL    = 5 * time.Minute
)

type Config struct {
	GRPCAddr            string         `json:"grpc_addr"`
	HTTPAddr            string         `json:"http_addr"`
	StoragePath         string         `json:"storage_path"`
	ReplayPath          string         `json:"replay_path"`
	MaxPayloadBytes     int            `json:"max_payload_bytes"`
	SignatureTTLSeconds int            `json:"signature_ttl_seconds"`
	AllowedPackages     []string       `json:"allowed_packages"`
	SensitivePackages   []string       `json:"sensitive_packages"`
	AllowedDevices      []DeviceConfig `json:"allowed_devices"`
	MTLS                MTLSConfig     `json:"mtls"`
}

type DeviceConfig struct {
	DeviceID                    string `json:"device_id"`
	Ed25519PublicKeyBase64      string `json:"ed25519_public_key_base64"`
	PublicKeyID                 string `json:"public_key_id,omitempty"`
	ClientCertFingerprintSHA256 string `json:"client_cert_fingerprint_sha256,omitempty"`
}

type MTLSConfig struct {
	Enabled       bool   `json:"enabled"`
	CertFile      string `json:"cert_file,omitempty"`
	KeyFile       string `json:"key_file,omitempty"`
	ClientCAFile  string `json:"client_ca_file,omitempty"`
	RequireClient bool   `json:"require_client"`
}

func Load(path string) (Config, error) {
	if path == "" {
		return Config{}, errors.New("config path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Validate() error {
	if c.GRPCAddr == "" {
		return errors.New("grpc_addr is required")
	}
	if c.HTTPAddr == "" {
		return errors.New("http_addr is required")
	}
	if c.StoragePath == "" {
		return errors.New("storage_path is required")
	}
	if c.ReplayPath == "" {
		c.ReplayPath = filepath.Join(filepath.Dir(c.StoragePath), "replay.db")
	}
	if len(c.AllowedDevices) == 0 {
		return errors.New("at least one allowed device is required")
	}
	if len(c.AllowedPackages) == 0 {
		return errors.New("at least one allowed package is required")
	}
	if c.MaxPayloadBytes == 0 {
		c.MaxPayloadBytes = DefaultMaxPayloadBytes
	}
	if c.MaxPayloadBytes < 1024 {
		return errors.New("max_payload_bytes must be at least 1024")
	}
	if c.SignatureTTLSeconds == 0 {
		c.SignatureTTLSeconds = int(DefaultSignatureTTL.Seconds())
	}
	if c.SignatureTTLSeconds < 1 {
		return errors.New("signature_ttl_seconds must be positive")
	}
	if c.MTLS.Enabled {
		if c.MTLS.CertFile == "" || c.MTLS.KeyFile == "" || c.MTLS.ClientCAFile == "" {
			return errors.New("mtls cert_file, key_file, and client_ca_file are required when mtls is enabled")
		}
	}
	devicesRequireClientCert := false
	for _, d := range c.AllowedDevices {
		if d.ClientCertFingerprintSHA256 != "" {
			devicesRequireClientCert = true
			break
		}
	}
	if devicesRequireClientCert {
		if !c.MTLS.Enabled {
			return errors.New("mtls must be enabled when a device sets client_cert_fingerprint_sha256")
		}
		// Fail closed: registry cert binding is useless without required client certs.
		c.MTLS.RequireClient = true
	}
	if _, err := c.AuthDevices(); err != nil {
		return err
	}
	return nil
}

func (c Config) AuthDevices() ([]auth.Device, error) {
	devices := make([]auth.Device, 0, len(c.AllowedDevices))
	for _, item := range c.AllowedDevices {
		if item.DeviceID == "" {
			return nil, errors.New("allowed device_id is required")
		}
		raw, err := base64.StdEncoding.DecodeString(item.Ed25519PublicKeyBase64)
		if err != nil {
			return nil, fmt.Errorf("decode device %q public key: %w", item.DeviceID, err)
		}
		if len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("device %q public key must be %d bytes", item.DeviceID, ed25519.PublicKeySize)
		}
		devices = append(devices, auth.Device{
			DeviceID:                    item.DeviceID,
			PublicKey:                   ed25519.PublicKey(raw),
			PublicKeyID:                 item.PublicKeyID,
			ClientCertFingerprintSHA256: item.ClientCertFingerprintSHA256,
		})
	}
	return devices, nil
}

func (c Config) SignatureTTL() time.Duration {
	if c.SignatureTTLSeconds <= 0 {
		return DefaultSignatureTTL
	}
	return time.Duration(c.SignatureTTLSeconds) * time.Second
}
