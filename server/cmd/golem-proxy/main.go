package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golem-harness/server/internal/auth"
	"golem-harness/server/internal/config"
	"golem-harness/server/internal/ingest"
	"golem-harness/server/internal/sanitize"
	"golem-harness/server/internal/storage"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "golem-proxy: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "", "path to JSON config")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	devices, err := cfg.AuthDevices()
	if err != nil {
		return err
	}
	registry, err := auth.NewStaticDeviceRegistry(devices)
	if err != nil {
		return err
	}
	sink, err := storage.NewJSONLSink(cfg.StoragePath)
	if err != nil {
		return err
	}
	pipeline := sanitize.NewPipeline(cfg.AllowedPackages, cfg.SensitivePackages)
	service := &ingest.Service{
		Verifier: &auth.Verifier{
			Registry:        registry,
			ReplayGuard:     auth.NewMemoryReplayGuard(),
			MaxPayloadBytes: cfg.MaxPayloadBytes,
			TTL:             cfg.SignatureTTL(),
		},
		Sanitizer: pipeline,
		Storage:   sink,
		Logger:    logger,
	}

	grpcOptions := ingest.ServerOptions(cfg.MaxPayloadBytes + 4096)
	if cfg.MTLS.Enabled {
		creds, err := transportCredentials(cfg.MTLS)
		if err != nil {
			return err
		}
		grpcOptions = append(grpcOptions, grpc.Creds(creds))
	}
	grpcServer := grpc.NewServer(grpcOptions...)
	ingest.RegisterTelemetryIngestServiceServer(grpcServer, service)

	httpServer := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           healthHandler(),
		ReadHeaderTimeout: 3 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)
	go func() {
		listener, err := net.Listen("tcp", cfg.GRPCAddr)
		if err != nil {
			errCh <- err
			return
		}
		logger.Info("grpc_listening", "addr", cfg.GRPCAddr, "mtls_enabled", cfg.MTLS.Enabled)
		errCh <- grpcServer.Serve(listener)
	}()
	go func() {
		logger.Info("http_listening", "addr", cfg.HTTPAddr)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		grpcServer.GracefulStop()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == nil || errors.Is(err, grpc.ErrServerStopped) || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		grpcServer.Stop()
		_ = httpServer.Close()
		return err
	}
}

func healthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	return mux
}

func transportCredentials(cfg config.MTLSConfig) (credentials.TransportCredentials, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load server certificate: %w", err)
	}
	clientCA, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read client ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(clientCA) {
		return nil, errors.New("client ca file did not contain a PEM certificate")
	}
	clientAuth := tls.VerifyClientCertIfGiven
	if cfg.RequireClient {
		clientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(&tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    pool,
		ClientAuth:   clientAuth,
	}), nil
}
