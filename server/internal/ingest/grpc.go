package ingest

import "google.golang.org/grpc"

// ServerOptions returns gRPC server options for the ingest proxy.
// Prefer Register + GRPCServer for service registration.
func ServerOptions(maxRecvBytes int) []grpc.ServerOption {
	if maxRecvBytes <= 0 {
		return nil
	}
	return []grpc.ServerOption{grpc.MaxRecvMsgSize(maxRecvBytes)}
}
