package ingest

import (
	"context"

	"golem-harness/server/internal/auth"

	"google.golang.org/grpc"
)

const (
	ServiceName      = "golem.v1.TelemetryIngestService"
	IngestFullMethod = "/golem.v1.TelemetryIngestService/IngestFrame"
)

type TelemetryIngestServiceServer interface {
	IngestFrame(context.Context, *auth.SignedEnvelope) (*Response, error)
}

func RegisterTelemetryIngestServiceServer(registrar grpc.ServiceRegistrar, server TelemetryIngestServiceServer) {
	registrar.RegisterService(&grpc.ServiceDesc{
		ServiceName: ServiceName,
		HandlerType: (*TelemetryIngestServiceServer)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "IngestFrame",
				Handler:    ingestFrameHandler,
			},
		},
		Streams:  []grpc.StreamDesc{},
		Metadata: "proto/golem/v1/telemetry.proto",
	}, server)
}

func ingestFrameHandler(server any, ctx context.Context, decode func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
	req := new(auth.SignedEnvelope)
	if err := decode(req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return server.(TelemetryIngestServiceServer).IngestFrame(ctx, req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     server,
		FullMethod: IngestFullMethod,
	}
	handler := func(ctx context.Context, request any) (any, error) {
		return server.(TelemetryIngestServiceServer).IngestFrame(ctx, request.(*auth.SignedEnvelope))
	}
	return interceptor(ctx, req, info, handler)
}

func ClientIngestFrame(ctx context.Context, conn grpc.ClientConnInterface, envelope *auth.SignedEnvelope, opts ...grpc.CallOption) (*Response, error) {
	response := new(Response)
	if err := conn.Invoke(ctx, IngestFullMethod, envelope, response, opts...); err != nil {
		return nil, err
	}
	return response, nil
}

func ServerOptions(maxRecvBytes int) []grpc.ServerOption {
	if maxRecvBytes <= 0 {
		return nil
	}
	return []grpc.ServerOption{grpc.MaxRecvMsgSize(maxRecvBytes)}
}
