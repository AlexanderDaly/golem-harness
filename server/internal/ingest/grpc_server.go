package ingest

import (
	"context"

	golemv1 "golem-harness/server/gen/golem/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GRPCServer adapts Service to the generated TelemetryIngestServiceServer.
type GRPCServer struct {
	golemv1.UnimplementedTelemetryIngestServiceServer
	Service *Service
}

func Register(registrar grpc.ServiceRegistrar, service *Service) {
	golemv1.RegisterTelemetryIngestServiceServer(registrar, &GRPCServer{Service: service})
}

func (s *GRPCServer) IngestFrame(ctx context.Context, req *golemv1.IngestFrameRequest) (*golemv1.IngestFrameResponse, error) {
	if req == nil || req.GetEnvelope() == nil {
		return nil, status.Error(codes.InvalidArgument, "missing envelope")
	}
	if s.Service == nil {
		return nil, status.Error(codes.FailedPrecondition, "ingest service is not configured")
	}
	envelope, err := envelopeFromProto(req.GetEnvelope())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, safeReason(err))
	}
	resp, err := s.Service.IngestFrame(ctx, &envelope)
	if err != nil {
		return nil, err
	}
	return responseToProto(resp), nil
}
