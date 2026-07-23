package ingest

import (
	golemv1 "golem-harness/server/gen/golem/v1"
	"golem-harness/server/pkg/signing"
)

func envelopeFromProto(pb *golemv1.SignatureEnvelope) (signing.SignedEnvelope, error) {
	return signing.EnvelopeFromProto(pb)
}

// ResponseToProto is the single server-side converter for ingest.Response → wire.
func ResponseToProto(resp *Response) *golemv1.IngestFrameResponse {
	if resp == nil {
		return &golemv1.IngestFrameResponse{}
	}
	return &golemv1.IngestFrameResponse{
		RequestId:        resp.RequestID,
		Decision:         signing.DecisionToProto(resp.Decision),
		ReasonCodes:      resp.ReasonCodes,
		SanitizerVersion: resp.SanitizerVersion,
	}
}

// ResponseFromProto maps a wire response to ingest.Response (tests / adapters).
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
