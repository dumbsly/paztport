// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// notReady returns why the processor is not ready, in the words /readyz gives, or "" when it is ready: its
// material is current and it is not shutting down.
func (s *Server) notReady() string {
	switch {
	case s.draining.Load():
		return "shutting down"
	case s.set.Ready(s.now().UnixMilli()) != nil:
		return "the policy material has expired"
	default:
		return ""
	}
}

// health is the standard gRPC health service on the gRPC port, which Envoy's active health check reaches
// over the same mutual TLS and the same path as the requests it sends. It answers with the readiness
// /readyz reports, so that a replica Envoy cannot reach is taken out of its routes even while Kubernetes,
// which cannot present the edge's certificate, still finds it ready. Only Check is served.
type health struct {
	grpc_health_v1.UnimplementedHealthServer
	s *Server
}

// Check answers SERVING while the processor is ready and NOT_SERVING otherwise, for the whole server (the
// empty service name) and for the ext_proc service; for any other service name it answers NotFound.
func (h health) Check(_ context.Context, req *grpc_health_v1.HealthCheckRequest) (*grpc_health_v1.HealthCheckResponse, error) {
	switch req.GetService() {
	case "", extprocv3.ExternalProcessor_ServiceDesc.ServiceName:
	default:
		return nil, status.Error(codes.NotFound, "unknown service")
	}
	if h.s.notReady() != "" {
		return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_NOT_SERVING}, nil
	}
	return &grpc_health_v1.HealthCheckResponse{Status: grpc_health_v1.HealthCheckResponse_SERVING}, nil
}
