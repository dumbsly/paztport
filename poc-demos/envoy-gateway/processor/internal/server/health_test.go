// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"testing"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/material/materialtest"
)

// check asks the health service on the gRPC port, as a client presenting the edge's certificate, for the
// status of service.
func (h *harness) check(t *testing.T, service string) (grpc_health_v1.HealthCheckResponse_ServingStatus, error) {
	t.Helper()
	conn, err := grpc.NewClient(h.grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(h.clientTLS(h.edge))))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{Service: service})
	if err != nil {
		return grpc_health_v1.HealthCheckResponse_UNKNOWN, err
	}
	return r.GetStatus(), nil
}

// TestHealthServesWhileReady answers SERVING for the whole server and for the ext_proc service, and
// NOT_FOUND for any other service.
func TestHealthServesWhileReady(t *testing.T) {
	h := start(t, nil)
	for _, service := range []string{"", extprocv3.ExternalProcessor_ServiceDesc.ServiceName} {
		got, err := h.check(t, service)
		if err != nil || got != grpc_health_v1.HealthCheckResponse_SERVING {
			t.Fatalf("Check(%q) = %v, %v, want SERVING", service, got, err)
		}
	}
	if _, err := h.check(t, "other"); status.Code(err) != codes.NotFound {
		t.Fatalf("Check(other) = %v, want NotFound", err)
	}
}

// TestHealthFollowsReadiness answers NOT_SERVING once the material has expired and while the server is
// draining, for both names it knows, as /readyz answers 503.
func TestHealthFollowsReadiness(t *testing.T) {
	h := start(t, nil)
	h.clock.Store(materialtest.Now + materialtest.Lifetime + 1)
	for _, service := range []string{"", extprocv3.ExternalProcessor_ServiceDesc.ServiceName} {
		got, err := h.check(t, service)
		if err != nil || got != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
			t.Fatalf("Check(%q) with expired material = %v, %v, want NOT_SERVING", service, got, err)
		}
	}
	if _, err := h.check(t, "other"); status.Code(err) != codes.NotFound {
		t.Fatalf("Check(other) with expired material = %v, want NotFound", err)
	}

	h = start(t, nil)
	h.srv.SetDraining()
	for _, service := range []string{"", extprocv3.ExternalProcessor_ServiceDesc.ServiceName} {
		got, err := h.check(t, service)
		if err != nil || got != grpc_health_v1.HealthCheckResponse_NOT_SERVING {
			t.Fatalf("Check(%q) while draining = %v, %v, want NOT_SERVING", service, got, err)
		}
	}
}
