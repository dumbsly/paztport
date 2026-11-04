// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/edge"
	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/material"
	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/routes"
)

// headroom is what a gRPC message may hold beyond the body limit: the request's headers and attributes,
// which Envoy sends in the same message as a body only at the request's headers, and protobuf's framing.
const headroom = 1 << 20

// shutdownGrace is how long [Run] lets the requests in flight finish once its context ends, before it
// closes their streams.
const shutdownGrace = 10 * time.Second

// Server is the edge's processor, served: the ext_proc service on the gRPC port, over mutual TLS that
// admits only the edge, and /metrics, /readyz and /livez on the admin port, over plain HTTP.
type Server struct {
	log      *slog.Logger
	now      func() time.Time
	set      *material.Set
	grpc     *grpc.Server
	admin    *http.Server
	draining atomic.Bool
}

// New loads everything cfg names and returns a server ready to [Server.Serve], judging the material by
// the clock now, or time.Now when nil, and logging to log. It refuses TLS files that do not load, routes
// that do not, and material that [material.Load] refuses, so that a processor that starts can stamp.
//
// Each request is counted in the metrics and logged once decided, with its outcome, the rid of its stamp
// and Envoy's x-request-id. Nothing else of a request is logged: not its body, nor its Paztport headers,
// nor any other header, nor any key.
func New(cfg Config, log *slog.Logger, now func() time.Time) (*Server, error) {
	if now == nil {
		now = time.Now
	}
	tlsConfig, err := serverTLS(cfg, log)
	if err != nil {
		return nil, err
	}
	rm, err := routes.Load(cfg.Routes)
	if err != nil {
		return nil, fmt.Errorf("server: the routes do not load: %w", err)
	}
	set, err := material.Load(material.Config{
		KeyPath: cfg.Key, PinPath: cfg.Pin, KeyringPaths: cfg.Keyrings, RootPaths: cfg.Roots,
		BundlePath: cfg.Bundle, Routes: rm,
	}, func() int64 { return now().UnixMilli() })
	if err != nil {
		return nil, err
	}
	m := newMetrics(set, now)
	p, err := edge.New(edge.Config{
		Material: set, Inst: cfg.Inst, MaxBody: cfg.BodyLimit, Now: now,
		Observe: func(o edge.Observation) {
			m.observe(o)
			logRequest(log, o)
		},
	})
	if err != nil {
		return nil, err
	}

	s := &Server{log: log, now: now, set: set}
	s.grpc = grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		// Envoy sends a buffered body whole, in one message, so a message may be as long as the body limit.
		grpc.MaxRecvMsgSize(cfg.BodyLimit+headroom),
		// Envoy keeps one connection open between requests: let it ping every 10 s, even with no stream,
		// and ping it ourselves, so that a connection that died silently is closed, not waited on.
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
	)
	extprocv3.RegisterExternalProcessorServer(s.grpc, p)

	mux := http.NewServeMux()
	mux.Handle("GET /metrics", promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelError),
	}))
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { text(w, http.StatusOK, "live\n") })
	s.admin = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	return s, nil
}

// Serve serves the ext_proc service on grpcLis and the admin endpoints on adminLis until
// [Server.Shutdown], when it returns nil, or until either fails, when it stops the other and returns the
// failure.
func (s *Server) Serve(grpcLis, adminLis net.Listener) error {
	errs := make(chan error, 2)
	go func() { errs <- s.grpc.Serve(grpcLis) }()
	go func() {
		err := s.admin.Serve(adminLis)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errs <- err
	}()
	s.log.Info("serving", "grpc", grpcLis.Addr().String(), "admin", adminLis.Addr().String(),
		"material_seconds_left", s.set.TimeLeft(s.now().UnixMilli()).Seconds())
	first := <-errs
	if first != nil {
		s.draining.Store(true)
		s.grpc.Stop()
		_ = s.admin.Close()
	}
	return errors.Join(first, <-errs)
}

// Shutdown stops the server: /readyz reports it not ready, the gRPC port takes no new stream and lets
// those in flight finish until ctx ends, when it closes them, and the admin port closes.
func (s *Server) Shutdown(ctx context.Context) error {
	s.draining.Store(true)
	stopped := make(chan struct{})
	go func() {
		s.grpc.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-ctx.Done():
		s.grpc.Stop()
		<-stopped
	}
	if err := s.admin.Shutdown(ctx); err != nil {
		_ = s.admin.Close()
		return err
	}
	return nil
}

// Run serves cfg on its two addresses, as [New] and [Server.Serve] do, until ctx ends; then it shuts
// down, giving the requests in flight up to ten seconds. A pod roll is how the processor takes new
// configuration, material or certificates.
func Run(ctx context.Context, cfg Config, log *slog.Logger, now func() time.Time) error {
	s, err := New(cfg, log, now)
	if err != nil {
		return err
	}
	grpcLis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("server: PROCESSOR_LISTEN: %w", err)
	}
	adminLis, err := net.Listen("tcp", cfg.AdminListen)
	if err != nil {
		_ = grpcLis.Close()
		return fmt.Errorf("server: PROCESSOR_ADMIN_LISTEN: %w", err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve(grpcLis, adminLis) }()
	select {
	case err := <-served:
		return err
	case <-ctx.Done():
	}
	s.log.Info("stopping")
	stopCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	stopErr := s.Shutdown(stopCtx)
	return errors.Join(<-served, stopErr)
}

// readyz reports the processor ready while its material is current and it is not shutting down.
func (s *Server) readyz(w http.ResponseWriter, _ *http.Request) {
	switch {
	case s.draining.Load():
		text(w, http.StatusServiceUnavailable, "shutting down\n")
	case s.set.Ready(s.now().UnixMilli()) != nil:
		text(w, http.StatusServiceUnavailable, "the policy material has expired\n")
	default:
		text(w, http.StatusOK, "ready\n")
	}
}

// text answers with status and a plain-text body.
func text(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

// logRequest logs one decided request: its outcome, the rid of its stamp when it was stamped, and Envoy's
// x-request-id when the request carried one of the form Envoy gives it (see [edge.Observation]). It is the
// only line a request writes, and it holds nothing else the request carried.
func logRequest(log *slog.Logger, o edge.Observation) {
	attrs := []slog.Attr{slog.String("outcome", string(o.Outcome))}
	if o.RID != "" {
		attrs = append(attrs, slog.String("rid", o.RID))
	}
	if o.RequestID != "" {
		attrs = append(attrs, slog.String("x_request_id", o.RequestID))
	}
	log.LogAttrs(context.Background(), slog.LevelInfo, "request", attrs...)
}
