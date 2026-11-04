// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Command processor is the Envoy Gateway edge's external processor. It reads its configuration from the
// environment (see the README), serves until SIGTERM or an interrupt, then lets the requests in flight
// finish, and logs as JSON on standard output.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/server"
)

func main() {
	os.Exit(run())
}

func run() int {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := server.FromEnv(os.Getenv)
	if err != nil {
		log.Error("not started", "error", err.Error())
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := server.Run(ctx, cfg, log, time.Now); err != nil {
		log.Error("stopped", "error", err.Error())
		return 1
	}
	return 0
}
