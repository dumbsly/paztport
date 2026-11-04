// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Command echo is the upstream the Envoy Gateway measurements send their load to: it does as little as an HTTP
// server can, so that what a run measures is the edge in front of it. It is not part of the processor's image.
//
// It listens on :8080, plain HTTP. GET /counts answers one line for each Host it has been sent requests for, in
// order,
//
//	<host> stamped=<n> unstamped=<n>
//
// where a stamped request is one that carries an X-Path-Chain header; every other request is read whole and
// answered 200 with an empty body. The counts are this process's own, from its start; GET /counts is not counted.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"sync"
	"syscall"
	"time"
)

func main() {
	srv := &http.Server{Addr: ":8080", Handler: newEcho(), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// echo counts the requests it is sent, per Host, with and without X-Path-Chain.
type echo struct {
	mu     sync.Mutex
	counts map[string]*[2]int64 // [stamped, unstamped]
}

func newEcho() *echo {
	return &echo{counts: map[string]*[2]int64{}}
}

func (e *echo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/counts" {
		e.writeCounts(w)
		return
	}
	unstamped := 1
	if _, ok := r.Header["X-Path-Chain"]; ok {
		unstamped = 0
	}
	e.mu.Lock()
	c := e.counts[r.Host]
	if c == nil {
		c = new([2]int64)
		e.counts[r.Host] = c
	}
	c[unstamped]++
	e.mu.Unlock()
	_, _ = io.Copy(io.Discard, r.Body)
	w.WriteHeader(http.StatusOK)
}

func (e *echo) writeCounts(w http.ResponseWriter) {
	e.mu.Lock()
	hosts := slices.Sorted(maps.Keys(e.counts))
	lines := make([]byte, 0, 64*len(hosts))
	for _, host := range hosts {
		c := e.counts[host]
		lines = fmt.Appendf(lines, "%s stamped=%d unstamped=%d\n", host, c[0], c[1])
	}
	e.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(lines)
}
