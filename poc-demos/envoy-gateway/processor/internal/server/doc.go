// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package server serves the edge's processor: Envoy's ext_proc service over gRPC with mutual TLS, which
// admits only a client certificate from the client CA naming the edge, and on a separate plain-HTTP port
// the processor's Prometheus metrics, its readiness, which follows its policy material, and its liveness.
// Its configuration comes from the environment (FromEnv) and is read once: a pod roll reloads it.
package server
