// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package server

// SetDraining marks the server as shutting down without stopping it, so that a test can see what
// readiness reports in the moment between Shutdown's start and the gRPC port closing.
func (s *Server) SetDraining() { s.draining.Store(true) }
