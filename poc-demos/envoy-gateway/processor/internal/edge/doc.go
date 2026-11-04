// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package edge is the Envoy Gateway edge's external processor: it stamps every request it lets in as
// Paztport's origin service edge, over the request whole, for the receiver the request's HTTPRoute maps
// to, and refuses any request it cannot stamp so. A client's own Paztport headers never reach a backend:
// every one is removed from the request before the stamp is set, and from the response before the client
// sees it.
package edge
