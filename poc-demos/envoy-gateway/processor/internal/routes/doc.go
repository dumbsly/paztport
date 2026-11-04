// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package routes names the receiver of each request the edge stamps. The receiver is the operator's
// configuration, a [Map] from each HTTPRoute to the receiving service's policy name, looked up by the
// HTTPRoute that Envoy Gateway says the matched route was built from ([FromAttributes]). Nothing the
// client sends, neither its authority, host, path nor any header, chooses it.
package routes
