// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/reason"
)

// UnsafeEndpoints are the endpoints a partner switches off for unsafe sessions, each written
// "<METHOD> <path pattern>", such as "POST /refund". The pattern is that of the handler the framework
// dispatched the request to, not the path the caller wrote, so /refund;x=1 and //refund, which reach the
// /refund handler, are refused as POST /refund. Only the framework knows that pattern, so its adapter
// hands it over.
type UnsafeEndpoints []string

// Refuses reports whether a request with method that reached the handler for pathPattern is switched
// off. A HEAD runs the GET handler, so it is refused wherever that GET is.
func (u UnsafeEndpoints) Refuses(method, pathPattern string) bool {
	return slices.Contains(u, method+" "+pathPattern) || method == "HEAD" && slices.Contains(u, "GET "+pathPattern)
}

// UnsafeRefusal returns the answer to a request [UnsafeEndpoints] refuses, sent in place of its handler:
// 403 {"reason":"UNSAFE_SESSION"}.
func UnsafeRefusal() Answer {
	return Refusal(403, reason.UnsafeSession)
}
