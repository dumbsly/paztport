// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package wire

import "strings"

// The names Paztport gives its HTTP headers, and what its handshake and refusals are sent as.
const (
	// Chain names the header holding a request's chain, as a token: origin first, the last stamp's rcv
	// the receiving service and its bind the request's [Bind].
	Chain = "X-Path-Chain"
	// Proof names the header holding the proof, as a token, for the request's full route, the receiving
	// service included.
	Proof = "X-Path-Proof"
	// Influence names the header holding, as a token, the influence entries a request was made under. An
	// absent one means no entries.
	Influence = "X-Path-Influence"
	// Response names the header holding a response's attestation, as a token of {labels, stamp}.
	Response = "X-Path-Response"
	// Session names the header holding, as plain text, the id of the session a call between
	// organisations is made in. Inside a mesh it is absent.
	Session = "X-Path-Session"
	// ContentType is the media type of a handshake's request and reply and of a refusal's body, with no
	// parameters.
	ContentType = "application/json"
	// SessionPath is the path a partner serves the handshake at, by POST.
	SessionPath = "/paztport/session"
)

// Header is one header to send: its name, such as [Chain], and its value.
type Header struct {
	Name, Value string
}

// HeaderValue returns a received header's value without the optional whitespace around it, and reports
// whether the header is present. HTTP's optional whitespace is space and horizontal tab (RFC 9110,
// section 5.5), and only those are trimmed: a value with any other character around its token, such as
// a no-break space, keeps it, and reads as no token. A value of nothing else is absent.
//
// Which value of a repeated header to pass is the caller's: Paztport reads the first.
func HeaderValue(v string) (string, bool) {
	v = strings.Trim(v, " \t")
	return v, v != ""
}

// IsPaztport reports whether name is one of Paztport's headers: it begins with X-Path-, compared
// case-insensitively over ASCII only, so no other byte sequence folds onto the prefix. The rest of the
// name is not read. Whoever sends a call removes every header of the request that IsPaztport names, all
// values, before it sets those paztporthttp's Caller.Stamp returns; a gateway's external processor, a
// forwarding origin, also removes them from the response it passes back.
func IsPaztport(name string) bool {
	const prefix = "x-path-"
	if len(name) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := name[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != prefix[i] {
			return false
		}
	}
	return true
}
