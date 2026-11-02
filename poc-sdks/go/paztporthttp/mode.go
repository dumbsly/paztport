// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import "strings"

// Mode is how a receiver treats the requests it verifies. [ModeAudit] and [ModeEnforce] are the spec's
// two modes; [ModeOff] and [ModeNone] are not modes, but say that a receiver verifies no requests, for
// two different reasons.
//
// The zero Mode is ModeEnforce, and a value that is none of the four is treated as ModeEnforce, so a mode
// left unset, or set to nonsense, fails closed: a service that cannot tell which mode it is in must
// enforce.
type Mode int

// The modes, and the two ways of having none.
const (
	// ModeEnforce verifies each request and refuses one whose result is not OK, with that result's code.
	ModeEnforce Mode = iota
	// ModeAudit verifies each request and refuses nothing: a request that fails is served, but not as
	// verified, so its response is not attested and it cannot write a trusted record. Influence that
	// does not read is still refused, since it may not be dropped.
	ModeAudit
	// ModeOff is a hop its deployment has switched Paztport off on: it verifies, attests and reports
	// nothing, so its callers count its responses untrusted. The chain and the influence are still
	// carried, and influence that does not read is still refused.
	ModeOff
	// ModeNone is a service that verifies no requests and has no mode to switch: it refuses no chain,
	// but it is not off, so where it can attest, it verifies the chain once to decide whether it does.
	ModeNone
)

// ParseMode returns the mode an operator's setting names: "enforce", "audit" or "off", in any case and
// with any ASCII whitespace around it. Anything else, a blank setting included, is ModeEnforce, so a
// mistake in configuration fails closed. No setting names ModeNone: whether a service verifies requests
// at all is the program's to say, not a switch.
func ParseMode(s string) Mode {
	s = strings.Trim(s, " \t\n\v\f\r")
	switch {
	case strings.EqualFold(s, "audit"):
		return ModeAudit
	case strings.EqualFold(s, "off"):
		return ModeOff
	}
	return ModeEnforce
}
