// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"strconv"
	"strings"
)

// Mode is how a receiver treats the requests it verifies. [ModeAudit] and [ModeEnforce] are the spec's
// two modes; [ModeOff] and [ModeNone] are not modes, but say that a receiver verifies no requests, for
// two different reasons.
//
// A mode applies at an origin too: there it decides whether a request is refused or reported, though an
// origin never carries the request's chain or blocks, never takes the chain as verified and never attests.
//
// The zero Mode is ModeEnforce, and a value that is none of the four is treated as ModeEnforce, so a mode
// left unset, or set to nonsense, fails closed: a service that cannot tell which mode it is in must
// enforce.
type Mode int

// The modes, and the two ways of having none.
const (
	// ModeEnforce verifies each request and refuses one whose result is not OK, with that result's code.
	ModeEnforce Mode = iota
	// ModeAudit verifies each request and refuses none that fails: a request that fails is served, but not as
	// verified, so its response is not attested and it cannot write a trusted record. Blocks that do not match
	// their stamps are still refused, 400 EXTENSION_MISMATCH, since none may be dropped or altered, and so, at a
	// service acting on influence, is an influence item that does not read, 400 INFLUENCE_MISMATCH.
	ModeAudit
	// ModeOff is a hop its deployment has switched Paztport off on: it verifies, attests and reports
	// nothing, so its callers count its responses untrusted. The chain and its blocks are still carried and
	// their items handed on, not verified, and blocks that do not match their stamps, or an influence item that
	// does not read at a service acting on influence, are still refused with 400.
	ModeOff
	// ModeNone is a service that verifies no requests and has no mode to switch: it refuses no chain,
	// but it is not off, so where it can attest, it verifies the chain once to decide whether it does. Its
	// blocks and items are refused as under ModeOff.
	ModeNone
)

// String returns the mode's setting, "enforce", "audit" or "off", or "none" for ModeNone, and for a value
// that is no mode, "Mode(<n>)".
func (m Mode) String() string {
	switch m {
	case ModeEnforce:
		return "enforce"
	case ModeAudit:
		return "audit"
	case ModeOff:
		return "off"
	case ModeNone:
		return "none"
	}
	return "Mode(" + strconv.Itoa(int(m)) + ")"
}

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
