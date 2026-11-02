// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package reason

// Code is the outcome of a verification, as the spec writes it: "OK", or the one reason for rejection.
type Code string

// The codes a live verifier gives, and an offline one but for PeerMismatch.
const (
	// OK means every check held.
	OK Code = "OK"
	// ChainMissing means there is no chain, or one that does not read, or a malformed transport field
	// around it, a response attestation that does not read included.
	ChainMissing Code = "CHAIN_MISSING"
	// BadOrigin means the origin is not an allowed origin, or offline, not the expected instance.
	BadOrigin Code = "BAD_ORIGIN"
	// BadSignature means a signed field holds "|", a key is unknown, or a signature fails.
	BadSignature Code = "BAD_SIGNATURE"
	// BrokenLink means a stamp's prev is not the previous stamp's sig.
	BrokenLink Code = "BROKEN_LINK"
	// Expired means a stamp is outside the freshness window, or offline, outside the age limits.
	Expired Code = "EXPIRED"
	// RIDMismatch means the stamps don't share the origin's rid, or name another request.
	RIDMismatch Code = "RID_MISMATCH"
	// BindingMismatch means a stamp's rcv names the wrong hop, or the binding does not match what was
	// received.
	BindingMismatch Code = "BINDING_MISMATCH"
	// Replay means the nonce key was seen before.
	Replay Code = "REPLAY"
	// PathNotAllowed means the route is not proven against the root.
	PathNotAllowed Code = "PATH_NOT_ALLOWED"
	// SessionUnknown means a stamp names another session. Over HTTP it is also a call whose
	// X-Path-Session names no live session opened by the sending peer.
	SessionUnknown Code = "SESSION_UNKNOWN"
	// InfluenceMismatch means the influence does not read, or the last stamp does not commit to it.
	InfluenceMismatch Code = "INFLUENCE_MISMATCH"
	// PeerMismatch, which only a live verifier gives, means the authenticated transport peer is not the
	// last signer.
	PeerMismatch Code = "PEER_MISMATCH"
	// PolicyExpired means the keyring or root the verifier relies on has expired: live, the time is past
	// the policy's notAfter; offline, the record's own time is past the notAfter of a root or keyring it
	// relies on. It is about the verifier's own material, not the request, so it names no one.
	PolicyExpired Code = "POLICY_EXPIRED"
)

// The codes only an offline verifier gives. A client never accepts one as a server's verdict.
const (
	// TimeMismatch means a stamp's time is not the one recorded with it.
	TimeMismatch Code = "TIME_MISMATCH"
	// PromptMismatch means the origin does not bind the run's recorded prompt.
	PromptMismatch Code = "PROMPT_MISMATCH"
	// OutsideSession means a recorded call that otherwise verifies, in a session whose recorded handshake
	// is attested, but whose last stamp's ts is past one of the session's limits.
	OutsideSession Code = "OUTSIDE_SESSION"
)

// The codes a server's decision on a call gives, besides a live verifier's.
const (
	// InfluenceDenied means the influence rule refused a public write.
	InfluenceDenied Code = "INFLUENCE_DENIED"
	// UnsafeSession means the tool is disabled in an unsafe session.
	UnsafeSession Code = "UNSAFE_SESSION"
)
