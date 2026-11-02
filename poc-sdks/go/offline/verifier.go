// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package offline

import (
	"slices"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/chaincheck"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/exact"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// RecordedTimes are the times a record set gives for a chain.
type RecordedTimes struct {
	// Last is when the chain's last hop made it, as recorded beside it: the last stamp's ts must be this.
	Last int64
	// RunGiven reports whether the run's records give start times, even none. When it is set, or Run
	// holds any time, the origin's ts must be one of Run: a run whose records give no start time then
	// fails, rather than compare nothing. A Run built by appending over no records is nil, so presence is
	// this flag's to say, never the slice's.
	RunGiven bool
	// Run is the start times the run's records give.
	Run []int64
}

// Input is what the offline verifier is handed for one recorded chain: the live Input's tokens and what
// the receiver knew, with no peer, since a record has no transport, and what the record set says of the
// chain. A nil token is absent; an empty one is present, and is read as what it is.
type Input struct {
	// Chain is the chain's token, as recorded.
	Chain *string
	// ExpectedBind is the binding the receiver computed for what it received. A nil one never matches.
	ExpectedBind *string
	// Influence is the influence's token, as recorded. A nil one is the empty list.
	Influence *string
	// Proof is the route proof's token, as recorded. A nil one proves nothing.
	Proof *string
	// Receiver is what the last stamp's rcv must name.
	Receiver string
	// ReceiverInRoute reports whether the route ends at Receiver: true for a call, false for a response.
	ReceiverInRoute bool
	// NonceKey is the chain's key among the record set's spent keys. A nil one can't be shown unspent, and
	// is a replay.
	NonceKey *string
	// RID is the rid the record files the chain under, which every stamp must carry; nil for the origin's.
	RID *string
	// Recorded is the times the record set gives for the chain. When it is nil no time is compared: the
	// spec does not say what a record with no recorded times gives, and this is the Java SDK's choice.
	Recorded *RecordedTimes
	// Prompt is the run's recorded prompt, which the origin must bind; nil when the run has none or it is
	// disputed, and the origin can then never bind it.
	Prompt *string
}

// Config is what the offline verifier pins: the policy material it checks chains against, the session it
// expects and the age limits.
//
// The age limits need no clock: a chain the live verifier passed at its last stamp's time has its last
// stamp at most RunMaxAgeMs after the origin, and its origin at most CallMaxAgeMs after its last stamp.
// Both nil leaves a chain's age unlimited. One alone is a misconfiguration, which fails closed: every chain
// that reaches the age limits is EXPIRED. The spec leaves that case open, and this is the Java SDK's choice.
type Config struct {
	// Keyring is each service's public key.
	Keyring policy.Keyring
	// Root is the bytes of the root of the allowed routes' tree.
	Root []byte
	// RootID labels that tree; a proof for another tree proves nothing.
	RootID string
	// AllowedOrigins are the services that may sign an origin stamp.
	AllowedOrigins []string
	// Sess is the session id every stamp must carry; "" for a chain in no session.
	Sess string
	// RunMaxAgeMs bounds how long after the origin the last stamp may be.
	RunMaxAgeMs *int64
	// CallMaxAgeMs bounds how long after the last stamp the origin may be.
	CallMaxAgeMs *int64
}

// RecordSet is one record set being verified again, such as a client's evidence file. It holds the nonce
// keys its chains have spent, one set for the whole record set, which never forgets: a live cache forgets
// a key after its window, which offline would let a copy pass once a later record is far enough on.
// Nothing in a handshake record resets it, so a repeated handshake leaves it as it is.
//
// The zero RecordSet is an empty record set, ready to use. A record set is read in order, by one goroutine.
type RecordSet struct {
	spent map[string]bool
}

// NewRecordSet returns a record set in which the nonce keys spent are already spent, such as by records
// verified before it.
func NewRecordSet(spent ...string) *RecordSet {
	rs := &RecordSet{spent: make(map[string]bool, len(spent))}
	for _, key := range spent {
		rs.spent[key] = true
	}
	return rs
}

// Verify runs the offline order on in, one recorded chain of the record set, and answers with the first
// check that fails, or OK:
//
//  1. CHAIN_MISSING, unless the chain reads from its token;
//  2. BAD_SIGNATURE, if a signed field of any stamp holds "|";
//  3. BAD_ORIGIN, unless the origin is an allowed origin;
//  4. BAD_SIGNATURE, BROKEN_LINK, then BINDING_MISMATCH, unless each stamp in turn is signed by its
//     service's key and links to the one before, and then each stamp's rcv names the next stamp's svc and
//     the last's names the receiver;
//  5. RID_MISMATCH, unless every stamp carries the record's rid, the origin's when it gives none;
//  6. SESSION_UNKNOWN, unless every stamp carries the Config's session;
//  7. TIME_MISMATCH, unless the last stamp's ts is the time recorded with it and, when the run's records
//     give start times, the origin's ts is one of them; then EXPIRED, if the last stamp is more than
//     RunMaxAgeMs after the origin or the origin more than CallMaxAgeMs after the last stamp, or only one
//     of the limits is set; then PROMPT_MISMATCH, unless there is a recorded prompt and the origin binds it;
//  8. BINDING_MISMATCH, unless the last stamp binds the expected binding;
//  9. INFLUENCE_MISMATCH, unless the influence reads and the last stamp commits to it;
//  10. REPLAY, unless there is a nonce key and the record set has not spent it; only then does the record
//     set spend it;
//  11. PATH_NOT_ALLOWED, unless the proof proves the route against the root.
//
// There is no check 0, since the record's own times stand in for a clock, and no check 12, since a record
// has no peer. OK and PATH_NOT_ALLOWED name the last stamp's svc and inst, as the live verifier's do with
// no peer; every other result names no one. Verify never panics, and a malformed input is a result.
func (rs *RecordSet) Verify(in Input, cfg Config) verify.Result {
	return result(rs.check(in, cfg))
}

// Call verifies in, a call recorded in the session s, as Verify does, and judges it in its session. A
// session that is not attested at all gives no result and false, and the call is neither verified nor
// spends its key: the spec gives a call relying on such a session no result, so the record set's reader
// reports it. Otherwise Call runs the offline order once, spending the key as Verify does, and returns its
// result and true, except that a call that verifies, OK, while the session is not attested at its last
// stamp's ts, which the client signed, is OUTSIDE_SESSION, naming no one: the call was made past one of
// the session's limits. Call judges the chain in the session s names, whatever cfg.Sess holds: it is cfg
// with Sess set to s.Sess().
func (rs *RecordSet) Call(in Input, cfg Config, s RecordedSession) (verify.Result, bool) {
	if !s.Attested() {
		return verify.Result{}, false
	}
	cfg.Sess = s.Sess()
	code, last := rs.check(in, cfg)
	if code == reason.OK && !s.AttestedAt(last.TS) {
		return verify.Result{Reason: reason.OutsideSession}, true
	}
	return result(code, last), true
}

// result names the party the spec names for code: the last stamp for OK and PATH_NOT_ALLOWED, and no one
// otherwise.
func result(code reason.Code, last stamp.Stamp) verify.Result {
	r := verify.Result{Reason: code}
	if code == reason.OK || code == reason.PathNotAllowed {
		r.SuspectSvc, r.SuspectInst = last.Svc, last.Inst
	}
	return r
}

// check runs checks 1 to 11 and returns the first code that fails, or OK, with the chain's last stamp
// once the chain has read.
func (rs *RecordSet) check(in Input, cfg Config) (reason.Code, stamp.Stamp) {
	// 1-2. The chain reads, and no signed field holds the delimiter.
	if in.Chain == nil {
		return reason.ChainMissing, stamp.Stamp{}
	}
	c, code := stamp.ReadChain(*in.Chain)
	if code != reason.OK {
		return code, stamp.Stamp{}
	}
	origin, last := c[0], c[len(c)-1]

	// 3-6. The origin, signatures and links, receivers, rid and session.
	if code := chaincheck.Stamps(c, cfg.Keyring, cfg.AllowedOrigins, cfg.Sess, in.Receiver, in.RID); code != reason.OK {
		return code, last
	}

	// 7. In place of freshness: the recorded times, the age limits, then the prompt.
	if !atRecordedTimes(in.Recorded, origin.TS, last.TS) {
		return reason.TimeMismatch, last
	}
	if !withinAge(origin.TS, last.TS, cfg.RunMaxAgeMs, cfg.CallMaxAgeMs) {
		return reason.Expired, last
	}
	if !bindsPrompt(origin, in.Prompt) {
		return reason.PromptMismatch, last
	}

	// 8-9. The binding and the influence commitment.
	if code := chaincheck.Commitments(last, in.ExpectedBind, in.Influence); code != reason.OK {
		return code, last
	}

	// 10. Replay across the whole record set. A chain with no nonce key can't be shown unspent.
	if in.NonceKey == nil || rs.spent[*in.NonceKey] {
		return reason.Replay, last
	}
	if rs.spent == nil {
		rs.spent = map[string]bool{}
	}
	rs.spent[*in.NonceKey] = true

	// 11. The route.
	return chaincheck.Route(c, in.Receiver, in.ReceiverInRoute, in.Proof, cfg.Root, cfg.RootID), last
}

// atRecordedTimes reports whether the origin's and the last stamp's ts are the times t records: the last
// stamp's is t.Last, and the origin's is one of t.Run when the run gives start times. With no recorded
// times, nothing is compared.
func atRecordedTimes(t *RecordedTimes, origin, last int64) bool {
	if t == nil {
		return true
	}
	runGiven := t.RunGiven || len(t.Run) > 0
	return last == t.Last && (!runGiven || slices.Contains(t.Run, origin))
}

// bindsPrompt reports whether origin binds prompt, the run's recorded prompt. No prompt, or one that is not
// valid UTF-8 and so has no binding, is never bound.
func bindsPrompt(origin stamp.Stamp, prompt *string) bool {
	if prompt == nil {
		return false
	}
	bind, err := stamp.PromptBinding(*prompt)
	return err == nil && origin.Bind == bind
}

// withinAge runs check 7's age limits on the origin's and the last stamp's ts: the last is at most run
// after the origin, and the origin at most call after the last. With neither limit the age is unlimited;
// with one alone, it is outside them. A difference too large for an int64 is compared exactly, never
// wrapped.
func withinAge(origin, last int64, run, call *int64) bool {
	switch {
	case run == nil && call == nil:
		return true
	case run == nil || call == nil:
		return false
	}
	return exact.AtMost(last, origin, *run) && exact.AtMost(origin, last, *call)
}
