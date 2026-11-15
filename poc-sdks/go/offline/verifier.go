// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package offline

import (
	"math"
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
	// Blocks is the token of the chain's blocks, as recorded beside it. A nil one is one empty block per stamp.
	Blocks *string
	// Proof is the route proof's token, as recorded. A nil one proves nothing.
	Proof *string
	// Receiver is what the last stamp's rcv must equal, an operation included.
	Receiver string
	// ReceiverInRoute reports whether the route ends at Receiver: true for a call, false for a response.
	ReceiverInRoute bool
	// NonceKey is the chain's key among the record set's spent keys. A nil one can't be shown unspent, and
	// is a replay.
	NonceKey *string
	// RID is the rid the record files the chain under, which every stamp must carry; nil for the origin's.
	RID *string
	// Recorded is the times the record set gives for the chain. A record with none gives no time to
	// compare the stamps' against, so a nil one is TIME_MISMATCH.
	Recorded *RecordedTimes
	// Prompt is the run's recorded prompt, which the origin must bind; nil when the run has none or it is
	// disputed, and the origin can then never bind it.
	Prompt *string
}

// Config is what the offline verifier pins: the policy material it checks chains against, the session it
// expects and the age limits.
//
// It pins one or more keyrings and one or more roots, each with its own window. A member counts for a
// record when the record's recorded time is at most its notAfter, and for every record when its notAfter is
// math.MaxInt64, no window: a caller that judges the windows itself, as RecordSet.Call does a session's,
// pins its members so. Checks 3 and 12 use only the members that count for the record.
//
// The age limits need no clock: a chain the live verifier passed at its last stamp's time has its last
// stamp at most RunMaxAgeMs after the origin, and its origin at most CallMaxAgeMs after its last stamp.
// A limit left nil is its live default, [verify.RunMaxAgeMs] or [verify.CallMaxAgeMs], each on its own, so
// no configuration leaves the age unlimited.
type Config struct {
	// Keyrings are the keyrings the verifier pins.
	Keyrings []verify.PinnedKeyring
	// Roots are the roots the verifier pins.
	Roots []verify.PinnedRoot
	// AllowedOrigins are the services that may sign an origin stamp.
	AllowedOrigins []string
	// Sess is the session id every stamp must carry; "" for a chain in no session.
	Sess string
	// RunMaxAgeMs bounds how long after the origin the last stamp may be; nil is [verify.RunMaxAgeMs].
	RunMaxAgeMs *int64
	// CallMaxAgeMs bounds how long after the last stamp the origin may be; nil is [verify.CallMaxAgeMs].
	CallMaxAgeMs *int64
	// Extensions is the offline verifier's extension settings: check 9b carries only the names its list allows,
	// when one is set, and the hand-over holds the extensions it acts on. Check 9c never runs offline. The zero
	// value acts on none and carries any name.
	Extensions verify.Extensions
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
//  0. POLICY_EXPIRED, unless some keyring and some root count for the record: their notAfter is no
//     earlier than its recorded time, Recorded.Last, or they have no window. For a record with no
//     recorded time every member with a well-formed window counts, and check 7 refuses the record;
//  1. CHAIN_MISSING, unless the chain reads from its token;
//  2. BAD_ORIGIN, unless the origin is an allowed origin;
//  3. BAD_SIGNATURE, then BROKEN_LINK, unless each stamp in turn is signed under one of the keys the keyrings
//     that count give its service and links to the one before;
//  4. BINDING_MISMATCH, unless each stamp's rcv addresses the next stamp's svc, by name or as svc#operation,
//     and the last's is the receiver exactly;
//  5. RID_MISMATCH, unless every stamp carries the record's rid, the origin's when it gives none;
//  6. SESSION_UNKNOWN, unless every stamp carries the Config's session;
//  7. TIME_MISMATCH, unless the record gives a time and the last stamp's ts is it and, when the run's
//     records give start times, the origin's ts is one of them; then EXPIRED, if the last stamp is more
//     than RunMaxAgeMs after the origin or the origin more than CallMaxAgeMs after the last stamp, each
//     limit its live default when not set; then PROMPT_MISMATCH, unless there is a recorded prompt and the
//     origin binds it;
//  8. BINDING_MISMATCH, unless the last stamp binds the expected binding;
//  9. the blocks: 9a, EXTENSION_MISMATCH, unless they read, one per stamp, each committing to its stamp's
//     ext; then 9b, EXTENSION_NOT_ALLOWED, if a block holds a name the Config's settings do not carry;
//  11. REPLAY, unless there is a nonce key and the record set has not spent it; only then does the record
//     set spend it;
//  12. PATH_NOT_ALLOWED, unless the proof proves the route against a root that counts, with its rootId.
//
// This is verification.md's offline order: check 0 runs against no clock, the record's own time standing in for
// one; check 9c is live only, since a record does not hold the actsOn it was checked against live; and there is
// no check 10, since a record has no peer. On OK the Result's HandOver holds, verified, one entry per stamp for
// each extension the settings act on. OK and PATH_NOT_ALLOWED name the last stamp's svc and inst, as the live
// verifier's do with no peer; every other result names no one, and POLICY_EXPIRED spends no key. Verify never
// panics, and a malformed input is a result.
func (rs *RecordSet) Verify(in Input, cfg Config) verify.Result {
	return result(rs.check(in, cfg))
}

// ItemCheck is an extension's reading of the items a verified recorded call hands over (verification.md, Offline
// verification): reason.OK when they read, and otherwise the extension's code, such as INFLUENCE_MISMATCH. The
// core reads no item, so an extension that acts offline passes its own; nil reads none.
type ItemCheck func(h *verify.HandOver) reason.Code

// Call verifies in, a call recorded in the session s, as Verify does, and judges it in its session. A
// session that is not attested at all gives no result and false, and the call is neither verified nor
// spends its key: the spec gives a call relying on such a session no result, so the record set's reader
// reports it. Otherwise Call runs the offline order once, spending the key as Verify does, and returns its
// result and true. Once the offline order gives OK, and before the call is held to the session's limits,
// items reads the items the call hands over, as verification.md's Offline verification orders it: a code
// other than OK it returns is the result, naming no one and handing nothing over, so a call past the limits
// whose items do not read gets the extension's code; a nil items reads none. Then a call that verifies, OK,
// while the session is not attested at its last stamp's ts, which the client signed, is OUTSIDE_SESSION,
// naming no one: the call was made past one of the session's limits. Call judges the chain in the session s
// names, whatever cfg.Sess holds: it is cfg with Sess set to s.Sess().
func (rs *RecordSet) Call(in Input, cfg Config, s RecordedSession, items ItemCheck) (verify.Result, bool) {
	if !s.Attested() {
		return verify.Result{}, false
	}
	cfg.Sess = s.Sess()
	code, last, h := rs.check(in, cfg)
	if code == reason.OK && items != nil {
		if read := items(h); read != reason.OK {
			return verify.Result{Reason: read}, true
		}
	}
	if code == reason.OK && !s.AttestedAt(last.TS) {
		return verify.Result{Reason: reason.OutsideSession}, true
	}
	return result(code, last, h), true
}

// result names the party the spec names for code: the last stamp for OK and PATH_NOT_ALLOWED, and no one
// otherwise; it carries h, the hand-over, which check gives only with OK.
func result(code reason.Code, last stamp.Stamp, h *verify.HandOver) verify.Result {
	r := verify.Result{Reason: code, HandOver: h}
	if code == reason.OK || code == reason.PathNotAllowed {
		r.SuspectSvc, r.SuspectInst = last.Svc, last.Inst
	}
	return r
}

// check runs the offline order, checks 0 to 12 less 9c and 10, and returns the first code that fails, or OK
// with the hand-over, with the chain's last stamp once the chain has read.
func (rs *RecordSet) check(in Input, cfg Config) (reason.Code, stamp.Stamp, *verify.HandOver) {
	// 0. The keyrings and roots that count at the record's own time, judged once; none of either names no
	// one and spends no key.
	keyrings, roots := counting(cfg, in.Recorded)
	if len(keyrings) == 0 || len(roots) == 0 {
		return reason.PolicyExpired, stamp.Stamp{}, nil
	}

	// 1. The chain reads.
	if in.Chain == nil {
		return reason.ChainMissing, stamp.Stamp{}, nil
	}
	c, code := stamp.ReadChain(*in.Chain)
	if code != reason.OK {
		return code, stamp.Stamp{}, nil
	}
	origin, last := c[0], c[len(c)-1]

	// 2-6. The origin, signatures and links, receivers, rid and session.
	if code := chaincheck.Stamps(c, keyrings, cfg.AllowedOrigins, cfg.Sess, in.Receiver, in.RID); code != reason.OK {
		return code, last, nil
	}

	// 7. In place of freshness: the recorded times, the age limits, then the prompt.
	if !atRecordedTimes(in.Recorded, origin.TS, last.TS) {
		return reason.TimeMismatch, last, nil
	}
	if !withinAge(origin.TS, last.TS, cfg.RunMaxAgeMs, cfg.CallMaxAgeMs) {
		return reason.Expired, last, nil
	}
	if !bindsPrompt(origin, in.Prompt) {
		return reason.PromptMismatch, last, nil
	}

	// 8. The binding.
	if code := chaincheck.Binding(last, in.ExpectedBind); code != reason.OK {
		return code, last, nil
	}

	// 9a-9b. The blocks; 9c is live only.
	ext := cfg.Extensions
	bs, code := chaincheck.Blocks(c, in.Blocks, ext.Carries, ext.ActsOnName, false)
	if code != reason.OK {
		return code, last, nil
	}

	// 11. Replay across the whole record set. A chain with no nonce key can't be shown unspent.
	if in.NonceKey == nil || rs.spent[*in.NonceKey] {
		return reason.Replay, last, nil
	}
	if rs.spent == nil {
		rs.spent = map[string]bool{}
	}
	rs.spent[*in.NonceKey] = true

	// 12. The route, against the roots that count for the record.
	if code := chaincheck.Route(c, in.ReceiverInRoute, in.Proof, roots); code != reason.OK {
		return code, last, nil
	}
	return reason.OK, last, verify.NewHandOver(true, c, bs, ext)
}

// counting returns the keys of cfg's keyrings and the roots that count for a record with the recorded
// times t, in their order: those whose window holds t.Last. A record with no recorded time is judged
// before every window, so that every member with a well-formed one counts and check 7 refuses the record.
func counting(cfg Config, t *RecordedTimes) ([]policy.Keyring, []chaincheck.Root) {
	at := int64(math.MinInt64)
	if t != nil {
		at = t.Last
	}
	var keyrings []policy.Keyring
	for _, k := range cfg.Keyrings {
		if chaincheck.Current(k.NotAfter, at) {
			keyrings = append(keyrings, k.Keys)
		}
	}
	var roots []chaincheck.Root
	for _, r := range cfg.Roots {
		if chaincheck.Current(r.NotAfter, at) {
			roots = append(roots, chaincheck.Root{Bytes: r.Root, RootID: r.RootID})
		}
	}
	return keyrings, roots
}

// atRecordedTimes reports whether the origin's and the last stamp's ts are the times t records: the last
// stamp's is t.Last, and the origin's is one of t.Run when the run gives start times. With no recorded
// times there is nothing to match, so they are not the times.
func atRecordedTimes(t *RecordedTimes, origin, last int64) bool {
	if t == nil {
		return false
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
// after the origin, and the origin at most call after the last. A nil limit is its live default, each on
// its own. A difference too large for an int64 is compared exactly, never wrapped.
func withinAge(origin, last int64, run, call *int64) bool {
	runMax, callMax := int64(verify.RunMaxAgeMs), int64(verify.CallMaxAgeMs)
	if run != nil {
		runMax = *run
	}
	if call != nil {
		callMax = *call
	}
	return exact.AtMost(last, origin, runMax) && exact.AtMost(origin, last, callMax)
}
