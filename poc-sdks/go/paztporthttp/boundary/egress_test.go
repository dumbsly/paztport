// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package boundary_test

import (
	"bytes"
	"errors"
	"maps"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/boundary"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
)

// A call's body, and the refusal that drops a session.
var (
	charge         = []byte(`{"charge":100}`)
	sessionUnknown = []byte(`{"reason":"SESSION_UNKNOWN"}`)
	ok200          = scriptedAnswer{status: 200, body: []byte(`{"ok":true}`)}
)

// fixture is the first egress case's egress and the request its receiver accepted, with a clock the test
// moves and a partner scripted by the test.
type fixture struct {
	cfg     boundary.Config
	e       *boundary.Egress
	a       paztporthttp.Accepted
	clock   *atomic.Int64
	partner *scriptedPartner
}

// newFixture returns the fixture with a partner scripted with handshakes, replacement and calls.
func newFixture(t testing.TB, handshakes []string, replacement string, calls ...scriptedAnswer) *fixture {
	t.Helper()
	c := vectors.Rules(t).Get("egress").Index(0)
	in := c.Get("inbound")
	clock := &atomic.Int64{}
	clock.Store(in.Get("now").Int())
	cfg := egressConfig(t, c.Get("egress"), clock.Load)
	e, err := boundary.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &fixture{
		cfg: cfg, e: e, a: acceptInbound(t, in), clock: clock,
		partner: newScriptedPartner(t, c.Get("egress").Get("material").Str(), clock.Load(), handshakes, replacement,
			calls...),
	}
}

// run drives the exchange x, whose first step is step, answering each step from the partner, and returns
// its outcome.
func (f *fixture) run(t testing.TB, x *boundary.Exchange, step boundary.Step) boundary.Outcome {
	t.Helper()
	for more := true; more; {
		status, body := f.partner.serve(t, step)
		var err error
		step, more, err = x.Answer(status, body)
		if err != nil {
			t.Fatalf("Answer: %v", err)
		}
	}
	out, done := x.Result()
	if !done {
		t.Fatal("Result: the exchange has not ended")
	}
	return out
}

// post begins a call of charge to /charge under infl and runs it to its end.
func (f *fixture) post(t testing.TB, infl []influence.Entry) boundary.Outcome {
	t.Helper()
	x, step, err := f.e.Begin(f.a, infl, "/charge", charge)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return f.run(t, x, step)
}

// begin begins a call of charge to /charge under the request's own influence.
func (f *fixture) begin(t testing.TB) (*boundary.Exchange, boundary.Step) {
	t.Helper()
	x, step, err := f.e.Begin(f.a, f.a.Influence, "/charge", charge)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return x, step
}

// fixStamperClock remakes the fixture's egress with a stamper whose clock stays at the fixture's start, so
// that the egress's own clock can go where no stamp's time may.
func (f *fixture) fixStamperClock(t testing.TB) {
	t.Helper()
	start := f.clock.Load()
	s := *f.cfg.Stamper
	s.Now = func() int64 { return start }
	f.cfg.Stamper = &s
	e, err := boundary.New(f.cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.e = e
}

// header returns the value of step's header called name, or "" when it has none.
func header(step boundary.Step, name string) string {
	for _, h := range step.Headers {
		if h.Name == name {
			return h.Value
		}
	}
	return ""
}

// TestBeginRefusesWithoutAVerifiedChain: a request whose chain did not pass the live order at this hop
// makes the egress sign and send nothing, the handshake included.
func TestBeginRefusesWithoutAVerifiedChain(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	if !f.a.Verified || len(f.a.Inbound) == 0 {
		t.Fatal("the fixture's request did not verify")
	}
	for name, a := range map[string]paztporthttp.Accepted{
		"the zero Accepted":            {},
		"a chain that did not verify":  {Inbound: f.a.Inbound, Influence: f.a.Influence},
		"verified with no chain":       {Verified: true, Influence: f.a.Influence},
		"verified with an empty chain": {Verified: true, Inbound: stamp.Chain{}, Influence: f.a.Influence},
	} {
		x, step, err := f.e.Begin(a, a.Influence, "/charge", charge)
		if !errors.Is(err, boundary.ErrNotVerified) || x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
			t.Errorf("Begin with %s = %v, %+v, %v; want ErrNotVerified and nothing to send", name, x, step, err)
		}
	}
	if got := f.partner.render(t); len(got) != 0 {
		t.Fatalf("the partner received %q", got)
	}
	// The request the receiver verified begins with the handshake.
	if _, step := f.begin(t); step.Path != wire.SessionPath {
		t.Fatalf("Begin with the verified request gave a step to %q, want the handshake", step.Path)
	}
}

// TestHandshakeRequests: the full request presents the egress's own material and a fresh nonce, and the
// replacement the same with no root and another nonce.
func TestHandshakeRequests(t *testing.T) {
	f := newFixture(t, nil, "unsafe")
	x, full := f.begin(t)
	replacement, more, err := x.Answer(404, nil)
	if err != nil || !more {
		t.Fatalf("Answer(404) = %v, %v; want the replacement", more, err)
	}
	if full.Path != wire.SessionPath || replacement.Path != wire.SessionPath {
		t.Fatalf("the handshakes go to %q and %q", full.Path, replacement.Path)
	}
	for _, s := range []boundary.Step{full, replacement} {
		if !s.Handshake {
			t.Fatal("a handshake's step does not say it is one")
		}
		if len(s.Headers) != 1 || s.Headers[0] != (wire.Header{Name: "Content-Type", Value: wire.ContentType}) {
			t.Fatalf("a handshake's headers are %+v", s.Headers)
		}
		if s.Originals != nil || s.Sent != nil {
			t.Fatal("a handshake carries originals or a sent list")
		}
	}
	req, err := session.ParseRequest(full.Body)
	if err != nil {
		t.Fatalf("the full request: %v", err)
	}
	rep, err := session.ParseRequest(replacement.Body)
	if err != nil {
		t.Fatalf("the replacement: %v", err)
	}
	if req.ClientRoot == nil || *req.ClientRoot != f.cfg.Root || rep.ClientRoot != nil {
		t.Fatalf("the roots presented are %+v and %+v", req.ClientRoot, rep.ClientRoot)
	}
	for _, r := range []session.Request{req, rep} {
		if r.ClientPolicyKey != f.cfg.PolicyKey || !reflect.DeepEqual(r.KeyringFile(), f.cfg.Keyring) ||
			!session.OpensSession(r) {
			t.Fatalf("a handshake presents %+v", r)
		}
	}
	if req.Nonce == rep.Nonce {
		t.Fatal("the replacement reuses the full request's nonce")
	}
}

// TestAttestedCallStep: in an attested session the call's step carries the originals, normalised, and the
// blinded entries sent, so the embedder can keep them before it sends; the stamp commits to the entries
// sent. In an unsafe session it carries neither.
func TestAttestedCallStep(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	// Out of order and with a duplicate, so that normalising changes it.
	page := influence.Entry{Class: influence.ThirdParty, Src: "web:example.com", H: "h-page"}
	infl := slices.Concat([]influence.Entry{
		{Class: influence.ThirdParty, Src: "web:example.org", H: "h-page-2"}, page,
	}, f.a.Influence, []influence.Entry{page})
	x, step, err := f.e.Begin(f.a, infl, "/charge", charge)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	step, more, err := x.Answer(f.partner.serve(t, step))
	if err != nil || !more {
		t.Fatalf("Answer = %v, %v; want the call", more, err)
	}
	if normalised := influence.Normalise(infl); len(normalised) != 4 || !slices.Equal(step.Originals, normalised) {
		t.Fatalf("Originals = %+v, want the influence normalised", step.Originals)
	}
	want, err := influence.Reduce(infl, f.cfg.BoundaryKey, f.a.Inbound[0].RID, "psp", "payment")
	if err != nil {
		t.Fatalf("Reduce: %v", err)
	}
	if len(want) != 3 || !slices.Equal(step.Sent, want) {
		t.Fatalf("Sent = %+v, want %+v", step.Sent, want)
	}
	sent, err := influence.ReadEntries(header(step, wire.Influence))
	if err != nil || !slices.Equal(sent, step.Sent) {
		t.Fatalf("the influence header holds %+v, %v; want the entries sent", sent, err)
	}
	chain, code := stamp.ReadChain(header(step, wire.Chain))
	commit, err := influence.Commit(step.Sent)
	if code != reason.OK || err != nil || len(chain) != 1 || chain[0].Infl != commit ||
		chain[0].Sess != header(step, wire.Session) {
		t.Fatalf("the boundary stamp is %+v, want one committing to the entries sent in the session", chain)
	}
	if out := f.run(t, x, step); !out.Attested {
		t.Fatal("the call was not attested")
	}

	// With no influence the stamp commits to none, infl "", and the call carries no influence header.
	n := newFixture(t, []string{"attested"}, "unsafe", ok200)
	x, step, err = n.e.Begin(n.a, nil, "/charge", charge)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	step, _, err = x.Answer(n.partner.serve(t, step))
	if err != nil || step.Handshake {
		t.Fatalf("Answer = %+v, %v; want the call", step, err)
	}
	chain, code = stamp.ReadChain(header(step, wire.Chain))
	if code != reason.OK || len(chain) != 1 || chain[0].Infl != "" ||
		len(step.Sent) != 0 || len(step.Originals) != 0 {
		t.Fatalf("the boundary stamp is %+v (%s) and the step sends %+v; want infl \"\" and no entries",
			chain, code, step.Sent)
	}
	for _, h := range step.Headers {
		if h.Name == wire.Influence {
			t.Fatalf("a call with no influence carries the header %+v", h)
		}
	}

	u := newFixture(t, []string{"unsafe"}, "unsafe", ok200)
	x, step = u.begin(t)
	step, _, err = x.Answer(u.partner.serve(t, step))
	if err != nil || step.Originals != nil || step.Sent != nil || header(step, wire.Session) == "" {
		t.Fatalf("an unsafe call's step is %+v, %v; want the session id and no entries", step, err)
	}
}

// TestReplySessionIDForm: a reply's sess goes in X-Path-Session only when it is canonical base64url of
// 32 bytes, the form every session id has. The full handshake's check derives the id, so a reply with
// any other sess is followed by the replacement; the replacement's reply is trusted for its id alone, so
// there only the form stops it, and any other fails the exchange with nothing of the call sent.
func TestReplySessionIDForm(t *testing.T) {
	id := b64.Encode(bytes.Repeat([]byte{0x5A}, 32))
	std := strings.NewReplacer("-", "+", "_", "/").Replace(b64.Encode(bytes.Repeat([]byte{0xFB, 0xFF}, 16)))
	for name, sess := range map[string]string{
		"empty":                 "",
		"31 bytes":              b64.Encode(make([]byte, 31)),
		"33 bytes":              b64.Encode(make([]byte, 33)),
		"the standard alphabet": std,
		"padded":                id + "=",
		"non-zero unused bits":  id[:len(id)-1] + "x",
		"a space after":         id + " ",
		"a header's line break": id + "\r\nX-Other: 1",
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, []string{"unsafe"}, "unsafe", ok200)
			f.partner.sessFor = func(string) string { return sess }
			out := f.post(t, f.a.Influence)
			if !out.Failed || !slices.Equal(out.Influence, f.a.Influence) {
				t.Fatalf("the exchange ended %+v, want failed with the influence unchanged", out)
			}
			want := []string{"handshake clientRoot=true", "handshake clientRoot=false"}
			if got := f.partner.render(t); !slices.Equal(got, want) {
				t.Fatalf("the partner received %q, want the handshakes alone", got)
			}
		})
	}

	// An id of the form is taken from the replacement's reply, though it is not the one the handshake
	// derives: that reply is the partner's word for the id, and only the form is the egress's to check.
	f := newFixture(t, []string{"unsafe"}, "unsafe", ok200)
	issued := []string{"abc", id}
	f.partner.sessFor = func(string) string {
		sess := issued[0]
		issued = issued[1:]
		return sess
	}
	if out := f.post(t, f.a.Influence); out.Failed || out.Status != 200 || out.Attested {
		t.Fatalf("the exchange ended %+v, want answered unsafe", out)
	}
	if got := f.partner.render(t); len(got) != 3 || !strings.Contains(got[2], "session=1 ") {
		t.Fatalf("the partner received %q, want the call in the replacement's session", got)
	}
}

// TestIdleSession: a session no call has used for IdleMs is dropped and the next call opens another; one
// used within it is kept, and its idle period starts again.
func TestIdleSession(t *testing.T) {
	f := newFixture(t, []string{"attested", "attested"}, "unsafe", ok200, ok200, ok200)
	start := f.clock.Load()
	f.post(t, f.a.Influence)
	f.clock.Store(start + f.cfg.IdleMs - 1)
	if _, step := f.begin(t); step.Path != "/charge" {
		t.Fatalf("a call 1 ms inside the idle period opened a session: %q", step.Path)
	}
	// That call used the session, so the period starts again from it.
	f.clock.Store(start + 2*f.cfg.IdleMs - 2)
	x, step := f.begin(t)
	if step.Path != "/charge" {
		t.Fatalf("a call 1 ms inside the renewed idle period opened a session: %q", step.Path)
	}
	f.run(t, x, step)
	f.clock.Store(start + 3*f.cfg.IdleMs - 2)
	if _, step := f.begin(t); step.Path != wire.SessionPath {
		t.Fatalf("a call after the idle period went in the old session: %q", step.Path)
	}
}

// TestIdleSessionClockExtremes: the idle period is computed exactly, so a clock that jumps across the
// range of an int64 neither keeps a session it should drop nor drops one it should keep.
func TestIdleSessionClockExtremes(t *testing.T) {
	// A clock gone far back has not aged the session: now - lastUsed is below every limit.
	f := newFixture(t, []string{"attested"}, "unsafe", ok200, ok200)
	f.fixStamperClock(t)
	f.post(t, f.a.Influence)
	f.clock.Store(math.MinInt64)
	if _, step := f.begin(t); step.Path != "/charge" {
		t.Fatalf("a clock gone back dropped the session: %q", step.Path)
	}

	// A session used near the bottom of the range is idle at the top: now - lastUsed is above every limit.
	g := newFixture(t, []string{"attested", "attested"}, "unsafe", ok200)
	g.fixStamperClock(t)
	g.clock.Store(math.MinInt64 + 1)
	g.post(t, g.a.Influence)
	g.clock.Store(math.MaxInt64)
	if _, step := g.begin(t); step.Path != wire.SessionPath {
		t.Fatalf("a session idle for the whole range was kept: %q", step.Path)
	}
}

// TestSessionUnknown: only a 403 whose body reads as the refusal SESSION_UNKNOWN, exactly
// {"reason":"SESSION_UNKNOWN"} as wire bytes, drops the session; the next call opens another.
func TestSessionUnknown(t *testing.T) {
	const bs = "\\"
	for name, c := range map[string]struct {
		answer scriptedAnswer
		drops  bool
	}{
		"403 SESSION_UNKNOWN":         {scriptedAnswer{403, sessionUnknown}, true},
		"403 with a newline after":    {scriptedAnswer{403, append(bytes.Clone(sessionUnknown), '\n')}, false},
		"403 with a space inside":     {scriptedAnswer{403, []byte(`{ "reason":"SESSION_UNKNOWN"}`)}, false},
		"403 with another member":     {scriptedAnswer{403, []byte(`{"reason":"SESSION_UNKNOWN","x":1}`)}, false},
		"403 with the code escaped":   {scriptedAnswer{403, []byte(`{"reason":"SESSION` + bs + `u005fUNKNOWN"}`)}, false},
		"403 in lower case":           {scriptedAnswer{403, []byte(`{"reason":"session_unknown"}`)}, false},
		"403 as an error":             {scriptedAnswer{403, []byte(`{"error":"SESSION_UNKNOWN"}`)}, false},
		"403 as an array":             {scriptedAnswer{403, []byte(`{"reason":["SESSION_UNKNOWN"]}`)}, false},
		"403 as a bare string":        {scriptedAnswer{403, []byte(`"SESSION_UNKNOWN"`)}, false},
		"403 with no body":            {scriptedAnswer{403, nil}, false},
		"403 POLICY_EXPIRED":          {scriptedAnswer{403, []byte(`{"reason":"POLICY_EXPIRED"}`)}, false},
		"200 with SESSION_UNKNOWN":    {scriptedAnswer{200, sessionUnknown}, false},
		"401 with SESSION_UNKNOWN":    {scriptedAnswer{401, sessionUnknown}, false},
		"404 with SESSION_UNKNOWN":    {scriptedAnswer{404, sessionUnknown}, false},
		"400 INFLUENCE_MISMATCH":      {scriptedAnswer{400, []byte(`{"reason":"INFLUENCE_MISMATCH"}`)}, false},
		"403 UNSAFE_SESSION":          {scriptedAnswer{403, []byte(`{"reason":"UNSAFE_SESSION"}`)}, false},
		"403 SESSION_UNKNOWN, padded": {scriptedAnswer{403, []byte(`{"reason":"SESSION_UNKNOWN "}`)}, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, []string{"attested"}, "unsafe", c.answer)
			out := f.post(t, f.a.Influence)
			if out.Status != c.answer.status || !bytes.Equal(out.Body, c.answer.body) || !out.Attested {
				t.Fatalf("the exchange ended %+v, want the partner's answer, attested", out)
			}
			_, step := f.begin(t)
			if dropped := step.Path == wire.SessionPath; dropped != c.drops {
				t.Fatalf("the next call's step goes to %q; want the session dropped: %v", step.Path, c.drops)
			}
		})
	}
}

// TestSessionUnknownDropsOnlyItsOwnSession: a SESSION_UNKNOWN drops the session the refused call was made
// in, never one opened since.
func TestSessionUnknownDropsOnlyItsOwnSession(t *testing.T) {
	refused := scriptedAnswer{403, sessionUnknown}
	f := newFixture(t, []string{"attested", "attested"}, "unsafe", refused, ok200, refused, ok200)
	// A opens the first session and holds its call.
	a, step := f.begin(t)
	aCall, _, err := a.Answer(f.partner.serve(t, step))
	if err != nil || aCall.Path != "/charge" {
		t.Fatalf("A's call: %+v, %v", aCall, err)
	}
	// B's call in it is refused, which drops it; C opens the second.
	if out := f.post(t, f.a.Influence); out.Status != 403 {
		t.Fatalf("B ended %+v", out)
	}
	c, step := f.begin(t)
	cCall, _, err := c.Answer(f.partner.serve(t, step))
	if err != nil || !step.Handshake || cCall.Handshake {
		t.Fatalf("C's call: %+v, %v; want it after a handshake", cCall, err)
	}
	if out := f.run(t, c, cCall); out.Status != 200 {
		t.Fatalf("C ended %+v", out)
	}
	// A's call is refused too, but the session it was made in is already gone.
	if out := f.run(t, a, aCall); out.Status != 403 {
		t.Fatalf("A ended %+v", out)
	}
	_, next := f.begin(t)
	aSess, cSess := header(aCall, wire.Session), header(cCall, wire.Session)
	if got := header(next, wire.Session); next.Handshake || aSess == cSess || got != cSess {
		t.Fatalf("A's refusal dropped the session C opened: the next step is %+v", next)
	}
}

// TestLastSessionKept: two exchanges that find no session each open one, and each makes its call in its
// own; the session that lands last is the one later calls share.
func TestLastSessionKept(t *testing.T) {
	f := newFixture(t, []string{"attested", "attested"}, "unsafe", ok200, ok200)
	a, aStep := f.begin(t)
	b, bStep := f.begin(t)
	if aStep.Path != wire.SessionPath || bStep.Path != wire.SessionPath {
		t.Fatalf("the exchanges begin with steps to %q and %q, want two handshakes", aStep.Path, bStep.Path)
	}
	aCall, _, err := a.Answer(f.partner.serve(t, aStep))
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	bCall, _, err := b.Answer(f.partner.serve(t, bStep))
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	aSess, bSess := header(aCall, wire.Session), header(bCall, wire.Session)
	if aSess == "" || aSess == bSess {
		t.Fatalf("A's call is in %q and B's in %q, want each in its own", aSess, bSess)
	}
	_, next := f.begin(t)
	if got := header(next, wire.Session); next.Path != "/charge" || got != bSess {
		t.Fatalf("the next call goes to %q in %q, want B's session %q", next.Path, got, bSess)
	}
}

// TestHandshakeStatus: only a 200 counts as a handshake's answer, whatever its body. The full handshake
// answered otherwise, even with a genuine reply, is followed by the replacement; the replacement answered
// otherwise, even with a genuine reply, fails the exchange with nothing of the call sent.
func TestHandshakeStatus(t *testing.T) {
	for _, status := range []int{201, 204, 404, 500, 503} {
		f := newFixture(t, []string{"attested"}, "unsafe")
		x, step := f.begin(t)
		_, genuine := f.partner.serve(t, step)
		replacement, more, err := x.Answer(status, genuine)
		if err != nil || !more || !replacement.Handshake {
			t.Fatalf("the full handshake answered %d with a genuine reply gave %+v, %v, %v; want the replacement",
				status, replacement, more, err)
		}
		if req, err := session.ParseRequest(replacement.Body); err != nil || req.ClientRoot != nil {
			t.Fatalf("the step after a %d is %+v, %v; want the replacement", status, req, err)
		}
		_, genuine = f.partner.serve(t, replacement)
		if step, more, err := x.Answer(status, genuine); err != nil || more || step.Path != "" {
			t.Fatalf("the replacement answered %d with a genuine reply gave %+v, %v, %v; want the end",
				status, step, more, err)
		}
		if out, _ := x.Result(); !out.Failed {
			t.Fatalf("the replacement answered %d: the exchange ended %+v, want failed", status, out)
		}
		want := []string{"handshake clientRoot=true", "handshake clientRoot=false"}
		if got := f.partner.render(t); !slices.Equal(got, want) {
			t.Fatalf("the partner received %q, want the handshakes alone", got)
		}
	}
}

// TestBeginRefusesUnstampable: a call whose influence cannot be blinded, or that cannot be stamped, is
// refused by Begin with nothing to send, whether no session, an attested one or an unsafe one is open.
func TestBeginRefusesUnstampable(t *testing.T) {
	notUTF8 := string([]byte{0xFF})
	badInfl := []influence.Entry{{Class: influence.ThirdParty, Src: "web:" + notUTF8, H: "h"}}
	for _, open := range []string{"", "attested", "unsafe"} {
		handshakes := []string{"attested"}
		if open != "" {
			handshakes = []string{open}
		}
		f := newFixture(t, handshakes, "unsafe", ok200)
		// The stamper keeps its own clock, so that it can leave a stamp's range while the egress's stays.
		stampClock := &atomic.Int64{}
		stampClock.Store(f.clock.Load())
		st := *f.cfg.Stamper
		st.Now = stampClock.Load
		f.cfg.Stamper = &st
		e, err := boundary.New(f.cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		f.e = e
		if open != "" {
			if out := f.post(t, f.a.Influence); out.Attested != (open == "attested") {
				t.Fatalf("session %q: the first call went out Attested %v", open, out.Attested)
			}
		}
		before := len(f.partner.render(t))
		x, step, err := f.e.Begin(f.a, badInfl, "/charge", charge)
		if err == nil || x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
			t.Errorf("session %q: Begin with influence that cannot be blinded = %v, %+v, %v; want a refusal",
				open, x, step, err)
		}
		// A stamper that cannot sign: a request id holding "|", which no stamp may carry.
		a := f.a
		a.Inbound = slices.Clone(a.Inbound)
		a.Inbound[0].RID = "rid|1"
		x, step, err = f.e.Begin(a, nil, "/charge", charge)
		if err == nil || x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
			t.Errorf("session %q: Begin with a call that cannot be stamped = %v, %+v, %v; want a refusal",
				open, x, step, err)
		}
		// A stamper whose clock has left the range a stamp's time may hold.
		stampClock.Store(math.MaxInt64)
		x, step, err = f.e.Begin(f.a, f.a.Influence, "/charge", charge)
		if err == nil || x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
			t.Errorf("session %q: Begin with a stamper's clock out of range = %v, %+v, %v; want a refusal",
				open, x, step, err)
		}
		if got := f.partner.render(t); len(got) != before {
			t.Errorf("session %q: the partner received %q", open, got[before:])
		}
	}
}

// TestCallToTheSessionPath: a call whose path is the handshake's endpoint is still a call, and its step
// says so.
func TestCallToTheSessionPath(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	x, step, err := f.e.Begin(f.a, f.a.Influence, wire.SessionPath, charge)
	if err != nil || !step.Handshake {
		t.Fatalf("Begin = %+v, %v; want the handshake", step, err)
	}
	call, more, err := x.Answer(f.partner.serve(t, step))
	if err != nil || !more || call.Handshake || call.Path != wire.SessionPath || header(call, wire.Chain) == "" {
		t.Fatalf("the call is %+v, %v; want a stamped call to the session path, not a handshake", call, err)
	}
}

// TestNoAnswer: a handshake with no answer is followed by the replacement, and a replacement with none
// fails the exchange; a call is not the egress's to retry, so it has no NoAnswer.
func TestNoAnswer(t *testing.T) {
	f := newFixture(t, nil, "unsafe", ok200)
	x, _ := f.begin(t)
	step, more, err := x.NoAnswer()
	if err != nil || !more || step.Path != wire.SessionPath {
		t.Fatalf("NoAnswer to the handshake = %+v, %v, %v; want the replacement", step, more, err)
	}
	if req, err := session.ParseRequest(step.Body); err != nil || req.ClientRoot != nil {
		t.Fatalf("the step after NoAnswer is %+v, %v; want the replacement", req, err)
	}
	if step, more, err := x.NoAnswer(); err != nil || more || step.Path != "" {
		t.Fatalf("NoAnswer to the replacement = %+v, %v, %v; want the exchange ended", step, more, err)
	}
	if out, done := x.Result(); !done || !out.Failed || !slices.Equal(out.Influence, f.a.Influence) {
		t.Fatalf("Result = %+v, %v; want failed with the influence unchanged", out, done)
	}

	g := newFixture(t, nil, "unsafe", ok200, ok200)
	x, step = g.begin(t)
	step, _, err = x.NoAnswer()
	if err != nil {
		t.Fatalf("NoAnswer: %v", err)
	}
	call, _, err := x.Answer(g.partner.serve(t, step))
	if err != nil || call.Path != "/charge" {
		t.Fatalf("the call after the replacement: %+v, %v", call, err)
	}
	if _, _, err := x.NoAnswer(); !errors.Is(err, boundary.ErrCallUnanswered) {
		t.Fatalf("NoAnswer to a call = %v, want ErrCallUnanswered", err)
	}
	if _, done := x.Result(); done {
		t.Fatal("NoAnswer to a call ended the exchange")
	}
	// The call may have reached the partner, so its session is kept.
	if _, step := g.begin(t); step.Path != "/charge" {
		t.Fatalf("the session was dropped: the next step goes to %q", step.Path)
	}
}

// TestFinishedExchange: an exchange that has ended takes no more answers, and its outcome stays.
func TestFinishedExchange(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	x, step := f.begin(t)
	out := f.run(t, x, step)
	if _, _, err := x.Answer(200, nil); err == nil {
		t.Error("Answer after the end was taken")
	}
	if _, _, err := x.NoAnswer(); err == nil {
		t.Error("NoAnswer after the end was taken")
	}
	if again, done := x.Result(); !done || !reflect.DeepEqual(again, out) {
		t.Errorf("Result after more answers = %+v, %v; want %+v", again, done, out)
	}
	// Each Result is the caller's own: editing one edits no other.
	out.Influence[0].H, out.Body[0] = "edited", 'X'
	if again, _ := x.Result(); again.Influence[0].H == "edited" || again.Body[0] == 'X' {
		t.Error("two Results share their influence or body")
	}
	var zero boundary.Exchange
	if _, done := zero.Result(); done {
		t.Error("the zero Exchange has ended")
	}
	if _, more, err := zero.Answer(200, nil); err == nil || more {
		t.Error("the zero Exchange took an answer")
	}
	if _, more, err := zero.NoAnswer(); err == nil || more {
		t.Error("the zero Exchange took NoAnswer")
	}
}

// TestOutcomeInfluence: the outcome's influence is the request's, the partner's answer joined as one
// local-untrusted entry, and the caller's slice is never written, its spare capacity included.
func TestOutcomeInfluence(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	spare := influence.Entry{Class: influence.Public, Src: "spare", H: "spare"}
	backing := slices.Repeat([]influence.Entry{spare}, len(f.a.Influence)+4)
	infl := backing[:copy(backing, f.a.Influence)]
	before := slices.Clone(backing)
	out := f.post(t, infl)
	want := slices.Concat(f.a.Influence, []influence.Entry{{
		Class: influence.LocalUntrusted, Src: "http:psp", H: wire.ResultHash(ok200.status, ok200.body),
	}})
	if !slices.Equal(out.Influence, want) {
		t.Fatalf("Influence = %+v, want %+v", out.Influence, want)
	}
	if !slices.Equal(backing, before) {
		t.Fatal("the exchange wrote to the caller's slice")
	}
	out.Influence[0].H = "changed"
	if infl[0].H == "changed" {
		t.Fatal("the outcome's influence shares the caller's array")
	}
}

// TestOutcomeInfluenceAsGiven keeps the influence Begin was given as it was given, out of normalised order and
// with a duplicate, and joins the partner's answer after it.
func TestOutcomeInfluenceAsGiven(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	web := influence.Entry{Class: influence.ThirdParty, Src: "web:z", H: "h-2"}
	catalogue := influence.Entry{Class: influence.Public, Src: "http:catalogue", H: "h-1"}
	infl := []influence.Entry{web, catalogue, web}
	if slices.Equal(influence.Normalise(infl), infl) {
		t.Fatal("the influence is already normalised")
	}
	out := f.post(t, infl)
	want := slices.Concat(infl, []influence.Entry{{
		Class: influence.LocalUntrusted, Src: "http:psp", H: wire.ResultHash(ok200.status, ok200.body),
	}})
	if !slices.Equal(out.Influence, want) {
		t.Fatalf("Influence = %+v, want %+v", out.Influence, want)
	}
}

// TestOwnMaterialExpired: an attested session is dropped once the root or the keyring the egress presented
// has passed its notAfter, whichever is earlier, and the next call opens a new session, which is unsafe and
// kept; at the notAfter itself the attested session is kept.
func TestOwnMaterialExpired(t *testing.T) {
	m := vectors.RulesMaterial(t, vectors.Rules(t).Get("egress").Index(0).Get("egress").Get("material").Str())
	policyKey, _ := vectors.RulesKey(t, m.PolicyKey)
	for _, earlier := range []string{"root", "keyring"} {
		t.Run(earlier, func(t *testing.T) {
			f := newFixture(t, []string{"attested", "unsafe"}, "unsafe", ok200, ok200, ok200)
			start := f.clock.Load()
			soon, later := start+10, start+20
			rootAt, ringAt := soon, later
			if earlier == "keyring" {
				rootAt, ringAt = later, soon
			}
			b, err := f.cfg.Root.Bytes()
			if err != nil {
				t.Fatalf("Bytes: %v", err)
			}
			if f.cfg.Root, err = policy.SignRoot(b, f.cfg.Root.RootID, rootAt, policyKey); err != nil {
				t.Fatalf("SignRoot: %v", err)
			}
			kf := f.cfg.Keyring
			if f.cfg.Keyring, err = policy.SignKeyring(kf.Services, kf.Policy, ringAt, policyKey); err != nil {
				t.Fatalf("SignKeyring: %v", err)
			}
			if f.e, err = boundary.New(f.cfg); err != nil {
				t.Fatalf("New: %v", err)
			}
			if out := f.post(t, f.a.Influence); !out.Attested {
				t.Fatal("the first call did not go out attested")
			}
			f.clock.Store(soon)
			x, step := f.begin(t)
			if step.Handshake {
				t.Fatalf("at the %s's notAfter, the call opened a new session", earlier)
			}
			f.run(t, x, step)
			f.clock.Store(soon + 1)
			x, step = f.begin(t)
			if !step.Handshake {
				t.Fatalf("past the %s's notAfter, the call went in the attested session", earlier)
			}
			if out := f.run(t, x, step); out.Attested {
				t.Fatal("past the material's notAfter, a call went out attested")
			}
			// The unsafe session opened in its place is kept.
			f.clock.Store(soon + 2)
			if _, step = f.begin(t); step.Handshake {
				t.Fatal("past the material's notAfter, the unsafe session was dropped")
			}
		})
	}
}

// TestConfigCopied: New keeps its own copy of the material it reads, the boundary key, the stamper, the
// keyring and the route's proof, so a caller that changes or reuses its own changes nothing an exchange
// sends.
func TestConfigCopied(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	want, err := influence.Reduce(f.a.Influence, f.cfg.BoundaryKey, f.a.Inbound[0].RID, "psp", "payment")
	if err != nil {
		t.Fatalf("Reduce: %v", err)
	}
	keyring := f.cfg.Keyring
	keyring.Services = maps.Clone(keyring.Services)
	route := policy.JoinRoute("payment", "psp")
	proof, ok := f.cfg.Bundle.ProofFor(route)
	if !ok {
		t.Fatal("the fixture's bundle has no proof for the route")
	}
	wantProof, err := wire.EncodeProof(proof)
	if err != nil {
		t.Fatalf("EncodeProof: %v", err)
	}
	f.cfg.BoundaryKey[0] ^= 0xFF
	f.cfg.Stamper.Inst = "changed"
	f.cfg.Keyring.Services["payment"] = "changed"
	proof.LeafSalt[0] ^= 0xFF
	proof.Siblings[0][0] ^= 0xFF
	delete(f.cfg.Bundle.Proofs, route)

	x, step := f.begin(t)
	req, err := session.ParseRequest(step.Body)
	if err != nil || !reflect.DeepEqual(req.KeyringFile(), keyring) {
		t.Fatalf("the handshake presents %+v, %v; want the keyring New was given", req.KeyringFile(), err)
	}
	step, _, err = x.Answer(f.partner.serve(t, step))
	if err != nil || !slices.Equal(step.Sent, want) {
		t.Fatalf("the entries sent are %+v, %v; want those under the key New was given", step.Sent, err)
	}
	if got := header(step, wire.Proof); got != wantProof {
		t.Fatalf("the call's proof is %q, want the one New was given", got)
	}
	chain, code := stamp.ReadChain(header(step, wire.Chain))
	if code != reason.OK || len(chain) != 1 || chain[0].Inst != "pay-1" {
		t.Fatalf("the boundary stamp is %+v (%s), want one signed as New was given", chain, code)
	}
}

// TestNewRefuses: New refuses a configuration that lacks what the egress needs.
func TestNewRefuses(t *testing.T) {
	good := newFixture(t, nil, "unsafe").cfg
	for name, mutate := range map[string]func(*boundary.Config){
		"no stamper":            func(c *boundary.Config) { c.Stamper = nil },
		"an unnamed egress":     func(c *boundary.Config) { s := *c.Stamper; s.Svc = ""; c.Stamper = &s },
		"no partner":            func(c *boundary.Config) { c.Partner = "" },
		"no partner policy key": func(c *boundary.Config) { c.PartnerPolicyKey = "" },
		"no own policy key":     func(c *boundary.Config) { c.PolicyKey = "" },
		"a 31-byte key":         func(c *boundary.Config) { c.BoundaryKey = c.BoundaryKey[:31] },
		"a 33-byte key":         func(c *boundary.Config) { c.BoundaryKey = append(bytes.Clone(c.BoundaryKey), 0) },
		"no key":                func(c *boundary.Config) { c.BoundaryKey = nil },
		"a zero idle period":    func(c *boundary.Config) { c.IdleMs = 0 },
		"a negative idle":       func(c *boundary.Config) { c.IdleMs = -1 },
		"no clock":              func(c *boundary.Config) { c.Now = nil },
	} {
		cfg := good
		mutate(&cfg)
		if e, err := boundary.New(cfg); err == nil || e != nil || !strings.HasPrefix(err.Error(), "paztport boundary: ") {
			t.Errorf("New with %s = %v, %v; want a refusal", name, e, err)
		}
	}
	// The bundle must be the egress's and hold the proof for <egress>/<partner>, which every attested call
	// sends: the refusal names the field.
	route := policy.JoinRoute("payment", "psp")
	for name, mutate := range map[string]func(*boundary.Config){
		"another service's bundle": func(c *boundary.Config) { c.Bundle.Service = "orders" },
		"no bundle":                func(c *boundary.Config) { c.Bundle = policy.ProofBundle{} },
		"no proof for the route": func(c *boundary.Config) {
			c.Bundle.Proofs = maps.Clone(c.Bundle.Proofs)
			delete(c.Bundle.Proofs, route)
		},
		"a partner the bundle has no route to": func(c *boundary.Config) { c.Partner = "elsewhere" },
	} {
		cfg := good
		mutate(&cfg)
		if e, err := boundary.New(cfg); err == nil || e != nil || !strings.Contains(err.Error(), "Config.Bundle") {
			t.Errorf("New with %s = %v, %v; want a refusal naming Config.Bundle", name, e, err)
		}
	}
	if _, err := boundary.New(good); err != nil {
		t.Fatalf("New: %v", err)
	}
}

// TestConcurrentExchanges runs many exchanges at once on one egress: each ends answered and attested in a
// session some handshake opened. Under -race it shows the session state is guarded.
func TestConcurrentExchanges(t *testing.T) {
	const n = 32
	answers := slices.Repeat([]scriptedAnswer{ok200}, n)
	f := newFixture(t, slices.Repeat([]string{"attested"}, n), "unsafe", answers...)
	var wg sync.WaitGroup
	outs := make([]boundary.Outcome, n)
	for i := range n {
		wg.Go(func() {
			x, step, err := f.e.Begin(f.a, f.a.Influence, "/charge", charge)
			if err != nil {
				t.Errorf("Begin: %v", err)
				return
			}
			outs[i] = f.run(t, x, step)
		})
	}
	wg.Wait()
	for i, out := range outs {
		if out.Status != 200 || !out.Attested {
			t.Fatalf("exchange %d ended %+v", i, out)
		}
	}
	handshakes, calls := 0, 0
	for _, r := range f.partner.render(t) {
		switch {
		case strings.HasPrefix(r, "handshake"):
			handshakes++
		case strings.Contains(r, "session=null"):
			t.Fatalf("a call is in no session a handshake opened: %s", r)
		default:
			calls++
		}
	}
	if calls != n || handshakes < 1 || handshakes > n {
		t.Fatalf("the partner received %d handshakes and %d calls", handshakes, calls)
	}
}
