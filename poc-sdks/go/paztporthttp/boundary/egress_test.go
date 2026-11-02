// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package boundary_test

import (
	"bytes"
	"errors"
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
	chain, _ := stamp.ReadChain(header(step, wire.Chain))
	commit, err := influence.Commit(step.Sent)
	if err != nil || len(chain) != 1 || chain[0].Infl != commit || chain[0].Sess != header(step, wire.Session) {
		t.Fatalf("the boundary stamp is %+v, want one committing to the entries sent in the session", chain)
	}
	if out := f.run(t, x, step); !out.Attested {
		t.Fatal("the call was not attested")
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
		"empty":                    "",
		"short text":               "abc",
		"31 bytes":                 b64.Encode(make([]byte, 31)),
		"33 bytes":                 b64.Encode(make([]byte, 33)),
		"padded":                   id + "=",
		"the standard alphabet":    std,
		"non-zero unused bits":     id[:len(id)-1] + "x",
		"a space after":            id + " ",
		"a header's line break":    id + "\r\nX-Other: 1",
		"twice the id":             id + id,
		"text that is not base64":  "not an id at all, but text",
		"a canonical 32 bytes cut": id[:42],
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
	f.cfg.Stamper.Now = func() int64 { return 1767225600000 }
	f.post(t, f.a.Influence)
	f.clock.Store(math.MinInt64)
	if _, step := f.begin(t); step.Path != "/charge" {
		t.Fatalf("a clock gone back dropped the session: %q", step.Path)
	}

	// A session used near the bottom of the range is idle at the top: now - lastUsed is above every limit.
	g := newFixture(t, []string{"attested", "attested"}, "unsafe", ok200)
	g.cfg.Stamper.Now = func() int64 { return 1767225600000 }
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
	if out := f.post(t, f.a.Influence); out.Status != 200 {
		t.Fatalf("C ended %+v", out)
	}
	// A's call is refused too, but the session it was made in is already gone.
	if out := f.run(t, a, aCall); out.Status != 403 {
		t.Fatalf("A ended %+v", out)
	}
	_, step = f.begin(t)
	if step.Path != "/charge" {
		t.Fatalf("A's refusal dropped the session C opened: the next step goes to %q", step.Path)
	}
	got := f.partner.render(t)
	if len(got) != 5 || !strings.Contains(got[4], "session=0 ") {
		t.Fatalf("the partner received %q, want A's call last, in the first session", got)
	}
	f.partner.received = append(f.partner.received, receivedStep{step: step})
	if got := f.partner.render(t); !strings.Contains(got[5], "session=2 ") {
		t.Fatalf("the next call is not in C's session: %q", got[5])
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
	if _, _, err := x.NoAnswer(); err == nil {
		t.Fatal("NoAnswer to a call was taken")
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

// TestConfigCopied: New keeps its own copy of the boundary key, so a caller that reuses its slice changes
// nothing the egress commits to.
func TestConfigCopied(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	want, err := influence.Reduce(f.a.Influence, f.cfg.BoundaryKey, f.a.Inbound[0].RID, "psp", "payment")
	if err != nil {
		t.Fatalf("Reduce: %v", err)
	}
	f.cfg.BoundaryKey[0] ^= 0xFF
	x, step := f.begin(t)
	step, _, err = x.Answer(f.partner.serve(t, step))
	if err != nil || !slices.Equal(step.Sent, want) {
		t.Fatalf("the entries sent are %+v, %v; want those under the key New was given", step.Sent, err)
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
