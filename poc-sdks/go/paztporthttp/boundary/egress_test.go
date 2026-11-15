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
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors/handover"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/boundary"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// A call's body, and the refusals that drop a session.
var (
	charge         = []byte(`{"charge":100}`)
	sessionUnknown = []byte(`{"reason":"SESSION_UNKNOWN"}`)
	policyExpired  = []byte(`{"reason":"POLICY_EXPIRED"}`)
	ok200          = scriptedAnswer{status: 200, body: []byte(`{"ok":true}`)}
)

// The egress cases whose inbound request the unit tests take, beside the first case's: in one an internal
// stamp's block does not name influence, and in the other every stamp's block names it and holds nothing.
const (
	unnamedCase = "an internal stamp whose block does not name influence: the boundary block names nothing"
	emptyCase   = "every internal stamp naming influence, with none held: the block names it with []"
)

// fixture is an egress case's egress and the request its receiver accepted, with a clock the test moves and
// a partner scripted by the test.
type fixture struct {
	cfg     boundary.Config
	e       *boundary.Egress
	a       paztporthttp.Accepted
	clock   *atomic.Int64
	partner *scriptedPartner
}

// newFixture returns the first egress case's fixture, its partner scripted with handshakes, replacement and
// calls.
func newFixture(t testing.TB, handshakes []string, replacement string, calls ...scriptedAnswer) *fixture {
	t.Helper()
	return caseFixture(t, vectors.Rules(t).Get("egress").Index(0), handshakes, replacement, calls...)
}

// namedFixture returns the fixture of the egress case called name.
func namedFixture(t testing.TB, name string, handshakes []string, replacement string,
	calls ...scriptedAnswer,
) *fixture {
	t.Helper()
	var found *vectors.Node
	vectors.Rules(t).Get("egress").Each(func(n string, c vectors.Node) {
		if n == name {
			found = &c
		}
	})
	if found == nil {
		t.Fatalf("no egress case is called %q", name)
	}
	return caseFixture(t, *found, handshakes, replacement, calls...)
}

// caseFixture returns egress case c's fixture: its egress, under its own settings and requirement, and the
// request its receiver accepted under the inbound's settings.
func caseFixture(t testing.TB, c vectors.Node, handshakes []string, replacement string,
	calls ...scriptedAnswer,
) *fixture {
	t.Helper()
	c = c.With(t)
	in := c.Get("inbound")
	clock := &atomic.Int64{}
	clock.Store(in.Get("now").Int())
	cfg := egressConfig(t, c.Get("egress"), clock.Load)
	e, err := boundary.New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	a := acceptInbound(t, in, handover.Settings(t, in.Get("actsOn").Raw(), in.Get("allowedExtensions").Raw()))
	return &fixture{
		cfg: cfg, e: e, a: a, clock: clock,
		partner: newScriptedPartner(t, c.Get("egress").Get("material").Str(), clock.Load(), handshakes, replacement,
			calls...),
	}
}

// remake remakes the fixture's egress with its configuration changed by change.
func (f *fixture) remake(t testing.TB, change func(*boundary.Config)) {
	t.Helper()
	change(&f.cfg)
	e, err := boundary.New(f.cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.e = e
}

// require remakes the fixture's egress requiring names of the partner, going on without them when
// continueWithout is true.
func (f *fixture) require(t testing.TB, names []string, continueWithout bool) {
	t.Helper()
	need, err := session.NewRequirement(names, continueWithout)
	if err != nil {
		t.Fatalf("NewRequirement: %v", err)
	}
	f.remake(t, func(c *boundary.Config) { c.Requirement = need })
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

// post begins a call of charge to /charge with what the request added at the egress, added, and runs it to
// its end.
func (f *fixture) post(t testing.TB, added []influence.Entry) boundary.Outcome {
	t.Helper()
	x, step, err := f.e.Begin(f.a, added, "/charge", charge)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return f.run(t, x, step)
}

// begin begins a call of charge to /charge, the request having added nothing at the egress.
func (f *fixture) begin(t testing.TB) (*boundary.Exchange, boundary.Step) {
	t.Helper()
	x, step, err := f.e.Begin(f.a, nil, "/charge", charge)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	return x, step
}

// call begins a call of charge to /charge with added, answers the handshake from the partner, and returns the
// exchange and the call's step.
func (f *fixture) call(t testing.TB, added []influence.Entry) (*boundary.Exchange, boundary.Step) {
	t.Helper()
	x, step, err := f.e.Begin(f.a, added, "/charge", charge)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if !step.Handshake {
		t.Fatalf("Begin gave the call %+v, want the handshake first", step)
	}
	step, more, err := x.Answer(f.partner.serve(t, step))
	if err != nil || !more || step.Handshake {
		t.Fatalf("Answer = %+v, %v, %v; want the call", step, more, err)
	}
	return x, step
}

// handedOn returns the entries the fixture's request was handed on under influence, read as the egress reads
// them.
func (f *fixture) handedOn(t testing.TB) []influence.Entry {
	t.Helper()
	stamps, ok := f.a.HandOver.Under(influence.Name)
	if !ok {
		t.Fatal("the fixture's receiver does not act on influence")
	}
	return influence.ReadRequest(stamps).Entries
}

// fixStamperClock remakes the fixture's egress with a stamper whose clock stays at the fixture's start, so
// that the egress's own clock can go where no stamp's time may.
func (f *fixture) fixStamperClock(t testing.TB) {
	t.Helper()
	start := f.clock.Load()
	s := *f.cfg.Stamper
	s.Now = func() int64 { return start }
	f.remake(t, func(c *boundary.Config) { c.Stamper = &s })
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

// headerNames returns the names of step's headers, in order.
func headerNames(step boundary.Step) []string {
	names := make([]string, len(step.Headers))
	for i, h := range step.Headers {
		names[i] = h.Name
	}
	return names
}

// stampedCall reads an attested call's step: its one boundary stamp and its one block, failing t unless the
// step carries both, the stamp in the call's session and committing to the block.
func stampedCall(t testing.TB, step boundary.Step) (stamp.Stamp, stamp.Block) {
	t.Helper()
	want := []string{"Content-Type", wire.Session, wire.Chain, wire.Proof, wire.Extensions}
	if got := headerNames(step); !slices.Equal(got, want) {
		t.Fatalf("an attested call's headers are %q, want %q", got, want)
	}
	chain, code := stamp.ReadChain(header(step, wire.Chain))
	if code != reason.OK || len(chain) != 1 {
		t.Fatalf("the call's chain is %+v (%s), want one boundary stamp", chain, code)
	}
	bs, err := stamp.ReadBlocks(header(step, wire.Extensions))
	if err != nil || len(bs) != 1 {
		t.Fatalf("the call's blocks are %d, %v; want one", len(bs), err)
	}
	if chain[0].Ext != bs[0].Commit() || chain[0].Sess != header(step, wire.Session) {
		t.Fatalf("the boundary stamp %+v does not commit to its block in the call's session", chain[0])
	}
	return chain[0], bs[0]
}

// namesNothing fails t unless block names no extension and requires nothing, and step keeps no entries.
func namesNothing(t testing.TB, block stamp.Block, step boundary.Step) {
	t.Helper()
	if len(block.Names()) != 0 || len(block.Requires()) != 0 || block.Commit() != "" {
		t.Fatalf("the boundary block is %s, want one naming nothing", block.Wire())
	}
	if step.Originals != nil || step.Sent != nil {
		t.Fatalf("the step keeps %+v and %+v, want no entries", step.Originals, step.Sent)
	}
}

// TestBeginRefusesWithoutAVerifiedChain: a request whose chain did not pass the live order at this hop
// makes the egress sign and send nothing, the handshake included.
func TestBeginRefusesWithoutAVerifiedChain(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	if !f.a.Verified || len(f.a.Inbound.Chain) == 0 {
		t.Fatal("the fixture's request did not verify")
	}
	for name, a := range map[string]paztporthttp.Accepted{
		"the zero Accepted":            {},
		"a chain that did not verify":  {Inbound: f.a.Inbound, HandOver: f.a.HandOver},
		"verified with no chain":       {Verified: true, HandOver: f.a.HandOver},
		"verified with an empty chain": {Verified: true, Inbound: paztporthttp.Inbound{Chain: stamp.Chain{}}},
	} {
		x, step, err := f.e.Begin(a, nil, "/charge", charge)
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

// TestTheBoundaryBlockHoldsTheBlindedEntries: where the egress acts on influence and every internal stamp
// names it, the boundary block names influence with the blinded entries of what the request holds, the entries
// handed on and those the service added, and the step keeps the originals, normalised, and the entries sent, so
// the embedder can keep them before it sends.
func TestTheBoundaryBlockHoldsTheBlindedEntries(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	handed := f.handedOn(t)
	if len(handed) != 2 {
		t.Fatalf("the fixture's request was handed on %+v, want two entries", handed)
	}
	// Of a class nothing handed on holds, out of order and with a duplicate, so that each source of the
	// entries shows in what is sent, and normalising changes the originals.
	page := influence.Entry{Class: influence.ThirdParty, Src: "web:example.com", H: "h-page"}
	added := []influence.Entry{{Class: influence.ThirdParty, Src: "web:example.org", H: "h-page-2"}, page, page}
	x, step := f.call(t, added)
	held := slices.Concat(handed, added)
	if want := influence.Normalise(held); len(want) != 4 || !slices.Equal(step.Originals, want) {
		t.Fatalf("Originals = %+v, want %+v", step.Originals, want)
	}
	want, err := influence.Reduce(held, f.cfg.BoundaryKey, f.a.Inbound.Chain[0].RID, "psp", "payment")
	if err != nil {
		t.Fatalf("Reduce: %v", err)
	}
	if len(want) != 3 || !slices.Equal(step.Sent, want) {
		t.Fatalf("Sent = %+v, want %+v", step.Sent, want)
	}
	_, block := stampedCall(t, step)
	wantBlock, err := influence.RequestBlock(want, nil)
	if err != nil {
		t.Fatalf("RequestBlock: %v", err)
	}
	if !bytes.Equal(block.Wire(), wantBlock.Wire()) {
		t.Fatalf("the boundary block is %s, want %s", block.Wire(), wantBlock.Wire())
	}
	if out := f.run(t, x, step); !out.Attested {
		t.Fatal("the call was not attested")
	}
}

// TestTheBoundaryBlockNamesInfluenceWithNothingHeld: where every internal stamp names influence and the
// request holds nothing, the boundary block names influence with [], and the step keeps empty lists, not
// none, since a block that names influence is one whose entries the sender may be asked to open.
func TestTheBoundaryBlockNamesInfluenceWithNothingHeld(t *testing.T) {
	f := namedFixture(t, emptyCase, []string{"attested"}, "unsafe", ok200)
	if handed := f.handedOn(t); len(handed) != 0 {
		t.Fatalf("the case's request was handed on %+v, want nothing", handed)
	}
	_, step := f.call(t, nil)
	_, block := stampedCall(t, step)
	items, named := block.Items(influence.Name)
	if !named || len(items) != 0 || !slices.Equal(block.Names(), []string{influence.Name}) {
		t.Fatalf("the boundary block is %s, want influence named with []", block.Wire())
	}
	if step.Originals == nil || len(step.Originals) != 0 || step.Sent == nil || len(step.Sent) != 0 {
		t.Fatalf("the step keeps %#v and %#v, want two empty lists", step.Originals, step.Sent)
	}
}

// TestTheBoundaryBlockNamesNothingWhenAnInternalStampDoesNot: one internal stamp whose block does not name
// influence makes the boundary block name nothing, {items: {}, requires}, whatever the request holds: no entry
// is blinded or kept, so an added entry the boundary key could not blind does not stop the call.
func TestTheBoundaryBlockNamesNothingWhenAnInternalStampDoesNot(t *testing.T) {
	f := namedFixture(t, unnamedCase, []string{"attested"}, "unsafe", ok200)
	if handed := f.handedOn(t); len(handed) != 2 {
		t.Fatalf("the case's request was handed on %+v, want two entries", handed)
	}
	unblindable := influence.Entry{Class: influence.ThirdParty, Src: "web:" + string([]byte{0xFF}), H: "h"}
	added := []influence.Entry{{Class: influence.ThirdParty, Src: "web:example.com", H: "h-page"}, unblindable}
	x, step := f.call(t, added)
	_, block := stampedCall(t, step)
	namesNothing(t, block, step)
	if out := f.run(t, x, step); !out.Attested || out.Status != 200 {
		t.Fatalf("the call ended %+v, want answered attested", out)
	}
}

// TestAnEgressNotActingOnInfluenceNamesNothing: an egress whose own settings do not act on influence names
// nothing in the boundary block, though its receiver acts on influence and every internal stamp names it.
func TestAnEgressNotActingOnInfluenceNamesNothing(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	f.remake(t, func(c *boundary.Config) { c.Extensions = verify.Extensions{} })
	if len(f.handedOn(t)) == 0 {
		t.Fatal("the fixture's request was handed on nothing")
	}
	_, step := f.call(t, []influence.Entry{{Class: influence.ThirdParty, Src: "web:example.com", H: "h-page"}})
	_, block := stampedCall(t, step)
	namesNothing(t, block, step)
}

// TestAReceiverNotActingOnInfluenceGivesABlockNamingNothing: behind a receiver whose settings do not act on
// influence, nothing says what the internal stamps' blocks name, so an egress that acts on it names nothing.
func TestAReceiverNotActingOnInfluenceGivesABlockNamingNothing(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	f.a = acceptInbound(t, vectors.Rules(t).Get("egress").Index(0).Get("inbound"), verify.Extensions{})
	if !f.a.Verified || f.a.HandOver == nil {
		t.Fatal("the receiver did not verify the request")
	}
	if _, ok := f.a.HandOver.Under(influence.Name); ok {
		t.Fatal("a receiver that does not act on influence handed it over")
	}
	_, step := f.call(t, nil)
	_, block := stampedCall(t, step)
	namesNothing(t, block, step)
}

// TestAnUnverifiedHandOverNamesNothing: the boundary block reads what the internal stamps name only from a
// verified hand-over, so an Accepted not made by Receiver.Accept, verified but carrying a hand-over that is not,
// gives a block naming nothing.
func TestAnUnverifiedHandOverNamesNothing(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	acts, err := verify.NewExtensions([]string{influence.Name})
	if err != nil {
		t.Fatalf("NewExtensions: %v", err)
	}
	h := verify.NewHandOver(false, f.a.Inbound.Chain, f.a.Inbound.Blocks, acts)
	if stamps, ok := h.Under(influence.Name); !ok || !influence.ReadRequest(stamps).EveryStampNames {
		t.Fatal("the unverified hand-over does not show every stamp naming influence")
	}
	f.a = paztporthttp.Accepted{Verified: true, Inbound: f.a.Inbound, HandOver: h}
	_, step := f.call(t, nil)
	_, block := stampedCall(t, step)
	namesNothing(t, block, step)
}

// TestAnUnsafeSessionSendsNoStampAndNoBlock: in an unsafe session the call carries the session id alone: no
// stamp, no proof, no block, and the step keeps no entries.
func TestAnUnsafeSessionSendsNoStampAndNoBlock(t *testing.T) {
	f := newFixture(t, []string{"unsafe"}, "unsafe", ok200)
	x, step := f.call(t, []influence.Entry{{Class: influence.ThirdParty, Src: "web:example.com", H: "h-page"}})
	if got := headerNames(step); !slices.Equal(got, []string{"Content-Type", wire.Session}) {
		t.Fatalf("an unsafe call's headers are %q, want the session id alone", got)
	}
	if step.Originals != nil || step.Sent != nil {
		t.Fatalf("an unsafe call's step keeps %+v and %+v", step.Originals, step.Sent)
	}
	if out := f.run(t, x, step); out.Attested || out.Status != 200 {
		t.Fatalf("the call ended %+v, want answered unsafe", out)
	}
}

// TestAnUnmetRequirementMakesNoCall: an egress that requires influence of the partner, without its switch,
// makes no call after a reply that does not list it, after an unsafe reply, or in the replacement's session,
// whether no reply could be checked or the reply failed the check: Answer gives ErrRequirementUnmet with
// nothing more to send, the exchange ends Failed with what Begin was given, and the partner receives the
// handshakes alone. A reply that fails step 5 is not followed by the replacement.
func TestAnUnmetRequirementMakesNoCall(t *testing.T) {
	for _, c := range []struct {
		name       string
		handshakes []string
		answer500  bool // the full handshake is answered 500, so no reply is checked
		received   []string
	}{
		{"EXTENSION_REQUIRED", []string{"attested"}, false, []string{"handshake clientRoot=true"}},
		{"UNSAFE", []string{"unsafe"}, false, []string{"handshake clientRoot=true"}},
		{"no reply checked", nil, true, []string{"handshake clientRoot=false"}},
		{"PIN_MISMATCH", []string{"wrongKey"}, false,
			[]string{"handshake clientRoot=true", "handshake clientRoot=false"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.handshakes, "unsafe")
			f.require(t, []string{influence.Name}, false)
			added := []influence.Entry{{Class: influence.ThirdParty, Src: "web:example.com", H: "h-page"}}
			x, step, err := f.e.Begin(f.a, added, "/charge", charge)
			if err != nil {
				t.Fatalf("Begin: %v", err)
			}
			if c.answer500 {
				if step, _, err = x.Answer(500, nil); err != nil || !step.Handshake {
					t.Fatalf("Answer(500) = %+v, %v; want the replacement", step, err)
				}
			}
			if c.name == "PIN_MISMATCH" {
				if step, _, err = x.Answer(f.partner.serve(t, step)); err != nil || !step.Handshake {
					t.Fatalf("Answer to a reply under another key = %+v, %v; want the replacement", step, err)
				}
			}
			next, more, err := x.Answer(f.partner.serve(t, step))
			if !errors.Is(err, boundary.ErrRequirementUnmet) || more || !reflect.DeepEqual(next, boundary.Step{}) {
				t.Fatalf("Answer = %+v, %v, %v; want ErrRequirementUnmet and nothing to send", next, more, err)
			}
			out, done := x.Result()
			if !done || !out.Failed || !slices.Equal(out.Influence, added) {
				t.Fatalf("Result = %+v, %v; want failed with what Begin was given", out, done)
			}
			if got := f.partner.render(t); !slices.Equal(got, c.received) {
				t.Fatalf("the partner received %q, want %q", got, c.received)
			}
		})
	}
}

// TestAReplyFailingStepFiveIsNotFollowedByTheReplacement: a reply that is attested but does not list what the
// egress requires is sound, so with the switch set the call goes in the attested session it opened, stamped,
// its block requiring nothing the reply did not list; no replacement is sent.
func TestAReplyFailingStepFiveIsNotFollowedByTheReplacement(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	f.require(t, []string{influence.Name}, true)
	x, step := f.call(t, nil)
	_, block := stampedCall(t, step)
	if len(block.Requires()) != 0 {
		t.Fatalf("the boundary block requires %q, which the reply did not list", block.Requires())
	}
	if out := f.run(t, x, step); !out.Attested || out.Status != 200 {
		t.Fatalf("the call ended %+v, want answered attested", out)
	}
	if got := f.partner.render(t); len(got) != 2 || got[0] != "handshake clientRoot=true" ||
		!strings.HasPrefix(got[1], "call ") {
		t.Fatalf("the partner received %q, want the full handshake and the call", got)
	}
}

// TestContinueWithoutCallsInAnUnsafeSessionWithNoRequires: with its switch set, an egress with a requirement
// makes its call in an unsafe session, whether the reply said unsafe or the session is the replacement's, as
// an egress with no requirement does: the session id alone.
func TestContinueWithoutCallsInAnUnsafeSessionWithNoRequires(t *testing.T) {
	for _, c := range []struct {
		name       string
		handshakes []string
		sent       int // the handshakes the partner receives before the call
	}{
		{"an unsafe reply", []string{"unsafe"}, 1},
		{"the replacement", []string{"notFound"}, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.handshakes, "unsafe", ok200)
			f.require(t, []string{influence.Name}, true)
			out := f.post(t, nil)
			if out.Failed || out.Attested || out.Status != 200 {
				t.Fatalf("the call ended %+v, want answered unsafe", out)
			}
			got := f.partner.render(t)
			if len(got) != c.sent+1 || !strings.Contains(got[c.sent], "stamps=null") ||
				!strings.Contains(got[c.sent], "blocks=null") {
				t.Fatalf("the partner received %q, want the call with the session id alone", got)
			}
		})
	}
}

// TestASessionWithNoCallIsNeverMarkedUsed: a session in which no call may be made is not marked used by a call
// that finds it, so the call after it within the idle period is refused with ErrRequirementUnmet, nothing
// sent, and the call after the idle period, counted from the handshake, opens a new session, whose reply may
// by then meet the requirement.
func TestASessionWithNoCallIsNeverMarkedUsed(t *testing.T) {
	f := newFixture(t, []string{"attested", "attested"}, "unsafe", ok200)
	f.require(t, []string{influence.Name}, false)
	start := f.clock.Load()
	x, step := f.begin(t)
	if _, _, err := x.Answer(f.partner.serve(t, step)); !errors.Is(err, boundary.ErrRequirementUnmet) {
		t.Fatalf("Answer: %v, want ErrRequirementUnmet", err)
	}
	f.clock.Store(start + f.cfg.IdleMs - 1)
	if x, step, err := f.e.Begin(f.a, nil, "/charge", charge); !errors.Is(err, boundary.ErrRequirementUnmet) ||
		x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
		t.Fatalf("Begin in the open session = %v, %+v, %v; want ErrRequirementUnmet and nothing to send", x, step, err)
	}
	if got := f.partner.render(t); len(got) != 1 {
		t.Fatalf("the partner received %q, want the one handshake", got)
	}
	// The partner now lists what the egress requires: the session's idle period, from the handshake, is over.
	f.partner.extensions = []string{influence.Name}
	f.clock.Store(start + f.cfg.IdleMs)
	if out := f.post(t, nil); out.Failed || !out.Attested || out.Status != 200 {
		t.Fatalf("the call after the idle period ended %+v, want answered attested", out)
	}
	if got := f.partner.render(t); len(got) != 3 || got[1] != "handshake clientRoot=true" {
		t.Fatalf("the partner received %q, want a second handshake and the call", got)
	}
}

// TestTheRequiresTheReplyListedTravelInTheBlock: the boundary block requires what the session lets the egress
// require: every required name after a reply that lists them all, and, with the switch, only the required names
// a reply that fails step 5 lists; an egress that requires nothing requires nothing.
func TestTheRequiresTheReplyListedTravelInTheBlock(t *testing.T) {
	two := []string{"example", influence.Name}
	for _, c := range []struct {
		name     string
		require  []string
		listed   []string
		requires []string
	}{
		{"every required name listed", two, two, two},
		{"one of two listed, with the switch", two, []string{influence.Name}, []string{influence.Name}},
		{"no requirement, the reply listing influence", nil, []string{influence.Name}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, []string{"attested"}, "unsafe", ok200)
			f.require(t, c.require, true)
			f.partner.extensions = c.listed
			_, step := f.call(t, nil)
			_, block := stampedCall(t, step)
			if got := block.Requires(); !slices.Equal(got, c.requires) {
				t.Fatalf("the boundary block requires %q, want %q", got, c.requires)
			}
			if items, named := block.Items(influence.Name); !named || len(items) != 2 {
				t.Fatalf("the boundary block is %s, want the blinded entries beside its requires", block.Wire())
			}
		})
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
			out := f.post(t, nil)
			if !out.Failed || len(out.Influence) != 0 {
				t.Fatalf("the exchange ended %+v, want failed with nothing added", out)
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
	if out := f.post(t, nil); out.Failed || out.Status != 200 || out.Attested {
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
	f.post(t, nil)
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
	f.post(t, nil)
	f.clock.Store(math.MinInt64)
	if _, step := f.begin(t); step.Path != "/charge" {
		t.Fatalf("a clock gone back dropped the session: %q", step.Path)
	}

	// A session used near the bottom of the range is idle at the top: now - lastUsed is above every limit.
	g := newFixture(t, []string{"attested", "attested"}, "unsafe", ok200)
	g.fixStamperClock(t)
	g.clock.Store(math.MinInt64 + 1)
	g.post(t, nil)
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
		"200 with SESSION_UNKNOWN":    {scriptedAnswer{200, sessionUnknown}, false},
		"401 with SESSION_UNKNOWN":    {scriptedAnswer{401, sessionUnknown}, false},
		"404 with SESSION_UNKNOWN":    {scriptedAnswer{404, sessionUnknown}, false},
		"400 INFLUENCE_MISMATCH":      {scriptedAnswer{400, []byte(`{"reason":"INFLUENCE_MISMATCH"}`)}, false},
		"403 UNSAFE_SESSION":          {scriptedAnswer{403, []byte(`{"reason":"UNSAFE_SESSION"}`)}, false},
		"403 SESSION_UNKNOWN, padded": {scriptedAnswer{403, []byte(`{"reason":"SESSION_UNKNOWN "}`)}, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, []string{"attested"}, "unsafe", c.answer)
			out := f.post(t, nil)
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

// TestPolicyExpiredDropsTheSession: a 403 whose body is exactly the refusal POLICY_EXPIRED drops the session
// the call was made in, as SESSION_UNKNOWN does, since the partner refuses every call in it once the egress's
// own material has expired; the next call handshakes. A body that is not exactly that refusal keeps it.
func TestPolicyExpiredDropsTheSession(t *testing.T) {
	for name, c := range map[string]struct {
		answer scriptedAnswer
		drops  bool
	}{
		"403 POLICY_EXPIRED":         {scriptedAnswer{403, policyExpired}, true},
		"403 with a newline after":   {scriptedAnswer{403, append(bytes.Clone(policyExpired), '\n')}, false},
		"200 with POLICY_EXPIRED":    {scriptedAnswer{200, policyExpired}, false},
		"401 with POLICY_EXPIRED":    {scriptedAnswer{401, policyExpired}, false},
		"403 POLICY_EXPIRED, padded": {scriptedAnswer{403, []byte(`{"reason":"POLICY_EXPIRED "}`)}, false},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, []string{"attested"}, "unsafe", c.answer)
			if out := f.post(t, nil); out.Status != c.answer.status || !out.Attested {
				t.Fatalf("the exchange ended %+v, want the partner's answer, attested", out)
			}
			_, step := f.begin(t)
			if dropped := step.Handshake; dropped != c.drops {
				t.Fatalf("the next call's step is %+v; want the session dropped: %v", step, c.drops)
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
	if out := f.post(t, nil); out.Status != 403 {
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

// TestBeginRefusesUnstampable: a call whose entries the boundary block would carry and the boundary key cannot
// blind, or that cannot be stamped, is refused by Begin with nothing to send, whether no session, an attested
// one or an unsafe one is open.
func TestBeginRefusesUnstampable(t *testing.T) {
	notUTF8 := string([]byte{0xFF})
	badAdded := []influence.Entry{{Class: influence.ThirdParty, Src: "web:" + notUTF8, H: "h"}}
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
		f.remake(t, func(c *boundary.Config) { c.Stamper = &st })
		if open != "" {
			if out := f.post(t, nil); out.Attested != (open == "attested") {
				t.Fatalf("session %q: the first call went out Attested %v", open, out.Attested)
			}
		}
		before := len(f.partner.render(t))
		x, step, err := f.e.Begin(f.a, badAdded, "/charge", charge)
		if err == nil || x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
			t.Errorf("session %q: Begin with entries that cannot be blinded = %v, %+v, %v; want a refusal",
				open, x, step, err)
		}
		// A stamper that cannot sign: a request id holding a noncharacter, which no stamp may carry.
		a := f.a
		a.Inbound.Chain = slices.Clone(a.Inbound.Chain)
		a.Inbound.Chain[0].RID = "rid\uffff1"
		x, step, err = f.e.Begin(a, nil, "/charge", charge)
		if err == nil || x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
			t.Errorf("session %q: Begin with a call that cannot be stamped = %v, %+v, %v; want a refusal",
				open, x, step, err)
		}
		// A stamper whose clock has left the range a stamp's time may hold.
		stampClock.Store(math.MaxInt64)
		x, step, err = f.e.Begin(f.a, nil, "/charge", charge)
		if err == nil || x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
			t.Errorf("session %q: Begin with a stamper's clock out of range = %v, %+v, %v; want a refusal",
				open, x, step, err)
		}
		if got := f.partner.render(t); len(got) != before {
			t.Errorf("session %q: the partner received %q", open, got[before:])
		}
	}
}

// TestBeginRefusesABoundaryBlockPastTheWireLimit: a call whose boundary block would pass the wire limit is
// refused by Begin with nothing to send, before any handshake; the same entries in a block that names nothing
// are never blinded, so they stop nothing.
func TestBeginRefusesABoundaryBlockPastTheWireLimit(t *testing.T) {
	// Three owners of 100 KiB each: three groups, so three blinded entries, each carrying its owner.
	var added []influence.Entry
	for _, c := range "abc" {
		owner := strings.Repeat(string(c), 100<<10)
		added = append(added, influence.Entry{Class: influence.Private, Src: "http:orders", H: "h", Owner: owner})
	}
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	x, step, err := f.e.Begin(f.a, added, "/charge", charge)
	if err == nil || x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
		t.Fatalf("Begin with a block past the wire limit = %v, %+v, %v; want a refusal", x, step, err)
	}
	if got := f.partner.render(t); len(got) != 0 {
		t.Fatalf("the partner received %q", got)
	}
	g := namedFixture(t, unnamedCase, []string{"attested"}, "unsafe", ok200)
	if out := g.post(t, added); out.Failed || !out.Attested {
		t.Fatalf("the call with a block naming nothing ended %+v, want answered attested", out)
	}
}

// TestBeginRefusesAnEmptyPath: a call with no path has no request line to bind, so it is refused with
// nothing to send, whether or not a session is open.
func TestBeginRefusesAnEmptyPath(t *testing.T) {
	for _, open := range []string{"", "attested", "unsafe"} {
		handshakes := []string{"attested"}
		if open != "" {
			handshakes = []string{open}
		}
		f := newFixture(t, handshakes, "unsafe", ok200)
		if open != "" {
			if out := f.post(t, nil); out.Attested != (open == "attested") {
				t.Fatalf("session %q: the first call went out Attested %v", open, out.Attested)
			}
		}
		before := len(f.partner.render(t))
		x, step, err := f.e.Begin(f.a, nil, "", charge)
		if err == nil || x != nil || !reflect.DeepEqual(step, boundary.Step{}) {
			t.Errorf("session %q: Begin with an empty path = %v, %+v, %v; want a refusal", open, x, step, err)
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
	x, step, err := f.e.Begin(f.a, nil, wire.SessionPath, charge)
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
	if out, done := x.Result(); !done || !out.Failed || len(out.Influence) != 0 {
		t.Fatalf("Result = %+v, %v; want failed with nothing added", out, done)
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

// TestOutcomeInfluence: the outcome's influence is what the request added at the egress, the partner's answer
// joined as one local-untrusted entry, and the caller's slice is never written, its spare capacity included.
func TestOutcomeInfluence(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	page := influence.Entry{Class: influence.ThirdParty, Src: "web:example.com", H: "h-page"}
	spare := influence.Entry{Class: influence.Public, Src: "spare", H: "spare"}
	backing := []influence.Entry{page, spare, spare, spare}
	added := backing[:1]
	before := slices.Clone(backing)
	out := f.post(t, added)
	want := []influence.Entry{page, {
		Class: influence.LocalUntrusted, Src: "http:psp", H: wire.ResultHash(ok200.status, ok200.body),
	}}
	if !slices.Equal(out.Influence, want) {
		t.Fatalf("Influence = %+v, want %+v", out.Influence, want)
	}
	if !slices.Equal(backing, before) {
		t.Fatal("the exchange wrote to the caller's slice")
	}
	out.Influence[0].H = "changed"
	if added[0].H == "changed" {
		t.Fatal("the outcome's influence shares the caller's array")
	}
}

// TestOutcomeInfluenceAsGiven keeps what Begin was given as it was given, out of normalised order and with a
// duplicate, and joins the partner's answer after it.
func TestOutcomeInfluenceAsGiven(t *testing.T) {
	f := newFixture(t, []string{"attested"}, "unsafe", ok200)
	web := influence.Entry{Class: influence.ThirdParty, Src: "web:z", H: "h-2"}
	catalogue := influence.Entry{Class: influence.Public, Src: "http:catalogue", H: "h-1"}
	added := []influence.Entry{web, catalogue, web}
	if slices.Equal(influence.Normalise(added), added) {
		t.Fatal("the entries are already normalised")
	}
	out := f.post(t, added)
	want := slices.Concat(added, []influence.Entry{{
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
			root, err := policy.SignRoot(b, f.cfg.Root.RootID, rootAt, policyKey)
			if err != nil {
				t.Fatalf("SignRoot: %v", err)
			}
			kf := f.cfg.Keyring
			ring, err := policy.SignKeyring(kf.Services, kf.Policy, ringAt, policyKey)
			if err != nil {
				t.Fatalf("SignKeyring: %v", err)
			}
			f.remake(t, func(c *boundary.Config) { c.Root, c.Keyring = root, ring })
			if out := f.post(t, nil); !out.Attested {
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
	want, err := influence.Reduce(f.handedOn(t), f.cfg.BoundaryKey, f.a.Inbound.Chain[0].RID, "psp", "payment")
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
	if err != nil || len(want) == 0 || !slices.Equal(step.Sent, want) {
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
			x, step, err := f.e.Begin(f.a, nil, "/charge", charge)
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
