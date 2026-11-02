// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package offline_test

import (
	"bytes"
	"math"
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/offline"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// The fixture's times: the origin's ts, and the last stamp's.
const (
	start int64 = 1767225598500
	end   int64 = 1767225599500
)

const prompt = "refund order 7"

func ptr[T any](v T) *T { return &v }

// setup is one recorded chain, the offline verifier's Config for it and the record set it is verified in.
// The fixture is the mesh policy of v3.json: gateway, then orders, calling payment, in a run started with
// prompt, in a record set that has spent nothing.
type setup struct {
	stamps  []stamp.Stamp                 // nil for no chain
	pre     []func(i int, s *stamp.Stamp) // before signing, once prev links to the stamp before
	post    []func(i int, s *stamp.Stamp) // after signing
	wire    func([]byte) []byte           // on the chain's wire bytes, if set
	cfg     offline.Config
	in      offline.Input
	records *offline.RecordSet
}

// mesh returns the fixture's setup, which verifies OK.
func mesh(t testing.TB) *setup {
	t.Helper()
	p := vectors.Load(t, "v3.json").Get("policies").Get("mesh")
	root, err := b64.Decode(p.Get("root").Str())
	if err != nil {
		t.Fatal(err)
	}
	bind, err := stamp.PromptBinding(prompt)
	if err != nil {
		t.Fatal(err)
	}
	return &setup{
		stamps: []stamp.Stamp{
			{Svc: "gateway", Inst: "gw-1", RID: "rid-1", TS: start, Rcv: "orders", Bind: bind},
			{Svc: "orders", Inst: "ord-1", RID: "rid-1", TS: end, Rcv: "payment", Bind: "bind-1"},
		},
		cfg: offline.Config{
			Keyring:        policy.Keyring{"gateway": pub(t, "gateway"), "orders": pub(t, "orders")},
			Root:           root,
			RootID:         p.Get("rootId").Str(),
			AllowedOrigins: []string{"gateway"},
			RunMaxAgeMs:    ptr[int64](verify.RunMaxAgeMs),
			CallMaxAgeMs:   ptr[int64](verify.CallMaxAgeMs),
		},
		in: offline.Input{
			ExpectedBind:    ptr("bind-1"),
			Proof:           ptr(p.Get("proofTokens").Get("gateway/orders/payment").Str()),
			Receiver:        "payment",
			ReceiverInRoute: true,
			NonceKey:        ptr("rid-1|orders|req"),
			Recorded:        &offline.RecordedTimes{Last: end, RunGiven: true, Run: []int64{start - 7, start}},
			Prompt:          ptr(prompt),
		},
		records: new(offline.RecordSet), // the zero RecordSet is an empty one
	}
}

func pub(t testing.TB, name string) []byte {
	t.Helper()
	_, pub := vectors.V3Key(t, name)
	return pub
}

// edit changes stamp i before it is signed.
func (s *setup) edit(i int, f func(*stamp.Stamp)) {
	s.pre = append(s.pre, func(j int, st *stamp.Stamp) {
		if j == i {
			f(st)
		}
	})
}

// tamper changes stamp i after it is signed.
func (s *setup) tamper(i int, f func(*stamp.Stamp)) {
	s.post = append(s.post, func(j int, st *stamp.Stamp) {
		if j == i {
			f(st)
		}
	})
}

// times signs the origin at origin and the last stamp at last, and records them so.
func (s *setup) times(origin, last int64) {
	s.edit(0, func(st *stamp.Stamp) { st.TS = origin })
	s.edit(1, func(st *stamp.Stamp) { st.TS = last })
	s.in.Recorded = &offline.RecordedTimes{Last: last, RunGiven: true, Run: []int64{origin}}
}

// token signs the setup's stamps, each with its own service's key, and returns the chain's token.
func (s *setup) token(t testing.TB) string {
	t.Helper()
	c := make(stamp.Chain, len(s.stamps))
	for i, st := range s.stamps {
		if i > 0 {
			st.Prev = c[i-1].Sig
		}
		for _, f := range s.pre {
			f(i, &st)
		}
		priv, _ := vectors.V3Key(t, s.stamps[i].Svc)
		signed, err := stamp.Sign(st, priv)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		for _, f := range s.post {
			f(i, &signed)
		}
		c[i] = signed
	}
	b, err := c.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if s.wire != nil {
		b = s.wire(b)
	}
	return b64.Encode(b)
}

// run verifies the setup's recorded chain once.
func (s *setup) run(t *testing.T) verify.Result {
	t.Helper()
	in := s.in
	if s.stamps != nil {
		in.Chain = ptr(s.token(t))
	}
	return s.records.Verify(in, s.cfg)
}

// named returns the result the spec names for code: the last stamp for OK and PATH_NOT_ALLOWED, and no
// one otherwise.
func named(code reason.Code) verify.Result {
	r := verify.Result{Reason: code}
	if code == reason.OK || code == reason.PathNotAllowed {
		r.SuspectSvc, r.SuspectInst = "orders", "ord-1"
	}
	return r
}

// A fault breaks one check of the offline order.
type fault struct {
	name string
	code reason.Code
	make func(*setup)
}

// faults are one or more for each check of the offline order, in its order.
var faults = []fault{
	{"no chain", reason.ChainMissing, func(s *setup) { s.stamps = nil }},
	{"an empty chain token", reason.ChainMissing, func(s *setup) {
		s.stamps = nil
		s.in.Chain = ptr("")
	}},
	{"a delimiter in rcv", reason.BadSignature, func(s *setup) {
		s.wire = func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"rcv":"payment"`), []byte(`"rcv":"pay|ment"`), 1)
		}
	}},
	{"an origin not allowed", reason.BadOrigin, func(s *setup) { s.cfg.AllowedOrigins = []string{"orders"} }},
	{"a bad signature", reason.BadSignature, func(s *setup) { s.tamper(1, func(st *stamp.Stamp) { st.Inst = "ord-2" }) }},
	{"no key for a signer", reason.BadSignature, func(s *setup) { delete(s.cfg.Keyring, "orders") }},
	{"a broken link", reason.BrokenLink, func(s *setup) { s.edit(1, func(st *stamp.Stamp) { st.Prev = "AAAA" }) }},
	{"an inner rcv for another hop", reason.BindingMismatch, func(s *setup) {
		s.edit(0, func(st *stamp.Stamp) { st.Rcv = "payment" })
	}},
	{"a chain for another receiver", reason.BindingMismatch, func(s *setup) { s.in.Receiver = "billing" }},
	{"another rid", reason.RIDMismatch, func(s *setup) { s.edit(1, func(st *stamp.Stamp) { st.RID = "rid-2" }) }},
	{"filed under another rid", reason.RIDMismatch, func(s *setup) { s.in.RID = ptr("rid-2") }},
	{"another session", reason.SessionUnknown, func(s *setup) { s.cfg.Sess = "sess-1" }},
	{"another recorded time", reason.TimeMismatch, func(s *setup) { s.in.Recorded.Last = end + 1 }},
	{"an origin not among the run's start times", reason.TimeMismatch, func(s *setup) {
		s.in.Recorded.Run = []int64{start - 1, start + 1}
	}},
	{"a run that gives no start times", reason.TimeMismatch, func(s *setup) { s.in.Recorded.Run = nil }},
	{"a last stamp past the run's age", reason.Expired, func(s *setup) { s.cfg.RunMaxAgeMs = ptr(end - start - 1) }},
	{"an origin past the call window after the last stamp", reason.Expired, func(s *setup) {
		s.times(end, start)
		s.cfg.CallMaxAgeMs = ptr(end - start - 1)
	}},
	{"a run limit alone", reason.Expired, func(s *setup) { s.cfg.CallMaxAgeMs = nil }},
	{"a call limit alone", reason.Expired, func(s *setup) { s.cfg.RunMaxAgeMs = nil }},
	{"another prompt", reason.PromptMismatch, func(s *setup) { s.in.Prompt = ptr("refund order 8") }},
	{"no prompt", reason.PromptMismatch, func(s *setup) { s.in.Prompt = nil }},
	{"a prompt that is not UTF-8", reason.PromptMismatch, func(s *setup) { s.in.Prompt = ptr(prompt + "\xff") }},
	{"a prompt that is not UTF-8, and an origin binding nothing", reason.PromptMismatch, func(s *setup) {
		s.edit(0, func(st *stamp.Stamp) { st.Bind = "" })
		s.in.Prompt = ptr("\xff")
	}},
	{"another binding", reason.BindingMismatch, func(s *setup) { s.in.ExpectedBind = ptr("bind-0") }},
	{"no expected binding", reason.BindingMismatch, func(s *setup) { s.in.ExpectedBind = nil }},
	{"an empty influence token", reason.InfluenceMismatch, func(s *setup) { s.in.Influence = ptr("") }},
	{"no nonce key", reason.Replay, func(s *setup) { s.in.NonceKey = nil }},
	{"a key spent in the record set", reason.Replay, func(s *setup) {
		s.records = offline.NewRecordSet("rid-1|orders|req")
	}},
	{"no proof", reason.PathNotAllowed, func(s *setup) { s.in.Proof = nil }},
	{"a route the proof does not prove", reason.PathNotAllowed, func(s *setup) { s.in.ReceiverInRoute = false }},
	{"a proof for another tree", reason.PathNotAllowed, func(s *setup) { s.cfg.RootID = "v0" }},
}

// TestOK pins the fixture: it verifies, and names its last signer.
func TestOK(t *testing.T) {
	if got, want := mesh(t).run(t), named(reason.OK); got != want {
		t.Fatalf("Verify = %+v, want %+v", got, want)
	}
}

// TestEachCheck breaks each check alone, and expects its code and the spec's naming: only OK and
// PATH_NOT_ALLOWED name the last stamp.
func TestEachCheck(t *testing.T) {
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			s := mesh(t)
			f.make(s)
			if got, want := s.run(t), named(f.code); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	}
}

// TestOrder breaks two adjacent checks of the offline order at once, for each pair, and expects the first.
// Check 7's three parts are pinned in their own order: the recorded times, the age limits, the prompt.
func TestOrder(t *testing.T) {
	byName := map[string]fault{}
	for _, f := range faults {
		byName[f.name] = f
	}
	pairs := [][2]string{
		{"a delimiter in rcv", "an origin not allowed"},
		{"an origin not allowed", "a bad signature"},
		{"a bad signature", "an inner rcv for another hop"},
		{"a broken link", "a chain for another receiver"},
		{"an inner rcv for another hop", "another rid"},
		{"a chain for another receiver", "filed under another rid"},
		{"filed under another rid", "another session"},
		{"another session", "another recorded time"},
		{"another session", "a run limit alone"},
		{"another recorded time", "a last stamp past the run's age"},
		{"an origin not among the run's start times", "a call limit alone"},
		{"a last stamp past the run's age", "another prompt"},
		{"a run limit alone", "no prompt"},
		{"another recorded time", "another prompt"},
		{"another prompt", "another binding"},
		{"no prompt", "an empty influence token"},
		{"another binding", "an empty influence token"},
		{"an empty influence token", "no nonce key"},
		{"an empty influence token", "a key spent in the record set"},
		{"no nonce key", "no proof"},
		{"a key spent in the record set", "a proof for another tree"},
	}
	for _, p := range pairs {
		first, second := byName[p[0]], byName[p[1]]
		if first.make == nil || second.make == nil {
			t.Fatalf("no fault named %q or %q", p[0], p[1])
		}
		t.Run(p[0]+", then "+p[1], func(t *testing.T) {
			s := mesh(t)
			second.make(s)
			first.make(s)
			if got, want := s.run(t), named(first.code); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	}
}

// TestRecordedTimes pins what check 7 compares: with no recorded times, no time; with no start times, only
// the last stamp's. Start times are given when RunGiven says so or Run holds any, so that neither a run
// whose records give none nor a flag left unset compares nothing.
func TestRecordedTimes(t *testing.T) {
	type times = offline.RecordedTimes
	tests := []struct {
		name     string
		recorded *offline.RecordedTimes
		code     reason.Code
	}{
		{"none", nil, reason.OK},
		{"the last stamp's, and no start times", &times{Last: end}, reason.OK},
		{"another last, and no start times", &times{Last: start}, reason.TimeMismatch},
		{"the origin's as the last", &times{Last: start, RunGiven: true, Run: []int64{start}}, reason.TimeMismatch},
		{"the origin's, one of several", &times{Last: end, RunGiven: true, Run: []int64{1, start, 2}}, reason.OK},
		{"start times given, none of them", &times{Last: end, RunGiven: true}, reason.TimeMismatch},
		{"start times given, an empty list", &times{Last: end, RunGiven: true, Run: []int64{}}, reason.TimeMismatch},
		{"no start times, an empty list", &times{Last: end, Run: []int64{}}, reason.OK},
		{"start times not flagged, the origin's among them", &times{Last: end, Run: []int64{start}}, reason.OK},
		{"start times not flagged, the origin's not among them", &times{Last: end, Run: []int64{start + 1}},
			reason.TimeMismatch},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.in.Recorded = tt.recorded
			if got := s.run(t); got != named(tt.code) {
				t.Fatalf("Verify = %+v, want %s", got, tt.code)
			}
		})
	}
}

// TestAgeLimits pins check 7's age limits at their bounds, and leaves the age unlimited with neither.
func TestAgeLimits(t *testing.T) {
	tests := []struct {
		name         string
		origin, last int64
		run, call    *int64
		code         reason.Code
	}{
		{"the last stamp at the run's age", start, end, ptr(end - start), ptr[int64](0), reason.OK},
		{"the last stamp past the run's age", start, end, ptr(end - start - 1), ptr[int64](0), reason.Expired},
		{"the origin at the call window after the last", end, start, ptr[int64](0), ptr(end - start), reason.OK},
		{"the origin past the call window", end, start, ptr[int64](0), ptr(end - start - 1), reason.Expired},
		{"the origin and the last stamp at once", start, start, ptr[int64](0), ptr[int64](0), reason.OK},
		{"no limits, a run of years", 0, json.MaxSafe, nil, nil, reason.OK},
		{"no limits, an origin years after", json.MaxSafe, 0, nil, nil, reason.OK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.times(tt.origin, tt.last)
			s.cfg.RunMaxAgeMs, s.cfg.CallMaxAgeMs = tt.run, tt.call
			if got := s.run(t); got != named(tt.code) {
				t.Fatalf("Verify = %+v, want %s", got, tt.code)
			}
		})
	}
}

// TestExtremeTimes holds check 7 to times and limits at the ends of int64: no difference wraps, so none
// passes a check it fails exactly. A recorded time no stamp can carry is TIME_MISMATCH, which comes before
// the age limits; limits below every difference are EXPIRED; limits above every difference hold.
func TestExtremeTimes(t *testing.T) {
	tests := []struct {
		name         string
		origin, last int64
		recorded     *offline.RecordedTimes
		run, call    int64
		code         reason.Code
	}{
		{"a recorded time of 2^63 - 1", 0, 1, &offline.RecordedTimes{Last: math.MaxInt64}, 1, 1, reason.TimeMismatch},
		{"a recorded time of -2^63", 0, 1, &offline.RecordedTimes{Last: math.MinInt64}, 1, 1, reason.TimeMismatch},
		{"a start time of -2^63", 0, 1, &offline.RecordedTimes{Last: 1, Run: []int64{math.MinInt64}}, 1, 1,
			reason.TimeMismatch},
		{"a run limit of -2^63", 0, json.MaxSafe, nil, math.MinInt64, math.MaxInt64, reason.Expired},
		{"a call limit of -2^63", 0, json.MaxSafe, nil, math.MaxInt64, math.MinInt64, reason.Expired},
		{"a call limit of -2^63, the origin last", json.MaxSafe, 0, nil, math.MaxInt64, math.MinInt64, reason.Expired},
		{"a run limit of -2^63, the origin last", json.MaxSafe, 0, nil, math.MinInt64, math.MaxInt64, reason.Expired},
		{"limits of 2^63 - 1", 0, json.MaxSafe, nil, math.MaxInt64, math.MaxInt64, reason.OK},
		{"limits of 2^63 - 1, the origin last", json.MaxSafe, 0, nil, math.MaxInt64, math.MaxInt64, reason.OK},
		{"the widest run, one short", 0, json.MaxSafe, nil, json.MaxSafe - 1, 0, reason.Expired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := mesh(t)
			s.times(tt.origin, tt.last)
			s.in.Recorded = tt.recorded
			s.cfg.RunMaxAgeMs, s.cfg.CallMaxAgeMs = ptr(tt.run), ptr(tt.call)
			if got := s.run(t); got != named(tt.code) {
				t.Fatalf("Verify = %+v, want %s", got, tt.code)
			}
		})
	}
}

// TestRID pins check 5's rid: the one the record files the chain under, or the origin's when it gives none.
func TestRID(t *testing.T) {
	for _, rid := range []*string{nil, ptr("rid-1")} {
		s := mesh(t)
		s.in.RID = rid
		if got := s.run(t); got != named(reason.OK) {
			t.Fatalf("RID %v: Verify = %+v, want OK", rid, got)
		}
	}
	s := mesh(t)
	s.edit(0, func(st *stamp.Stamp) { st.RID = "rid-2" })
	s.edit(1, func(st *stamp.Stamp) { st.RID = "rid-2" })
	s.in.RID = ptr("rid-1")
	if got := s.run(t); got != named(reason.RIDMismatch) {
		t.Fatalf("a chain of another rid filed under rid-1: Verify = %+v, want RID_MISMATCH", got)
	}
}

// TestSpending pins check 10: a chain spends its key only once checks 1 to 9 hold, and spends it whatever
// check 11 then says; a spent key is a replay however much later its copy was recorded. Whether a fault
// spent the key shows in the record set: the fixture's own chain, verified in it next, is a replay or not.
func TestSpending(t *testing.T) {
	for _, f := range faults {
		t.Run(f.name, func(t *testing.T) {
			s := mesh(t)
			f.make(s)
			got := s.run(t).Reason
			spent := got == reason.OK || got == reason.PathNotAllowed || f.name == "a key spent in the record set"
			next := mesh(t)
			next.records = s.records
			want := named(reason.OK)
			if spent {
				want = named(reason.Replay)
			}
			if again := next.run(t); again != want {
				t.Fatalf("after %s, the fixture's chain = %+v, want %+v", got, again, want)
			}
		})
	}

	s := mesh(t)
	if got := s.run(t); got != named(reason.OK) {
		t.Fatalf("Verify = %+v, want OK", got)
	}
	s.times(start+verify.RunMaxAgeMs, end+verify.RunMaxAgeMs)
	if got := s.run(t); got != named(reason.Replay) {
		t.Fatalf("a copy recorded later: Verify = %+v, want REPLAY", got)
	}
}

// handshake returns v3.json's recordedHandshake case name: its request's and reply's bytes, its pin and
// its configured entry.
func handshake(t *testing.T, name string) (request, reply []byte, pin, entry string) {
	t.Helper()
	v3 := vectors.Load(t, "v3.json")
	found := false
	v3.Get("recordedHandshake").Each(func(n string, c vectors.Node) {
		if n != name {
			return
		}
		c = c.With(t)
		request, reply = decode(t, c.Get("requestToken").Str()), decode(t, c.Get("replyToken").Str())
		pin = v3.Get("keys").Get(c.Get("pin").Str()).Get("pub").Str()
		entry, found = c.Get("serverEntry").Str(), true
	})
	if !found {
		t.Fatalf("v3.json has no recordedHandshake case %q", name)
	}
	return request, reply, pin, entry
}

// The limit of the case "entry-key form, limited by the certificate": the certificate's notAfter.
const certNotAfter int64 = 1798761600000

// edit returns the canonical bytes of the object wire holds, its member name set to v, or taken out when v
// is nil.
func edit(t *testing.T, wire []byte, name string, v *json.Value) []byte {
	t.Helper()
	o, err := json.ReadWire(wire)
	if err != nil {
		t.Fatalf("ReadWire: %v", err)
	}
	members := slices.DeleteFunc(o.Members(), func(m json.Member) bool { return m.Name == name })
	if v != nil {
		members = append(members, json.Member{Name: name, Value: *v})
	}
	b, err := json.Wire(json.Obj(members...))
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	return b
}

// TestRecordNeverPanics records handshakes that open no attested session, from messages that do not read
// to a pin or an entry that is not the server's. It expects sessions attested at no time, a request only
// when it reads, and the response window the reply holds, 2^53 - 1 when it holds none.
func TestRecordNeverPanics(t *testing.T) {
	request, reply, pin, entry := handshake(t, "entry-key form, limited by the certificate")
	tests := []struct {
		name             string
		request, reply   []byte
		pin, entry       string
		responseNotAfter int64
	}{
		{"nothing", nil, nil, "", "", json.MaxSafe},
		{"no request", nil, reply, pin, entry, 4102444800000},
		{"a request that is null", []byte("null"), reply, pin, entry, 4102444800000},
		{"a request that is an array", []byte("[]"), reply, pin, entry, 4102444800000},
		{"no reply", request, nil, pin, entry, json.MaxSafe},
		{"a reply cut short", request, reply[:len(reply)-1], pin, entry, json.MaxSafe},
		{"a reply that is null", request, []byte("null"), pin, entry, json.MaxSafe},
		{"a reply that is a string", request, []byte(`"sess"`), pin, entry, json.MaxSafe},
		{"no pin", request, reply, "", entry, 4102444800000},
		{"a pin that is not a key", request, reply, "AAAA", entry, 4102444800000},
		{"no entry", request, reply, pin, "", 4102444800000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := offline.Record(tt.request, tt.reply, tt.pin, tt.entry)
			if s.Attested() || s.AttestedAt(certNotAfter) || s.AttestedAt(0) {
				t.Fatal("the session is attested")
			}
			if _, ok := s.Request(); ok != bytes.Equal(tt.request, request) {
				t.Fatalf("Request reads: %t, want %t", ok, !ok)
			}
			if got := s.ResponseNotAfter(); got != tt.responseNotAfter {
				t.Fatalf("ResponseNotAfter = %d, want %d", got, tt.responseNotAfter)
			}
		})
	}
}

// TestZeroRecordedSession checks that the zero RecordedSession is what Record reads when nothing was
// recorded: attested at no time, naming no session, with no request and no response window.
func TestZeroRecordedSession(t *testing.T) {
	var zero offline.RecordedSession
	nothing := offline.Record(nil, nil, "", "")
	for _, s := range []offline.RecordedSession{zero, nothing} {
		if s.Attested() || s.AttestedAt(0) || s.Sess() != "" {
			t.Fatal("the session is attested, or names a session")
		}
		if _, ok := s.Request(); ok {
			t.Fatal("the session has a request")
		}
		if got := s.ResponseNotAfter(); got != json.MaxSafe {
			t.Fatalf("ResponseNotAfter = %d, want 2^53 - 1", got)
		}
	}
}

// TestSess pins the session id: the reply's, read whether or not the session is attested, and "" when the
// reply holds no string there.
func TestSess(t *testing.T) {
	request, reply, pin, entry := handshake(t, "entry-key form, limited by the certificate")
	o, err := json.ReadWire(reply)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := json.Field(o, "sess")
	if got := offline.Record(request, reply, pin, entry).Sess(); got != id.Str() || got == "" {
		t.Fatalf("Sess = %q, want %q", got, id.Str())
	}
	unattested := offline.Record(request, reply, pin, "github-tools")
	if unattested.Attested() || unattested.Sess() != id.Str() {
		t.Fatalf("a session not attested: Sess = %q, want %q", unattested.Sess(), id.Str())
	}
	for name, r := range map[string][]byte{
		"a sess that is a number": edit(t, reply, "sess", ptr(json.I(7))),
		"no sess":                 edit(t, reply, "sess", nil),
		"a reply cut short":       reply[:len(reply)-1],
	} {
		if got := offline.Record(request, r, pin, entry).Sess(); got != "" {
			t.Fatalf("%s: Sess = %q, want none", name, got)
		}
	}
}

// TestResponseNotAfter pins the response window's leniency: it is read from the reply's value whether or
// not the reply is well formed, counts the server keyring's window only in the entry-key form, and passes
// over a window that is not an integer.
func TestResponseNotAfter(t *testing.T) {
	request, reply, pin, entry := handshake(t, "server keyring's notAfter")
	const keyringNotAfter, rootNotAfter int64 = 1767225600000, 4102444800000
	tests := []struct {
		name  string
		reply []byte
		want  int64
	}{
		{"the entry-key form", reply, keyringNotAfter},
		{"no keyring signature", edit(t, reply, "serverKeyringSig", nil), rootNotAfter},
		{"a keyring signature that is null", edit(t, reply, "serverKeyringSig", ptr(json.Null())), keyringNotAfter},
		{"a keyring window that is a string", edit(t, reply, "serverKeyringNotAfter", ptr(json.S("1"))), rootNotAfter},
		{"a server root that is null", edit(t, reply, "serverRoot", ptr(json.Null())), keyringNotAfter},
		{"neither window", edit(t, edit(t, reply, "serverRoot", ptr(json.Null())), "serverKeyringNotAfter", nil),
			json.MaxSafe},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := offline.Record(request, tt.reply, pin, entry).ResponseNotAfter(); got != tt.want {
				t.Fatalf("ResponseNotAfter = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestRecordedSessionKeepsItsOwn checks that a RecordedSession is a value: changing the bytes it was read
// from, or the request it returns, changes nothing in it.
func TestRecordedSessionKeepsItsOwn(t *testing.T) {
	request, reply, pin, entry := handshake(t, "entry-key form, limited by the certificate")
	s := offline.Record(request, reply, pin, entry)
	if !s.Attested() {
		t.Fatal("the session is not attested")
	}
	clear(reply)
	clear(request)
	req, ok := s.Request()
	if !ok || req.ClientRoot == nil || len(req.ClientKeyring) == 0 {
		t.Fatal("the session has no request, or one with no client root or keyring")
	}
	req.ClientRoot.NotAfter = 0
	clear(req.ClientKeyring)
	again, _ := s.Request()
	if again.ClientRoot.NotAfter == 0 || len(again.ClientKeyring) == 0 {
		t.Fatal("changing the request returned changed the session's")
	}
	if !s.AttestedAt(certNotAfter) || s.AttestedAt(certNotAfter+1) {
		t.Fatal("the session is no longer attested up to its limit and no further")
	}
}

// TestCall pins a recorded call's result in its session: the chain is verified once, and a call that
// verifies is OUTSIDE_SESSION, naming no one, when its last stamp's ts is past one of the session's limits.
// The time judged is the chain's own: here the origin is inside the limit and nothing else is recorded.
func TestCall(t *testing.T) {
	s := offline.Record(handshake(t, "entry-key form, limited by the certificate"))
	tests := []struct {
		name string
		make func(*setup)
		want verify.Result
	}{
		{"a call at the limit", func(c *setup) { c.times(certNotAfter-1000, certNotAfter) }, named(reason.OK)},
		{"a call past the limit", func(c *setup) {
			c.times(certNotAfter-1000, certNotAfter+1)
			c.in.Recorded = nil
		}, verify.Result{Reason: reason.OutsideSession}},
		{"a call that fails past the limit", func(c *setup) {
			c.times(certNotAfter-1000, certNotAfter+1)
			c.tamper(1, func(st *stamp.Stamp) { st.Inst = "ord-2" })
		}, named(reason.BadSignature)},
		{"a call on no allowed route past the limit", func(c *setup) {
			c.times(certNotAfter-1000, certNotAfter+1)
			c.in.Proof = nil
		}, named(reason.PathNotAllowed)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := mesh(t)
			tt.make(c)
			in := c.in
			in.Chain = ptr(c.token(t))
			got, ok := c.records.Call(in, c.cfg, s)
			if !ok || got != tt.want {
				t.Fatalf("Call = %+v, %t; want %+v", got, ok, tt.want)
			}
			// The chain was verified once: a call that reached check 10 spent its key.
			again, _ := c.records.Call(in, c.cfg, s)
			spent := tt.want.Reason != reason.BadSignature
			if spent != (again.Reason == reason.Replay) {
				t.Fatalf("the same call again = %+v; spent the first time: %t", again, spent)
			}
		})
	}
}

// TestCallInAnUnsafeSession checks that a call in a session not attested at all has no result, and is not
// verified: the record set spends nothing, so the same chain verifies afterwards.
func TestCallInAnUnsafeSession(t *testing.T) {
	unsafe := offline.Record(handshake(t, "unsafe"))
	c := mesh(t)
	in := c.in
	in.Chain = ptr(c.token(t))
	if got, ok := c.records.Call(in, c.cfg, unsafe); ok || got != (verify.Result{}) {
		t.Fatalf("Call = %+v, %t; want no result", got, ok)
	}
	if got := c.records.Verify(in, c.cfg); got != named(reason.OK) {
		t.Fatalf("Verify after Call = %+v, want OK: Call spent the key", got)
	}
}

// TestRecordSet checks that a record set holds the keys it was made with and every key its chains spend,
// and no other record set's: the zero one and a new one with no keys have spent nothing.
func TestRecordSet(t *testing.T) {
	const key = "rid-1|orders|req"
	sets := map[string]struct {
		records *offline.RecordSet
		code    reason.Code
	}{
		"the zero record set":               {new(offline.RecordSet), reason.OK},
		"a new record set":                  {offline.NewRecordSet(), reason.OK},
		"a record set made with other keys": {offline.NewRecordSet("rid-1|orders|resp", "rid-2|orders|req"), reason.OK},
		"a record set made with the key":    {offline.NewRecordSet("rid-0|gateway|req", key), reason.Replay},
	}
	for name, set := range sets {
		t.Run(name, func(t *testing.T) {
			s := mesh(t)
			s.records = set.records
			if got := s.run(t); got != named(set.code) {
				t.Fatalf("Verify = %+v, want %s", got, set.code)
			}
			if got := s.run(t); got != named(reason.Replay) {
				t.Fatalf("the same chain again: Verify = %+v, want REPLAY", got)
			}
			s.in.NonceKey = ptr("rid-1|orders|req-2")
			if got := s.run(t); got != named(reason.OK) {
				t.Fatalf("a chain with another key: Verify = %+v, want OK", got)
			}
			s.in.NonceKey = ptr(key)
			if got := s.run(t); got != named(reason.Replay) {
				t.Fatalf("the first chain after another: Verify = %+v, want REPLAY", got)
			}
			if got := mesh(t).run(t); got != named(reason.OK) {
				t.Fatalf("in another record set: Verify = %+v, want OK", got)
			}
		})
	}
}
