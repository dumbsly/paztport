// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package offline_test

import (
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/offline"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestVectors replays v3.json's offline cases: each runs the offline verifier once, in a record set that
// has already spent the case's seen keys, and expects its result. A case reads only its tokens, never the
// readable values beside them.
func TestVectors(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	cases := v3.Get("offline")
	if cases.Len() == 0 {
		t.Fatal("v3.json has no offline case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			if got, want := replay(t, v3.With(t), c), expected(c); got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	})
}

// TestVectorsReadTheOptionalArrays checks that the replay reads the keyrings and roots a case may carry,
// beside the committed cases that carry them: every offline case with one keyring, that keyring and its
// policy's root written as the arrays with no window, gives its recorded answer, with its keyring whole or split one
// service to a keyring. And each member's window is the one it gives: a record later than every keyring's
// or every root's notAfter is POLICY_EXPIRED, and one at it is not.
func TestVectorsReadTheOptionalArrays(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	v3.Get("offline").Each(func(name string, c vectors.Node) {
		if c.Has("keyrings") || c.Has("roots") {
			return // already written as arrays: TestVectors replays it
		}
		for _, split := range []bool{false, true} {
			t.Run(name+", split "+strconv.FormatBool(split), func(t *testing.T) {
				c := c.With(t)
				if got, want := replay(t, v3.With(t), asArrays(c, "", split)), expected(c); got != want {
					t.Fatalf("Verify = %+v, want %+v", got, want)
				}
			})
		}
	})
	var recorded vectors.Node
	v3.Get("offline").Each(func(name string, c vectors.Node) {
		if name == "recorded call" {
			recorded = c
		}
	})
	last := recorded.Get("recordedTs").Get("last").Int()
	at, before := strconv.FormatInt(last, 10), strconv.FormatInt(last-1, 10)
	if got := replay(t, v3, asArrays(recorded, at, true)); got.Reason != reason.OK {
		t.Errorf("under members until the record's time: Verify = %+v, want OK", got)
	}
	if got := replay(t, v3, asArrays(recorded, before, false)); got.Reason != reason.PolicyExpired {
		t.Errorf("under members until before the record: Verify = %+v, want POLICY_EXPIRED", got)
	}
	lapsed := asArrays(recorded, "", false).Rewrite([]string{"roots"},
		vectors.Member{Name: "roots", Text: `[{"policy": ` + string(recorded.Get("policy").Raw()) + `, "notAfter": ` +
			before + `}]`})
	if got := replay(t, v3, lapsed); got.Reason != reason.PolicyExpired {
		t.Errorf("under a root until before the record: Verify = %+v, want POLICY_EXPIRED", got)
	}
	elsewhere := asArrays(recorded, "", false).Rewrite([]string{"roots"},
		vectors.Member{Name: "roots", Text: `[{"policy": "server"}]`})
	if got := replay(t, v3, elsewhere); got.Reason != reason.PathNotAllowed {
		t.Errorf("under another policy's root: Verify = %+v, want PATH_NOT_ALLOWED", got)
	}
}

// replay runs case c of v3.json's offline section once, in a record set that has already spent the case's
// seen keys. A member a case gives with no window counts for every record.
func replay(t *testing.T, v3, c vectors.Node) verify.Result {
	t.Helper()
	cfg := offline.Config{
		Keyrings:       keyrings(t, c),
		Roots:          roots(t, v3, c),
		AllowedOrigins: c.Get("allowedOrigins").Strs(),
		Sess:           c.Get("sess").Str(),
		RunMaxAgeMs:    optionalInt(c.Get("runMaxAgeMs")),
		CallMaxAgeMs:   optionalInt(c.Get("callMaxAgeMs")),
	}
	p := v3.Get("policies").Get(c.Get("policy").Str())
	return offline.NewRecordSet(c.Get("seen").Strs()...).Verify(input(t, c, p), cfg)
}

// expected returns the result case c expects.
func expected(c vectors.Node) verify.Result {
	e := c.Get("expected")
	return verify.Result{
		Reason:      reason.Code(e.Get("reason").Str()),
		SuspectSvc:  e.Get("suspectSvc").Str(),
		SuspectInst: e.Get("suspectInst").Str(),
	}
}

// keyrings returns the keyrings case c pins: its keyrings, which replace keyring, each until its own
// notAfter or with no window when it gives none; otherwise its one keyring, with no window.
func keyrings(t *testing.T, c vectors.Node) []verify.PinnedKeyring {
	t.Helper()
	if !c.Has("keyrings") {
		return []verify.PinnedKeyring{{Keys: keyring(t, c.Get("keyring")), NotAfter: math.MaxInt64}}
	}
	if c.Has("keyring") {
		t.Fatal("the case gives keyrings and keyring, which keyrings replace")
	}
	var out []verify.PinnedKeyring
	c.Get("keyrings").Each(func(_ string, k vectors.Node) {
		out = append(out, verify.PinnedKeyring{Keys: keyring(t, k.Get("keyring")), NotAfter: window(k)})
	})
	return out
}

// roots returns the roots case c pins: its roots, each a policy's root until its own notAfter or with no
// window when it gives none; otherwise its policy's root, with no window. With roots, policy names only
// where the case's proof comes from.
func roots(t *testing.T, v3, c vectors.Node) []verify.PinnedRoot {
	t.Helper()
	if !c.Has("roots") {
		return []verify.PinnedRoot{pinnedRoot(t, v3, c.Get("policy").Str(), math.MaxInt64)}
	}
	var out []verify.PinnedRoot
	c.Get("roots").Each(func(_ string, r vectors.Node) {
		out = append(out, pinnedRoot(t, v3, r.Get("policy").Str(), window(r)))
	})
	return out
}

// keyring returns the keyring ring names: each service to the vector key of the name it maps to.
func keyring(t *testing.T, ring vectors.Node) policy.Keyring {
	t.Helper()
	k := policy.Keyring{}
	for _, svc := range ring.Names() {
		_, pub := vectors.V3Key(t, ring.Get(svc).Str())
		k[svc] = pub
	}
	return k
}

// pinnedRoot returns the root of v3.json's policy name, until notAfter.
func pinnedRoot(t *testing.T, v3 vectors.Node, name string, notAfter int64) verify.PinnedRoot {
	t.Helper()
	p := v3.Get("policies").Get(name)
	return verify.PinnedRoot{Root: decode(t, p.Get("root").Str()), RootID: p.Get("rootId").Str(), NotAfter: notAfter}
}

// window returns member m's notAfter, or math.MaxInt64, no window, when it gives none.
func window(m vectors.Node) int64 {
	if !m.Has("notAfter") {
		return math.MaxInt64
	}
	return m.Get("notAfter").Int()
}

// asArrays returns case c with its keyring written as keyrings, whole or split one service to a keyring,
// and its policy's root as roots, each member until notAfter, a JSON number's text, or with no window
// when it is "".
func asArrays(c vectors.Node, notAfter string, split bool) vectors.Node {
	until := ""
	if notAfter != "" {
		until = `, "notAfter": ` + notAfter
	}
	ring := c.Get("keyring")
	var parts []string
	if split {
		for _, svc := range ring.Names() {
			parts = append(parts, `{"keyring": {`+strconv.Quote(svc)+`: `+string(ring.Get(svc).Raw())+`}`+until+`}`)
		}
	} else {
		parts = append(parts, `{"keyring": `+string(ring.Raw())+until+`}`)
	}
	return c.Rewrite([]string{"keyring"},
		vectors.Member{Name: "keyrings", Text: "[" + strings.Join(parts, ", ") + "]"},
		vectors.Member{Name: "roots", Text: `[{"policy": ` + string(c.Get("policy").Raw()) + until + `}]`})
}

// TestRecordedHandshakeVectors replays v3.json's recordedHandshake cases: whether each opened an attested
// session at all and at each of its times, and the limit on a response recorded in it.
func TestRecordedHandshakeVectors(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	cases := v3.Get("recordedHandshake")
	if cases.Len() == 0 {
		t.Fatal("v3.json has no recordedHandshake case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			s := record(t, v3, c)
			e := c.Get("expected")
			if got, want := s.Attested(), e.Get("attested").Bool(); got != want {
				t.Errorf("Attested = %t, want %t", got, want)
			}
			at, want := c.Get("at"), e.Get("attestedAt")
			if at.Len() == 0 || at.Len() != want.Len() {
				t.Fatalf("the case gives %d times and %d answers", at.Len(), want.Len())
			}
			for i := range at.Len() {
				if got := s.AttestedAt(at.Index(i).Int()); got != want.Index(i).Bool() {
					t.Errorf("AttestedAt(%d) = %t, want %t", at.Index(i).Int(), got, want.Index(i).Bool())
				}
			}
			got, ok := s.ResponseNotAfter()
			if want := e.Get("responseNotAfter"); want.IsNull() {
				if ok {
					t.Errorf("ResponseNotAfter = %d, want none", got)
				}
			} else if !ok || got != want.Int() {
				t.Errorf("ResponseNotAfter = %d, %t; want %d", got, ok, want.Int())
			}
		})
	})
}

// TestRecordedCallVectors replays v3.json's recordedCall cases. Each case is one record set: its calls are
// checked in order against one set of spent keys, each by Call in the session of the handshake it names
// (that request's client keyring and root, that reply's session id), which holds a call that verifies to
// that session's limits at its last stamp's ts.
func TestRecordedCallVectors(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	cases := v3.Get("recordedCall")
	if cases.Len() == 0 {
		t.Fatal("v3.json has no recordedCall case")
	}
	// The section's shape, from its data, so that a filtered run still checks it: nine calls, and at least
	// one that is OUTSIDE_SESSION.
	calls, outside := 0, 0
	cases.Each(func(_ string, c vectors.Node) {
		want := c.Get("expected")
		calls += want.Len()
		want.Each(func(_ string, e vectors.Node) {
			if e.Get("reason").Str() == string(reason.OutsideSession) {
				outside++
			}
		})
	})
	if calls != 9 || outside == 0 {
		t.Fatalf("the section has %d calls, %d of them OUTSIDE_SESSION; want 9, and at least one", calls, outside)
	}
	policies := v3.Get("policies")
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			var sessions []offline.RecordedSession
			c.Get("handshakes").Each(func(_ string, h vectors.Node) {
				sessions = append(sessions, record(t, v3, h.With(t)))
			})
			records := offline.NewRecordSet()
			origins := c.Get("allowedOrigins").Strs()
			want := c.Get("expected")
			if c.Get("calls").Len() != want.Len() {
				t.Fatalf("the case gives %d calls and %d answers", c.Get("calls").Len(), want.Len())
			}
			for i := range c.Get("calls").Len() {
				call := c.Get("calls").Index(i)
				s := sessions[call.Get("handshake").Int()]
				req, ok := s.Request()
				if !ok || req.ClientRoot == nil {
					t.Fatalf("call %d: the handshake's request does not read, or has no client root", i)
				}
				keyring, err := req.KeyringFile().Keyring()
				if err != nil {
					t.Fatalf("call %d: the client keyring: %v", i, err)
				}
				root, err := req.ClientRoot.Bytes()
				if err != nil {
					t.Fatalf("call %d: the client root: %v", i, err)
				}
				// The session's windows are Call's to judge, so the members have none.
				cfg := offline.Config{
					Keyrings: []verify.PinnedKeyring{{Keys: keyring, NotAfter: math.MaxInt64}},
					Roots: []verify.PinnedRoot{
						{Root: root, RootID: req.ClientRoot.RootID, NotAfter: math.MaxInt64},
					},
					AllowedOrigins: origins,
					Sess:           s.Sess(),
					RunMaxAgeMs:    optionalInt(c.Get("runMaxAgeMs")),
					CallMaxAgeMs:   optionalInt(c.Get("callMaxAgeMs")),
				}
				in := input(t, call, policies.With(t).Get(call.Get("policy").Str()))
				got, ok := records.Call(in, cfg, s)
				if !ok {
					t.Fatalf("call %d: no result, though every handshake here is attested", i)
				}
				if w := reason.Code(want.Index(i).Get("reason").Str()); got.Reason != w {
					t.Errorf("call %d = %s, want %s", i, got.Reason, w)
				}
			}
		})
	})
}

// record reads h, a handshake in the recordedHandshake shape, from its tokens.
func record(t *testing.T, v3, h vectors.Node) offline.RecordedSession {
	t.Helper()
	pin := v3.With(t).Get("keys").Get(h.Get("pin").Str()).Get("pub").Str()
	return offline.Record(decode(t, h.Get("requestToken").Str()), decode(t, h.Get("replyToken").Str()), pin,
		h.Get("serverEntry").Str())
}

// input returns the offline input case c gives, with the proof its proofRoute names in policy p.
func input(t *testing.T, c, p vectors.Node) offline.Input {
	t.Helper()
	in := offline.Input{
		Chain:           optional(c.Get("chainToken")),
		ExpectedBind:    optional(c.Get("expectedBind")),
		Influence:       optional(c.Get("influenceToken")),
		Receiver:        c.Get("receiver").Str(),
		ReceiverInRoute: c.Get("receiverInRoute").Bool(),
		NonceKey:        optional(c.Get("nonceKey")),
		RID:             optional(c.Get("rid")),
		Prompt:          optional(c.Get("prompt")),
	}
	if route := c.Get("proofRoute"); !route.IsNull() {
		tok := p.Get("proofTokens").Get(route.Str()).Str()
		in.Proof = &tok
	}
	if ts := c.Get("recordedTs"); !ts.IsNull() {
		in.Recorded = &offline.RecordedTimes{Last: ts.Get("last").Int()}
		if ts.Has("run") {
			in.Recorded.RunGiven = true
			ts.Get("run").Each(func(_ string, n vectors.Node) {
				in.Recorded.Run = append(in.Recorded.Run, n.Int())
			})
		}
	}
	return in
}

// decode returns the bytes of tok, a base64url token.
func decode(t testing.TB, tok string) []byte {
	t.Helper()
	b, err := b64.Decode(tok)
	if err != nil {
		t.Fatalf("a token: %v", err)
	}
	return b
}

// optional returns n's string, or nil when n is null.
func optional(n vectors.Node) *string {
	if n.IsNull() {
		return nil
	}
	s := n.Str()
	return &s
}

// optionalInt returns n's integer, or nil when n is null.
func optionalInt(n vectors.Node) *int64 {
	if n.IsNull() {
		return nil
	}
	i := n.Int()
	return &i
}
