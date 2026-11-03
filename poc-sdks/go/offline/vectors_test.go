// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package offline_test

import (
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
	policies := v3.Get("policies")
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			p := policies.With(t).Get(c.Get("policy").Str())
			root, err := b64.Decode(p.Get("root").Str())
			if err != nil {
				t.Fatalf("the policy's root: %v", err)
			}
			keyring := policy.Keyring{}
			ring := c.Get("keyring")
			for _, svc := range ring.Names() {
				_, pub := vectors.V3Key(t, ring.Get(svc).Str())
				keyring[svc] = pub
			}
			cfg := offline.Config{
				Keyring:        keyring,
				Root:           root,
				RootID:         p.Get("rootId").Str(),
				AllowedOrigins: c.Get("allowedOrigins").Strs(),
				Sess:           c.Get("sess").Str(),
				RunMaxAgeMs:    optionalInt(c.Get("runMaxAgeMs")),
				CallMaxAgeMs:   optionalInt(c.Get("callMaxAgeMs")),
			}
			got := offline.NewRecordSet(c.Get("seen").Strs()...).Verify(input(t, c, p), cfg)
			e := c.Get("expected")
			want := verify.Result{
				Reason:      reason.Code(e.Get("reason").Str()),
				SuspectSvc:  e.Get("suspectSvc").Str(),
				SuspectInst: e.Get("suspectInst").Str(),
			}
			if got != want {
				t.Fatalf("Verify = %+v, want %+v", got, want)
			}
		})
	})
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
			if got, want := s.ResponseNotAfter(), e.Get("responseNotAfter").Int(); got != want {
				t.Errorf("ResponseNotAfter = %d, want %d", got, want)
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
				cfg := offline.Config{
					Keyring:        keyring,
					Root:           root,
					RootID:         req.ClientRoot.RootID,
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
