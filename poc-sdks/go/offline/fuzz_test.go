// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package offline_test

import (
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/offline"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// offlineCodes are the codes the offline verifier gives: a live verifier's but PEER_MISMATCH and
// POLICY_EXPIRED, and TIME_MISMATCH and PROMPT_MISMATCH.
var offlineCodes = []reason.Code{
	reason.OK, reason.ChainMissing, reason.BadOrigin, reason.BadSignature, reason.BrokenLink, reason.Expired,
	reason.RIDMismatch, reason.BindingMismatch, reason.Replay, reason.PathNotAllowed, reason.SessionUnknown,
	reason.InfluenceMismatch, reason.TimeMismatch, reason.PromptMismatch,
}

// FuzzVerify verifies any recorded chain token, with any rid, recorded times or none, age limits or none,
// prompt and session, against a verifier that holds every key of v3.json's offline cases and the mesh
// fixture, in a record set that has spent one key. The seeds are the mesh fixture's chain, recorded at its
// own time, which verifies, at another, with no recorded time and with no age limits, and the offline
// cases' chains, with their times and limits absent where the case gives none. It never panics, gives only
// an offline code, and names no one unless the result is OK or PATH_NOT_ALLOWED.
func FuzzVerify(f *testing.F) {
	s := mesh(f)
	tok := s.token(f)
	f.Add(tok, "rid-1", "", true, end, start, true, true, int64(1800000), true, int64(5000), prompt)
	f.Add(tok, "rid-1", "", true, end+1, start, true, true, int64(1800000), true, int64(5000), prompt)
	f.Add(tok, "rid-1", "", false, int64(0), int64(0), false, true, int64(1800000), true, int64(5000), prompt)
	f.Add(tok, "rid-1", "", true, end, start, true, false, int64(0), false, int64(0), prompt)
	v3 := vectors.Load(f, "v3.json")
	v3.Get("offline").Each(func(_ string, c vectors.Node) {
		ts, runMax, callMax := c.Get("recordedTs"), c.Get("runMaxAgeMs"), c.Get("callMaxAgeMs")
		last := int64(0)
		if !ts.IsNull() {
			last = ts.Get("last").Int()
		}
		f.Add(c.Get("chainToken").Str(), "rid-1", "sess-1", !ts.IsNull(), last, int64(0), false,
			!runMax.IsNull(), orZero(runMax), !callMax.IsNull(), orZero(callMax), c.Get("prompt").Str())
	})
	mesh := v3.Get("policies").Get("mesh")
	root, err := b64.Decode(mesh.Get("root").Str())
	if err != nil {
		f.Fatal(err)
	}
	proof := mesh.Get("proofTokens").Get("gateway/orders/payment").Str()
	keyring := policy.Keyring{}
	for _, name := range []string{"session", "pi", "gateway", "orders"} {
		_, keyring[name] = vectors.V3Key(f, name)
	}
	rootID := mesh.Get("rootId").Str()
	f.Fuzz(func(t *testing.T, chain, rid, sess string, recorded bool, last, run int64, runGiven bool,
		runMaxGiven bool, runMax int64, callMaxGiven bool, callMax int64, prompt string) {
		bind, key := "bind-1", "rid-1|orders|req"
		in := offline.Input{
			Chain:           &chain,
			ExpectedBind:    &bind,
			Proof:           &proof,
			Receiver:        "payment",
			ReceiverInRoute: true,
			NonceKey:        &key,
			RID:             &rid,
			Prompt:          &prompt,
		}
		if recorded {
			in.Recorded = &offline.RecordedTimes{Last: last, RunGiven: runGiven, Run: []int64{run}}
		}
		cfg := offline.Config{
			Keyring:        keyring,
			Root:           root,
			RootID:         rootID,
			AllowedOrigins: []string{"gateway", "session"},
			Sess:           sess,
		}
		if runMaxGiven {
			cfg.RunMaxAgeMs = &runMax
		}
		if callMaxGiven {
			cfg.CallMaxAgeMs = &callMax
		}
		r := offline.NewRecordSet("rid-0|orders|req").Verify(in, cfg)
		if !slices.Contains(offlineCodes, r.Reason) {
			t.Fatalf("Verify gave %q", r.Reason)
		}
		named := r.SuspectSvc != "" || r.SuspectInst != ""
		if named && r.Reason != reason.OK && r.Reason != reason.PathNotAllowed {
			t.Fatalf("a %s result names %q, %q", r.Reason, r.SuspectSvc, r.SuspectInst)
		}
	})
}

// FuzzRecord records any request and reply bytes, with any pin and entry, judged at any time. The seeds
// are v3.json's recordedHandshake cases and a handshake of which nothing was recorded. Record never
// panics; the response window is a protocol integer; a session attested at all is attested at 0, since
// every limit is an upper bound at or after 0; and a call gets a result exactly in a session attested at
// all.
func FuzzRecord(f *testing.F) {
	v3 := vectors.Load(f, "v3.json")
	v3.Get("recordedHandshake").Each(func(_ string, c vectors.Node) {
		pin := v3.Get("keys").Get(c.Get("pin").Str()).Get("pub").Str()
		f.Add(decode(f, c.Get("requestToken").Str()), decode(f, c.Get("replyToken").Str()), pin,
			c.Get("serverEntry").Str(), c.Get("at").Index(0).Int())
	})
	f.Add([]byte{}, []byte{}, "", "", int64(0))
	f.Fuzz(func(t *testing.T, request, reply []byte, pin, entry string, at int64) {
		s := offline.Record(request, reply, pin, entry)
		n, limited := s.ResponseNotAfter()
		if limited && (n < 0 || n > json.MaxSafe) {
			t.Fatalf("ResponseNotAfter = %d, outside [0, 2^53 - 1]", n)
		}
		if s.Attested() && !limited {
			t.Fatal("an attested session gives a response no limit")
		}
		if s.Attested() != s.AttestedAt(0) {
			t.Fatalf("Attested = %t, but AttestedAt(0) = %t", s.Attested(), s.AttestedAt(0))
		}
		if s.AttestedAt(at) && !s.Attested() {
			t.Fatalf("attested at %d, but not at all", at)
		}
		r, ok := new(offline.RecordSet).Call(offline.Input{}, offline.Config{}, s)
		if ok != s.Attested() || (!ok && r != verify.Result{}) {
			t.Fatalf("Call = %+v, %t; but Attested = %t", r, ok, s.Attested())
		}
	})
}

// orZero returns n's integer, or 0 when n is null.
func orZero(n vectors.Node) int64 {
	if n.IsNull() {
		return 0
	}
	return n.Int()
}
