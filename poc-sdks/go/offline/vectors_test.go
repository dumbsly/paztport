// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package offline_test

import (
	"math"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/offline"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestVectors replays v4.json's offline cases: each runs the offline verifier once, with the case's extension
// settings, in a record set that has already spent the case's seen keys, and expects its result, its hand-over
// included. A case reads only its tokens, never the readable values beside them.
func TestVectors(t *testing.T) {
	v4 := vectors.Load(t, "v4.json")
	cases := v4.Get("offline")
	if cases.Len() != 21 {
		t.Fatalf("v4.json has %d offline cases, want 21", cases.Len())
	}
	occur := map[reason.Code]bool{}
	cases.Each(func(_ string, c vectors.Node) { occur[reason.Code(c.Get("expected").Get("reason").Str())] = true })
	if !occur[reason.ExtensionMismatch] || !occur[reason.ExtensionNotAllowed] {
		t.Fatal("no offline case expects EXTENSION_MISMATCH, or none EXTENSION_NOT_ALLOWED")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			matches(t, replay(t, v4.With(t), c), c)
		})
	})
}

// matches checks got against what case c expects: its reason and suspect, and its hand-over, which is absent or
// null for none, and otherwise holds, for each name the case acts on, one entry per stamp, items null where the
// stamp's block does not name the extension. Each item is compared as the canonical text of its JSON value.
func matches(t *testing.T, got verify.Result, c vectors.Node) {
	t.Helper()
	plain := got
	plain.HandOver = nil
	if want := expected(c); plain != want {
		t.Fatalf("Verify = %+v, want %+v", plain, want)
	}
	e := c.Get("expected")
	if !e.Has("handOver") || e.Get("handOver").IsNull() {
		if got.HandOver != nil {
			t.Fatalf("Verify handed over %q, want nothing", got.HandOver.Names())
		}
		return
	}
	if got.HandOver == nil || !got.HandOver.Verified() {
		t.Fatalf("Verify handed over %v, want a verified hand-over", got.HandOver)
	}
	want := e.Get("handOver")
	names := slices.Clone(want.Names())
	slices.Sort(names)
	if !slices.Equal(got.HandOver.Names(), names) {
		t.Fatalf("the hand-over holds %q, want %q", got.HandOver.Names(), names)
	}
	for _, name := range names {
		var entries []verify.StampItems
		want.Get(name).Each(func(_ string, n vectors.Node) {
			entry := verify.StampItems{Svc: n.Get("svc").Str()}
			if items := n.Get("items"); !items.IsNull() {
				entry.Named, entry.Items = true, []string{}
				items.Each(func(_ string, item vectors.Node) { entry.Items = append(entry.Items, canonical(t, item)) })
			}
			entries = append(entries, entry)
		})
		under, ok := got.HandOver.Under(name)
		if !ok || !slices.EqualFunc(under, entries, func(a, b verify.StampItems) bool {
			return a.Svc == b.Svc && a.Named == b.Named && slices.Equal(a.Items, b.Items)
		}) {
			t.Fatalf("Under(%s) = %+v, %t, want %+v", name, under, ok, entries)
		}
	}
}

// canonical returns the JCS text of the JSON value n holds.
func canonical(t *testing.T, n vectors.Node) string {
	t.Helper()
	v, err := json.ReadFile(n.Raw())
	if err != nil {
		t.Fatalf("an item: %v", err)
	}
	b, err := json.Wire(v)
	if err != nil {
		t.Fatalf("an item has no canonical text: %v", err)
	}
	return string(b)
}

// extensions returns the settings case c gives: acting on actsOn and carrying any name, or, where
// allowedExtensions is not null, only the names it lists.
func extensions(t *testing.T, c vectors.Node) verify.Extensions {
	t.Helper()
	var e verify.Extensions
	var err error
	if allowed := c.Get("allowedExtensions"); allowed.IsNull() {
		e, err = verify.NewExtensions(c.Get("actsOn").Strs())
	} else {
		e, err = verify.NewExtensionsAllowing(c.Get("actsOn").Strs(), allowed.Strs())
	}
	if err != nil {
		t.Fatalf("the case's extension settings: %v", err)
	}
	return e
}

// TestVectorsReadTheOptionalArrays checks that the replay reads the keyrings and roots a case may carry,
// beside the committed cases that carry them: every offline case written in the single form, its keyring and its
// policy's root written as the arrays with no window, gives its recorded answer, with its keyring whole or split one
// service to a keyring. And each member's window is the one it gives: a record later than every keyring's
// or every root's notAfter is POLICY_EXPIRED, and one at it is not.
func TestVectorsReadTheOptionalArrays(t *testing.T) {
	v4 := vectors.Load(t, "v4.json")
	v4.Get("offline").Each(func(name string, c vectors.Node) {
		if c.Has("keyrings") || c.Has("roots") {
			return // already written as arrays: TestVectors replays it
		}
		for _, split := range []bool{false, true} {
			t.Run(name+", split "+strconv.FormatBool(split), func(t *testing.T) {
				c := c.With(t)
				matches(t, replay(t, v4.With(t), asArrays(c, "", split)), c)
			})
		}
	})
	var recorded vectors.Node
	v4.Get("offline").Each(func(name string, c vectors.Node) {
		if name == "recorded call" {
			recorded = c
		}
	})
	last := recorded.Get("recordedTs").Get("last").Int()
	at, before := strconv.FormatInt(last, 10), strconv.FormatInt(last-1, 10)
	if got := replay(t, v4, asArrays(recorded, at, true)); got.Reason != reason.OK {
		t.Errorf("under members until the record's time: Verify = %+v, want OK", got)
	}
	if got := replay(t, v4, asArrays(recorded, before, false)); got.Reason != reason.PolicyExpired {
		t.Errorf("under members until before the record: Verify = %+v, want POLICY_EXPIRED", got)
	}
	lapsed := asArrays(recorded, "", false).Rewrite([]string{"roots"},
		vectors.Member{Name: "roots", Text: `[{"policy": ` + string(recorded.Get("policy").Raw()) + `, "notAfter": ` +
			before + `}]`})
	if got := replay(t, v4, lapsed); got.Reason != reason.PolicyExpired {
		t.Errorf("under a root until before the record: Verify = %+v, want POLICY_EXPIRED", got)
	}
	elsewhere := asArrays(recorded, "", false).Rewrite([]string{"roots"},
		vectors.Member{Name: "roots", Text: `[{"policy": "server"}]`})
	if got := replay(t, v4, elsewhere); got.Reason != reason.PathNotAllowed {
		t.Errorf("under another policy's root: Verify = %+v, want PATH_NOT_ALLOWED", got)
	}
}

// replay runs case c of v4.json's offline section once, in a record set that has already spent the case's
// seen keys. A member a case gives with no window counts for every record.
func replay(t *testing.T, v4, c vectors.Node) verify.Result {
	t.Helper()
	cfg := offline.Config{
		Keyrings:       keyrings(t, c),
		Roots:          roots(t, v4, c),
		AllowedOrigins: c.Get("allowedOrigins").Strs(),
		Sess:           c.Get("sess").Str(),
		RunMaxAgeMs:    optionalInt(c.Get("runMaxAgeMs")),
		CallMaxAgeMs:   optionalInt(c.Get("callMaxAgeMs")),
		Extensions:     extensions(t, c),
	}
	p := v4.Get("policies").Get(c.Get("policy").Str())
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
func roots(t *testing.T, v4, c vectors.Node) []verify.PinnedRoot {
	t.Helper()
	if !c.Has("roots") {
		return []verify.PinnedRoot{pinnedRoot(t, v4, c.Get("policy").Str(), math.MaxInt64)}
	}
	var out []verify.PinnedRoot
	c.Get("roots").Each(func(_ string, r vectors.Node) {
		out = append(out, pinnedRoot(t, v4, r.Get("policy").Str(), window(r)))
	})
	return out
}

// keyring returns the keyring ring names: each service to the vector key of the name it maps to.
func keyring(t *testing.T, ring vectors.Node) policy.Keyring {
	t.Helper()
	k := policy.Keyring{}
	for _, svc := range ring.Names() {
		_, pub := vectors.VectorKey(t, ring.Get(svc).Str())
		k[svc] = pub
	}
	return k
}

// pinnedRoot returns the root of v4.json's policy name, until notAfter.
func pinnedRoot(t *testing.T, v4 vectors.Node, name string, notAfter int64) verify.PinnedRoot {
	t.Helper()
	p := v4.Get("policies").Get(name)
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

// TestRecordedHandshakeVectors replays v4.json's recordedHandshake cases: whether each opened an attested
// session at all and at each of its times, and the limit on a response recorded in it.
func TestRecordedHandshakeVectors(t *testing.T) {
	v4 := vectors.Load(t, "v4.json")
	cases := v4.Get("recordedHandshake")
	if cases.Len() == 0 {
		t.Fatal("v4.json has no recordedHandshake case")
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			s := record(t, v4, c)
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

// TestRecordedCallVectors replays v4.json's recordedCall cases. Each case is one record set: its calls are
// checked in order against one set of spent keys, each by Call in the session of the handshake it names, with the
// config that session gives (CallConfig: that request's client keyring and root, that reply's session id), which
// holds a call that verifies to that session's limits at its last stamp's ts. No extension's items are read.
func TestRecordedCallVectors(t *testing.T) {
	v4 := vectors.Load(t, "v4.json")
	cases := v4.Get("recordedCall")
	if cases.Len() != 6 {
		t.Fatalf("v4.json has %d recordedCall cases, want 6", cases.Len())
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
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			if got, want := replayCalls(t, v4, c, nil), answers(c); !slices.Equal(got, want) {
				t.Fatalf("the calls give %v, want %v", got, want)
			}
		})
	})
}

// TestInfluenceRecordedCallVectors replays v4.json's influence.recordedCall as TestRecordedCallVectors replays
// recordedCall, at a verifier that acts on influence, whose item check is influence.Items: the items are read once
// the offline order gives OK, before the call is held to its session's limits (verification.md, Offline
// verification), so a call past the limits whose items do not read is INFLUENCE_MISMATCH, not OUTSIDE_SESSION.
func TestInfluenceRecordedCallVectors(t *testing.T) {
	v4 := vectors.Load(t, "v4.json")
	cases := v4.Get("influence").Get("recordedCall")
	if cases.Len() != 1 {
		t.Fatalf("v4.json has %d influence.recordedCall cases, want 1", cases.Len())
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			if !extensions(t, c).ActsOnName(influence.Name) {
				t.Fatal("the case's settings do not act on influence")
			}
			// The case this replay is written for: calls that read and calls that do not, within the session's
			// limits and past them.
			want := answers(c)
			if !slices.Equal(want, []reason.Code{reason.OK, reason.InfluenceMismatch, reason.InfluenceMismatch,
				reason.OutsideSession}) {
				t.Fatalf("the case expects %v", want)
			}
			if got := replayCalls(t, v4, c, influence.Items); !slices.Equal(got, want) {
				t.Fatalf("the calls give %v, want %v", got, want)
			}
			// With no item check the same calls are judged by the core alone, so the session's limits decide: the
			// third call, whose items do not read and which is past them, is OUTSIDE_SESSION.
			core := []reason.Code{reason.OK, reason.OK, reason.OutsideSession, reason.OutsideSession}
			if got := replayCalls(t, v4, c, nil); !slices.Equal(got, core) {
				t.Fatalf("with no item check, the calls give %v, want %v", got, core)
			}
		})
	})
}

// replayCalls checks case c's calls in order against one fresh set of spent keys, each by Call with items in the
// session of the handshake it names, with the config that session gives, and returns each call's reason.
func replayCalls(t *testing.T, v4, c vectors.Node, items offline.ItemCheck) []reason.Code {
	t.Helper()
	var sessions []offline.RecordedSession
	c.Get("handshakes").Each(func(_ string, h vectors.Node) {
		sessions = append(sessions, record(t, v4, h.With(t)))
	})
	records := offline.NewRecordSet()
	if c.Get("calls").Len() != c.Get("expected").Len() {
		t.Fatalf("the case gives %d calls and %d answers", c.Get("calls").Len(), c.Get("expected").Len())
	}
	var got []reason.Code
	policies := v4.With(t).Get("policies")
	for i := range c.Get("calls").Len() {
		call := c.Get("calls").Index(i)
		s := sessions[call.Get("handshake").Int()]
		cfg, ok := s.CallConfig(c.Get("allowedOrigins").Strs(), optionalInt(c.Get("runMaxAgeMs")),
			optionalInt(c.Get("callMaxAgeMs")), extensions(t, c))
		if !ok {
			t.Fatalf("call %d: no config, though every handshake here is attested", i)
		}
		in := input(t, call, policies.Get(call.Get("policy").Str()))
		r, ok := records.Call(in, cfg, s, items)
		if !ok {
			t.Fatalf("call %d: no result, though every handshake here is attested", i)
		}
		if (r.HandOver != nil) != r.OK() {
			t.Errorf("call %d: a %s result has the hand-over %v", i, r.Reason, r.HandOver)
		}
		got = append(got, r.Reason)
	}
	return got
}

// answers returns the reasons case c expects of its calls, in order.
func answers(c vectors.Node) []reason.Code {
	var want []reason.Code
	c.Get("expected").Each(func(_ string, e vectors.Node) {
		want = append(want, reason.Code(e.Get("reason").Str()))
	})
	return want
}

// record reads h, a handshake in the recordedHandshake shape, from its tokens, its pin named in file's keys.
func record(t *testing.T, file, h vectors.Node) offline.RecordedSession {
	t.Helper()
	pin := file.With(t).Get("keys").Get(h.Get("pin").Str()).Get("pub").Str()
	return offline.Record(decode(t, h.Get("requestToken").Str()), decode(t, h.Get("replyToken").Str()), pin,
		h.Get("serverEntry").Str())
}

// input returns the offline input case c gives, with the proof its proofRoute names in policy p.
func input(t *testing.T, c, p vectors.Node) offline.Input {
	t.Helper()
	in := offline.Input{
		Chain:           optional(c.Get("chainToken")),
		ExpectedBind:    optional(c.Get("expectedBind")),
		Blocks:          optional(c.Get("blocksToken")),
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
