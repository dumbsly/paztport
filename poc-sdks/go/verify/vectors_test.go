// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify_test

import (
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestVectors replays v4.json's verify cases. Each builds its Config directly, with a fixed clock, a fresh
// MemoryNonceCache of the case's nonceTtlMs and the extension settings the case gives, runs the verifier uses times
// against that one cache, each use sent by its peer, and expects the last result, its hand-over included. A case
// reads only its tokens, never the readable values beside them. A case that carries keyrings or roots gives the
// pinning factory's policyNotAfter for them: the earlier of the latest keyring notAfter and the latest root notAfter.
func TestVectors(t *testing.T) {
	v4 := vectors.Load(t, "v4.json")
	cases := v4.Get("verify")
	if cases.Len() != 90 {
		t.Fatalf("v4.json has %d verify cases, want 90", cases.Len())
	}
	// The codes the section exists for, from its data, so that a filtered run still checks they occur.
	occur := map[reason.Code]bool{}
	cases.Each(func(_ string, c vectors.Node) { occur[reason.Code(c.Get("expected").Get("reason").Str())] = true })
	for _, code := range []reason.Code{
		reason.ExtensionMismatch, reason.ExtensionNotAllowed, reason.ExtensionRequired, reason.PeerMismatch,
	} {
		if !occur[code] {
			t.Fatalf("no verify case expects %s", code)
		}
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			if c.Has("keyrings") || c.Has("roots") {
				policyNotAfter := c.Get("policyNotAfter").Int()
				got := pinnedNotAfter(keyrings(t, c, policyNotAfter), roots(t, v4.With(t), c, policyNotAfter))
				if got != policyNotAfter {
					t.Fatalf("the members give policyNotAfter %d, the case %d", got, policyNotAfter)
				}
			}
			got := replay(t, v4.With(t), c)
			matches(t, got, c)
			if got.OK() != (got.Reason == reason.OK) {
				t.Fatalf("OK() = %t for %s", got.OK(), got.Reason)
			}
		})
	})
}

// matches checks got against what case c expects: its reason and suspect, and its hand-over, which is absent or
// null for none, and otherwise holds, for each name the case acts on, one entry per stamp, items null where the
// stamp's block does not name the extension. Each item is compared as the canonical text of its JSON value.
func matches(t *testing.T, got verify.Result, c vectors.Node) {
	t.Helper()
	if plain, want := withoutHandOver(got), expected(c); plain != want {
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
	if !slices.Equal(got.HandOver.Names(), sorted(want.Names())) {
		t.Fatalf("the hand-over holds %q, want %q", got.HandOver.Names(), want.Names())
	}
	for _, name := range want.Names() {
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

// withoutHandOver returns r without its hand-over, for comparing the rest with ==.
func withoutHandOver(r verify.Result) verify.Result {
	r.HandOver = nil
	return r
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

// sorted returns a sorted copy of names.
func sorted(names []string) []string {
	out := slices.Clone(names)
	slices.Sort(out)
	return out
}

// TestVectorsReadTheOptionalArrays checks that the replay reads the keyrings and roots a case may carry,
// beside the committed cases that carry them: every verify case written in the single form, its keyring and its
// policy's root written as the arrays, each member until the case's policyNotAfter, gives its recorded answer, with its
// keyring whole or split one service to a keyring. And what the arrays pin is what is used: without the
// keyring that holds a signer's key the chain is BAD_SIGNATURE, and with another policy's root in place of
// the one the proof comes from it is PATH_NOT_ALLOWED; so it is under a root past its window.
func TestVectorsReadTheOptionalArrays(t *testing.T) {
	v4 := vectors.Load(t, "v4.json")
	v4.Get("verify").Each(func(name string, c vectors.Node) {
		if c.Has("keyrings") || c.Has("roots") {
			return // already written as arrays: TestVectors replays it
		}
		for _, split := range []bool{false, true} {
			t.Run(name+", split "+strconv.FormatBool(split), func(t *testing.T) {
				c := c.With(t)
				window := string(c.Get("policyNotAfter").Raw())
				matches(t, replay(t, v4.With(t), asArrays(c, window, split)), c)
			})
		}
	})
	var ok vectors.Node
	v4.Get("verify").Each(func(name string, c vectors.Node) {
		if name == "mcp call ok" {
			ok = c
		}
	})
	window := string(ok.Get("policyNotAfter").Raw())
	split := asArrays(ok, window, true)
	var some []string
	for i := range split.Get("keyrings").Len() {
		if i != 1 {
			some = append(some, string(split.Get("keyrings").Index(i).Raw()))
		}
	}
	short := split.Rewrite([]string{"keyrings"},
		vectors.Member{Name: "keyrings", Text: "[" + strings.Join(some, ", ") + "]"})
	if got := replay(t, v4, short); got.Reason != reason.BadSignature {
		t.Errorf("without the second keyring: Verify = %+v, want BAD_SIGNATURE", got)
	}
	elsewhere := asArrays(ok, window, false).Rewrite([]string{"roots"},
		vectors.Member{Name: "roots", Text: `[{"policy": "server", "notAfter": ` + window + `}]`})
	if got := replay(t, v4, elsewhere); got.Reason != reason.PathNotAllowed {
		t.Errorf("under another policy's root: Verify = %+v, want PATH_NOT_ALLOWED", got)
	}
	past := strconv.FormatInt(ok.Get("now").Int()-1, 10)
	if got := replay(t, v4, asArrays(ok, past, false)); got.Reason != reason.BadSignature {
		t.Errorf("under members past their windows: Verify = %+v, want BAD_SIGNATURE", got)
	}
	lapsed := asArrays(ok, window, false).Rewrite([]string{"roots"},
		vectors.Member{Name: "roots", Text: `[{"policy": "client", "notAfter": ` + past + `}]`})
	if got := replay(t, v4, lapsed); got.Reason != reason.PathNotAllowed {
		t.Errorf("under a root past its window: Verify = %+v, want PATH_NOT_ALLOWED", got)
	}
}

// TestVectorsRefuseALiveMemberWithNoWindow checks that the replay stops at a verify case whose keyring or
// root has no notAfter, a shape the format gives only offline cases, rather than pinning it with a window
// of its own choosing.
func TestVectorsRefuseALiveMemberWithNoWindow(t *testing.T) {
	v4 := vectors.Load(t, "v4.json")
	var ok vectors.Node
	v4.Get("verify").Each(func(name string, c vectors.Node) {
		if name == "mcp call ok" {
			ok = c
		}
	})
	window := string(ok.Get("policyNotAfter").Raw())
	single := ok.Get("policyNotAfter").Int()
	arrays := asArrays(ok, window, false)
	keyringless := arrays.Rewrite([]string{"keyrings"},
		vectors.Member{Name: "keyrings", Text: `[{"keyring": ` + string(ok.Get("keyring").Raw()) + `}]`})
	rootless := arrays.Rewrite([]string{"roots"},
		vectors.Member{Name: "roots", Text: `[{"policy": ` + string(ok.Get("policy").Raw()) + `}]`})
	for _, tt := range []struct {
		name string
		pin  func(tb testing.TB)
		want string
	}{
		{"a keyring", func(tb testing.TB) { keyrings(tb, keyringless.With(tb), single) }, "keyrings[0] has no"},
		{"a root", func(tb testing.TB) { roots(tb, v4.With(tb), rootless.With(tb), single) }, "roots[0] has no"},
	} {
		if got := fatal(t, tt.pin); !strings.Contains(got, tt.want) {
			t.Errorf("%s with no notAfter: the replay failed with %q, want %q", tt.name, got, tt.want)
		}
	}
}

// stopped stands in for a test so a check can watch a helper fail one.
type stopped struct {
	testing.TB
	message string
}

func (s *stopped) Helper() {}

func (s *stopped) Fatalf(format string, args ...any) {
	s.message = fmt.Sprintf(format, args...)
	runtime.Goexit()
}

// fatal runs f against a stand-in test and returns the message f stopped it with, or "" when it did not.
func fatal(t *testing.T, f func(tb testing.TB)) string {
	t.Helper()
	s := &stopped{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f(s)
	}()
	<-done
	return s.message
}

// pinnedNotAfter returns what the pinning factory gives for keyrings and roots: the earlier of the latest
// keyring notAfter and the latest root notAfter.
func pinnedNotAfter(keyrings []verify.PinnedKeyring, roots []verify.PinnedRoot) int64 {
	var latestKeyring, latestRoot int64
	for i, k := range keyrings {
		if i == 0 || k.NotAfter > latestKeyring {
			latestKeyring = k.NotAfter
		}
	}
	for i, r := range roots {
		if i == 0 || r.NotAfter > latestRoot {
			latestRoot = r.NotAfter
		}
	}
	return min(latestKeyring, latestRoot)
}

// replay runs case c of v4.json's verify section and returns the last result. Its settings act on the case's
// actsOn and, where allowedExtensions is not null, carry only those names; each use is sent by the case's peer, or
// by peers[i] for use i.
func replay(t *testing.T, v4, c vectors.Node) verify.Result {
	t.Helper()
	p := v4.Get("policies").Get(c.Get("policy").Str())
	now, policyNotAfter := c.Get("now").Int(), c.Get("policyNotAfter").Int()
	cfg := verify.Config{
		Keyrings:       keyrings(t, c, policyNotAfter),
		Roots:          roots(t, v4, c, policyNotAfter),
		PolicyNotAfter: policyNotAfter,
		AllowedOrigins: c.Get("allowedOrigins").Strs(),
		Sess:           c.Get("sess").Str(),
		Nonces:         verify.NewMemoryNonceCache(c.Get("nonceTtlMs").Int()),
		Now:            func() int64 { return now },
		CallMaxAgeMs:   c.Get("callMaxAgeMs").Int(),
		RunMaxAgeMs:    c.Get("runMaxAgeMs").Int(),
		Extensions:     extensions(t, c),
	}
	in := verify.Input{
		Chain:           optional(c.Get("chainToken")),
		ExpectedBind:    optional(c.Get("expectedBind")),
		Blocks:          optional(c.Get("blocksToken")),
		Receiver:        c.Get("receiver").Str(),
		ReceiverInRoute: c.Get("receiverInRoute").Bool(),
		NonceKey:        optional(c.Get("nonceKey")),
	}
	if route := c.Get("proofRoute"); !route.IsNull() {
		tok := p.Get("proofTokens").Get(route.Str()).Str()
		in.Proof = &tok
	}
	uses := c.Get("uses").Int()
	if uses < 1 {
		t.Fatalf("the case runs %d times", uses)
	}
	if c.Has("peers") && (c.Has("peer") || int64(c.Get("peers").Len()) != uses) {
		t.Fatalf("the case gives peers and peer, or %d peers for %d uses", c.Get("peers").Len(), uses)
	}
	v := verify.New(cfg)
	var got verify.Result
	for i := range uses {
		var peer vectors.Node
		if c.Has("peers") {
			peer = c.Get("peers").Index(int(i))
		} else {
			peer = c.Get("peer")
		}
		in.Peer = nil
		if !peer.IsNull() {
			in.Peer = &verify.Peer{Svc: peer.Get("svc").Str(), Inst: peer.Get("inst").Str()}
		}
		var err error
		if got, err = v.Verify(t.Context(), in); err != nil {
			t.Fatalf("Verify: %v", err)
		}
	}
	return got
}

// extensions returns the settings case c gives: acting on actsOn and carrying any name, or, where
// allowedExtensions is not null, only the names it lists.
func extensions(t testing.TB, c vectors.Node) verify.Extensions {
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
// notAfter, which a live member always has; otherwise its one keyring, until single.
func keyrings(t testing.TB, c vectors.Node, single int64) []verify.PinnedKeyring {
	t.Helper()
	if !c.Has("keyrings") {
		return []verify.PinnedKeyring{{Keys: keyring(t, c.Get("keyring")), NotAfter: single}}
	}
	if c.Has("keyring") {
		t.Fatal("the case gives keyrings and keyring, which keyrings replace")
	}
	var out []verify.PinnedKeyring
	for i := range c.Get("keyrings").Len() {
		k := c.Get("keyrings").Index(i)
		notAfter := window(t, k, "keyrings", i)
		out = append(out, verify.PinnedKeyring{Keys: keyring(t, k.Get("keyring")), NotAfter: notAfter})
	}
	return out
}

// roots returns the roots case c pins: its roots, each a policy's root until its own notAfter, which a
// live member always has; otherwise its policy's root, until single. With roots, policy names only where
// the case's proof comes from.
func roots(t testing.TB, v4, c vectors.Node, single int64) []verify.PinnedRoot {
	t.Helper()
	if !c.Has("roots") {
		return []verify.PinnedRoot{pinnedRoot(t, v4, c.Get("policy").Str(), single)}
	}
	var out []verify.PinnedRoot
	for i := range c.Get("roots").Len() {
		r := c.Get("roots").Index(i)
		out = append(out, pinnedRoot(t, v4, r.Get("policy").Str(), window(t, r, "roots", i)))
	}
	return out
}

// keyring returns the keyring ring names: each service to the vector key of the name it maps to.
func keyring(t testing.TB, ring vectors.Node) policy.Keyring {
	t.Helper()
	k := policy.Keyring{}
	for _, svc := range ring.Names() {
		_, pub := vectors.VectorKey(t, ring.Get(svc).Str())
		k[svc] = pub
	}
	return k
}

// pinnedRoot returns the root of v4.json's policy name, until notAfter.
func pinnedRoot(t testing.TB, v4 vectors.Node, name string, notAfter int64) verify.PinnedRoot {
	t.Helper()
	p := v4.Get("policies").Get(name)
	root, err := b64.Decode(p.Get("root").Str())
	if err != nil {
		t.Fatalf("the policy's root: %v", err)
	}
	return verify.PinnedRoot{Root: root, RootID: p.Get("rootId").Str(), NotAfter: notAfter}
}

// window returns live member i of the case's array name: its notAfter, failing t when it gives none.
func window(t testing.TB, m vectors.Node, name string, i int) int64 {
	t.Helper()
	if !m.Has("notAfter") {
		t.Fatalf("%s[%d] has no notAfter: a live member always has a window", name, i)
	}
	return m.Get("notAfter").Int()
}

// asArrays returns case c with its keyring written as keyrings, whole or split one service to a keyring,
// and its policy's root as roots, each member until notAfter, a JSON number's text.
func asArrays(c vectors.Node, notAfter string, split bool) vectors.Node {
	ring := c.Get("keyring")
	var parts []string
	if split {
		for _, svc := range ring.Names() {
			parts = append(parts, `{`+strconv.Quote(svc)+`: `+string(ring.Get(svc).Raw())+`}`)
		}
	} else {
		parts = append(parts, string(ring.Raw()))
	}
	var members []string
	for _, part := range parts {
		members = append(members, `{"keyring": `+part+`, "notAfter": `+notAfter+`}`)
	}
	return c.Rewrite([]string{"keyring"},
		vectors.Member{Name: "keyrings", Text: "[" + strings.Join(members, ", ") + "]"},
		vectors.Member{Name: "roots", Text: `[{"policy": ` + string(c.Get("policy").Raw()) + `, "notAfter": ` +
			notAfter + `}]`})
}

// optional returns n's string, or nil when n is null.
func optional(n vectors.Node) *string {
	if n.IsNull() {
		return nil
	}
	s := n.Str()
	return &s
}
