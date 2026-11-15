// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package wire_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors/handover"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// surrogate is the Go string that stands for a lone surrogate: U+D800's three-byte pattern, which is not
// valid UTF-8.
const surrogate = "\xed\xa0\x80"

// nbsp is U+00A0, NO-BREAK SPACE, as its UTF-8 bytes: whitespace to Unicode, but not HTTP's optional
// whitespace.
const nbsp = "\xc2\xa0"

// noncharacter is U+FDD0, which no stamp field may hold, so a stamp holding it has no wire form.
const noncharacter = "\uFDD0"

// okSigner is the result, without its hand-over, of an OK check of the "response ok" case.
var okSigner = verify.Result{Reason: reason.OK, SuspectSvc: "payment", SuspectInst: "pay-1"}

// okResponse is the response stamp's own entry under influence in the "response ok" case: its block names
// influence with no item.
var okResponse = verify.StampItems{Svc: "payment", Named: true, Items: []string{}}

// TestHeaderNames pins the header names, the content type and the handshake path the spec gives.
func TestHeaderNames(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{wire.Chain, "X-Path-Chain"},
		{wire.Proof, "X-Path-Proof"},
		{wire.Extensions, "X-Path-Extensions"},
		{wire.Response, "X-Path-Response"},
		{wire.Session, "X-Path-Session"},
		{wire.ContentType, "application/json"},
		{wire.SessionPath, "/paztport/session"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

// TestIsPaztportBytes pins the byte reading of the prefix: the suffix is never read, the prefix is ASCII
// only, and no input panics.
func TestIsPaztportBytes(t *testing.T) {
	for name, tc := range map[string]struct {
		header string
		want   bool
	}{
		"suffix not read":      {"X-Path-\xff", true},
		"bare prefix":          {"X-Path-", true},
		"invalid lead byte":    {"\xff-Path-Chain", false},
		"invalid byte in stem": {"X-Path\xff", false},
		"empty":                {"", false},
		"one byte short":       {"X-Path", false},
		"hyphen replaced":      {"X-Path_Chain", false},
		"non-ASCII suffix":     {"X-Path-\u212a", true},
		"prefix not at start":  {"Y-X-Path-Chain", false},
		"lookalike hyphen":     {"X\u2010Path-Chain", false},
	} {
		t.Run(name, func(t *testing.T) {
			if got := wire.IsPaztport(tc.header); got != tc.want {
				t.Fatalf("IsPaztport(%q) = %t, want %t", tc.header, got, tc.want)
			}
		})
	}
}

// TestBindTargetsAsSent binds each target exactly as sent: nothing decoded or re-encoded, and only a bare
// trailing "?", which ends an empty query, left out.
func TestBindTargetsAsSent(t *testing.T) {
	body := []byte(`{"amount":100}`)
	for _, c := range []struct{ name, target, bound string }{
		{"no query", "/pay", "/pay"},
		{"empty query", "/pay?", "/pay"},
		{"query", "/pay?x=1", "/pay?x=1"},
		{"a ? inside the query", "/search?q=a?b", "/search?q=a?b"},
		{"a query of one ?", "/pay??", "/pay??"},
		{"a query ending in ?", "/pay?x?", "/pay?x?"},
		{"percent-encoding kept", "/p%C3%A9?q=caf%C3%A9", "/p%C3%A9?q=caf%C3%A9"},
		{"encoded ? kept", "/pay%3F", "/pay%3F"},
		{"raw non-ASCII kept", "/p\xc3\xa9?x=\xf0\x9f\x98\x80", "/p\xc3\xa9?x=\xf0\x9f\x98\x80"},
		{"plus kept", "/s?q=a+b", "/s?q=a+b"},
		{"dot segments kept", "/a/../b/./c", "/a/../b/./c"},
		{"only a ?", "?", ""},
		{"empty", "", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := wire.Bind("POST", c.target, body)
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if want := sha("POST\n" + c.bound + "\n" + string(body)); got != want {
				t.Fatalf("Bind = %s, want the binding of %q", got, c.bound)
			}
		})
	}
	encoded, err := wire.Bind("GET", "/p%C3%A9", nil)
	if err != nil {
		t.Fatalf("Bind of the percent-encoded target: %v", err)
	}
	raw, err := wire.Bind("GET", "/p\xc3\xa9", nil)
	if err != nil {
		t.Fatalf("Bind of the raw target: %v", err)
	}
	if encoded == raw {
		t.Fatal("a percent-encoded target binds as its raw form")
	}
}

// FuzzBind binds any method, target and body without panicking: text that is valid UTF-8 binds, and
// nothing else does; a target with no "?" binds as itself, and with a bare "?" added, as before.
func FuzzBind(f *testing.F) {
	for _, s := range []struct{ method, target, body string }{
		{"GET", "", ""}, {"GET", "?", ""}, {"POST", "/pay?", "{}"}, {"GET", "/a?b?", ""},
		{"G\xffT", "/a", ""}, {"GET", "/a" + surrogate, ""}, {"", "/p\xc3\xa9", "\xff"},
	} {
		f.Add(s.method, s.target, []byte(s.body))
	}
	f.Fuzz(func(t *testing.T, method, target string, body []byte) {
		got, err := wire.Bind(method, target, body)
		valid := utf8.ValidString(method) && utf8.ValidString(target)
		if valid != (err == nil) {
			t.Fatalf("Bind = %q, %v for text valid %t", got, err, valid)
		}
		if !valid || strings.Contains(target, "?") {
			return
		}
		if want := sha(method + "\n" + target + "\n" + string(body)); got != want {
			t.Fatalf("Bind = %s, want the binding of the target as given", got)
		}
		if bare, err := wire.Bind(method, target+"?", body); err != nil || bare != got {
			t.Fatalf("Bind with a bare ? = %s, %v, want %s", bare, err, got)
		}
	})
}

// TestBindBodyAsBytes binds the body as raw bytes, whether or not they are text.
func TestBindBodyAsBytes(t *testing.T) {
	body := []byte{0xff, 0x00, '\n', 0xfe}
	got, err := wire.Bind("PUT", "/blob", body)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if want := sha("PUT\n/blob\n" + string(body)); got != want {
		t.Fatalf("Bind = %s, want %s", got, want)
	}
}

// TestBindRefusesInvalidUTF8 gives no binding for a method or target that is not valid UTF-8, and the
// refusal never quotes it.
func TestBindRefusesInvalidUTF8(t *testing.T) {
	for _, c := range []struct{ name, method, target, names string }{
		{"target with a stray byte", "GET", "/a\xff", "target"},
		{"target with a lone surrogate", "GET", "/a" + surrogate + "?q=1", "target"},
		{"target cut mid-character", "GET", "/p\xc3", "target"},
		{"query not UTF-8", "GET", "/a?q=\xe9", "target"},
		{"method with a stray byte", "G\xffT", "/a", "method"},
		{"method with a lone surrogate", "GE" + surrogate + "T", "/a", "method"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := wire.Bind(c.method, c.target, nil)
			if err == nil {
				t.Fatalf("Bind bound it as %s", got)
			}
			msg := err.Error()
			if !strings.HasPrefix(msg, "paztport wire: ") || !strings.Contains(msg, c.names) {
				t.Errorf("the refusal %q does not name the %s", msg, c.names)
			}
			if strings.Contains(msg, "/a") || strings.Contains(msg, "\xff") || strings.Contains(msg, surrogate) {
				t.Errorf("the refusal %q quotes the input", msg)
			}
		})
	}
}

// TestResultHashStatus hashes the status in decimal before the body, so a body can't stand in for part
// of the status.
func TestResultHashStatus(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
	}{
		{200, ""}, {201, "x"}, {20, "0\nx"}, {599, "\xff"},
	} {
		want := sha("http-response\n" + strconv.Itoa(c.status) + "\n" + c.body)
		if got := wire.ResultHash(c.status, []byte(c.body)); got != want {
			t.Errorf("ResultHash(%d) = %s, want %s", c.status, got, want)
		}
	}
	if wire.ResultHash(20, []byte("0\nx")) == wire.ResultHash(200, []byte("x")) {
		t.Fatal("two statuses share a result hash")
	}
}

// TestHeaderValue trims only HTTP's optional whitespace, space and horizontal tab, and takes a value
// with nothing else as absent.
func TestHeaderValue(t *testing.T) {
	for _, c := range []struct {
		name, in, want string
		present        bool
	}{
		{"empty", "", "", false},
		{"spaces", "   ", "", false},
		{"tabs and spaces", " \t \t", "", false},
		{"a token", "abc", "abc", true},
		{"trailing space and tab", "abc \t", "abc", true},
		{"leading tab and space", "\t abc", "abc", true},
		{"inner space kept", "a b", "a b", true},
		{"trailing no-break space kept", "abc" + nbsp, "abc" + nbsp, true},
		{"a no-break space alone", nbsp, nbsp, true},
		{"trailing newline kept", "abc\n", "abc\n", true},
		{"trailing carriage return kept", "abc\r", "abc\r", true},
		{"vertical tab kept", "\vabc", "\vabc", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := wire.HeaderValue(c.in)
			if got != c.want || ok != c.present {
				t.Fatalf("HeaderValue = %q, %t, want %q, %t", got, ok, c.want, c.present)
			}
		})
	}
}

// TestCheckResponseHeaderValues checks the "response ok" case under header values an HTTP stack may hand
// over: optional whitespace around the token reads, and anything else around it does not.
func TestCheckResponseHeaderValues(t *testing.T) {
	rc := okCase(t)
	for _, c := range []struct {
		name, header string
		ok           bool
	}{
		{"as sent", rc.header, true},
		{"trailing space", rc.header + " ", true},
		{"trailing tab", rc.header + "\t", true},
		{"leading space and tab", " \t" + rc.header, true},
		{"trailing no-break space", rc.header + nbsp, false},
		{"leading no-break space", nbsp + rc.header, false},
		{"trailing newline", rc.header + "\r\n", false},
		{"blank", "", false},
		{"whitespace only", " \t ", false},
		{"two values joined", rc.header + ", " + rc.header, false},
		{"padded", rc.header + "=", false},
		{"cut short", rc.header[:len(rc.header)-1], false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := check(t, rc, c.header)
			if c.ok {
				wantOK(t, got)
				return
			}
			refused(t, got, rc, reason.ChainMissing)
		})
	}
}

// TestAResponseHeaderNotBlockAndStampIsChainMissing refuses, as CHAIN_MISSING, a header that does not read as an
// object of exactly block and stamp whose block reads as a block, version 3's {labels, stamp} among them. The
// stamp itself is the verifier's to read. None of them spends the response's nonce key, so the response as sent
// then verifies under the same verifier.
func TestAResponseHeaderNotBlockAndStampIsChainMissing(t *testing.T) {
	rc := okCase(t)
	block, stampValue := attestation(t, rc.header)
	member := func(name string, v json.Value) json.Member { return json.Member{Name: name, Value: v} }
	withBlock := func(b json.Value) string {
		return token(t, json.Obj(member("block", b), member("stamp", stampValue)))
	}
	names := func(ns ...string) json.Value {
		vs := make([]json.Value, len(ns))
		for i, n := range ns {
			vs[i] = json.S(n)
		}
		return json.Arr(vs...)
	}
	bw, err := json.Wire(block)
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	sw, err := json.Wire(stampValue)
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	raw := func(text string) string { return base64.RawURLEncoding.EncodeToString([]byte(text)) }
	beside := func(m json.Member) string {
		return token(t, json.Obj(member("block", block), m, member("stamp", stampValue)))
	}
	headers := map[string]string{
		"the stamp alone":          token(t, json.Obj(member("stamp", stampValue))),
		"the block alone":          token(t, json.Obj(member("block", block))),
		"no members":               token(t, json.Obj()),
		"a member beside them":     beside(member("x", json.I(1))),
		"a null member beside":     beside(member("sess", json.Null())),
		"version 3's labels":       token(t, json.Obj(member("labels", json.Arr()), member("stamp", stampValue))),
		"an array":                 token(t, json.Arr(block, stampValue)),
		"a block without requires": withBlock(json.Obj(member("items", json.Obj()))),
		"a null block":             withBlock(json.Null()),
		"an array of blocks":       withBlock(json.Arr(block)),
		"requires unsorted":        withBlock(json.Obj(member("items", json.Obj()), member("requires", names("b", "a")))),
		"a name that is no extension name": withBlock(json.Obj(
			member("items", json.Obj(member("Example", json.Arr()))), member("requires", json.Arr()))),
		"block bytes not canonical":   raw(`{"block":{"items":{"influence":[]}, "requires":[]},"stamp":` + string(sw) + `}`),
		"members reordered":           raw(`{"stamp":` + string(sw) + `,"block":` + string(bw) + `}`),
		"a stamp that is not a stamp": withStamp(t, block, json.I(3)),
	}
	v := rc.verifier()
	for name, header := range headers {
		t.Run(name, func(t *testing.T) {
			got, err := wire.CheckResponse(t.Context(), v, rc.sent, rc.sentBlocks, &rc.proof, header, rc.status,
				rc.body, rc.caller, "")
			if err != nil {
				t.Fatalf("CheckResponse: %v", err)
			}
			refused(t, got, rc, reason.ChainMissing)
		})
	}
	got, err := wire.CheckResponse(t.Context(), v, rc.sent, rc.sentBlocks, &rc.proof, rc.header, rc.status, rc.body,
		rc.caller, "")
	if err != nil {
		t.Fatalf("CheckResponse: %v", err)
	}
	wantOK(t, got)
}

// TestCheckResponseStampToVerifier hands the response stamp to the verifier unread, so its live order
// answers for it: the policy's window first, then the chain's reading.
func TestCheckResponseStampToVerifier(t *testing.T) {
	rc := okCase(t)
	block, stampValue := attestation(t, rc.header)
	notAStamp := withStamp(t, block, json.Obj(json.Member{Name: "v", Value: json.I(4)}))
	other := make([]json.Member, 0, len(stampValue.Members()))
	for _, m := range stampValue.Members() {
		if m.Name == "inst" {
			m.Value = json.S("pay-2")
		}
		other = append(other, m)
	}

	refused(t, check(t, rc, notAStamp), rc, reason.ChainMissing)
	refused(t, check(t, rc, withStamp(t, block, json.Obj(other...))), rc, reason.BadSignature)

	expired := rc
	expired.cfg.PolicyNotAfter = rc.cfg.Now() - 1
	refused(t, check(t, expired, notAStamp), expired, reason.PolicyExpired)
}

// TestCheckResponseSentChain checks the chain the caller passes: none is CHAIN_MISSING, a rid the
// response binding cannot carry is BINDING_MISMATCH, as is a key value the nonce key cannot, and the chain is
// left as it was.
func TestCheckResponseSentChain(t *testing.T) {
	rc := okCase(t)
	t.Run("nil", func(t *testing.T) {
		c := rc
		c.sent, c.sentBlocks = nil, nil
		refused(t, check(t, c, c.header), c, reason.ChainMissing)
	})
	t.Run("empty", func(t *testing.T) {
		c := rc
		c.sent, c.sentBlocks = stamp.Chain{}, stamp.Blocks{}
		refused(t, check(t, c, c.header), c, reason.ChainMissing)
	})
	for _, c := range []struct{ name, rid string }{
		{"rid not UTF-8", "rid-http-1\xff"},
		{"rid with a lone surrogate", "rid-" + surrogate},
		{"rid with a newline", "rid-http-1\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := rc
			bad.sent = slices.Clone(rc.sent)
			bad.sent[0].RID = c.rid
			refused(t, check(t, bad, bad.header), bad, reason.BindingMismatch)
		})
	}
	t.Run("a key value with a lone surrogate", func(t *testing.T) {
		got, err := wire.CheckResponse(t.Context(), rc.verifier(), rc.sent, rc.sentBlocks, &rc.proof, rc.header,
			rc.status, rc.body, rc.caller, "A"+surrogate)
		if err != nil {
			t.Fatalf("CheckResponse: %v", err)
		}
		refused(t, got, rc, reason.BindingMismatch)
	})
	t.Run("a stamp with no wire form", func(t *testing.T) {
		c := rc
		c.sent = slices.Clone(rc.sent)
		c.sent[1].Inst = "ord-" + noncharacter
		refused(t, check(t, c, c.header), c, reason.ChainMissing)
	})
	t.Run("left as it was", func(t *testing.T) {
		spare := stamp.Stamp{Svc: "spare"}
		backing := append(slices.Clone(rc.sent), spare)
		c := rc
		c.sent = backing[:len(rc.sent)]
		wantOK(t, check(t, c, c.header))
		if !slices.Equal(c.sent, rc.sent) || backing[len(rc.sent)] != spare {
			t.Fatal("CheckResponse changed the caller's chain or wrote past its end")
		}
	})
}

// TestCheckResponseReceiver checks the response as received by the caller named, never as received by the
// chain's own last receiver.
func TestCheckResponseReceiver(t *testing.T) {
	rc := okCase(t)
	c := rc
	c.caller = "gateway"
	refused(t, check(t, c, c.header), c, reason.BindingMismatch)
}

// TestCheckResponseProof checks the route with the proof the caller sent; with none, or one that can't be
// written, the route is not proved.
func TestCheckResponseProof(t *testing.T) {
	rc := okCase(t)
	unwritable := rc.proof
	unwritable.RootID = "mesh\xff"
	for name, proof := range map[string]*policy.Proof{"none": nil, "unwritable": &unwritable} {
		t.Run(name, func(t *testing.T) {
			got, err := wire.CheckResponse(t.Context(), rc.verifier(), rc.sent, rc.sentBlocks, proof, rc.header,
				rc.status, rc.body, rc.caller, "")
			if err != nil {
				t.Fatalf("CheckResponse: %v", err)
			}
			w := verify.Result{Reason: reason.PathNotAllowed, SuspectSvc: "payment", SuspectInst: "pay-1"}
			if got.Result != w {
				t.Fatalf("Result = %+v, want %+v", got.Result, w)
			}
			if r := got.Response(influence); r != nil {
				t.Fatalf("Response = %+v on a check that failed", r)
			}
		})
	}
}

// TestTheResponseNonceKeyIsAJCSArray writes each nonce key as the JCS text of its parts, so no part can run into
// its neighbour, and the key value comes before the direction.
func TestTheResponseNonceKeyIsAJCSArray(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{wire.ResponseNonceKey("rid-http-1", "payment", ""), `["rid-http-1","payment","resp"]`},
		{wire.ResponseNonceKey("rid-http-1", "payment#refund", "k1"), `["rid-http-1","payment#refund","k1","resp"]`},
		{wire.RequestNonceKey("r", "orders", "payment", ""), `["r","orders","payment","req"]`},
		{wire.RequestNonceKey("r", "orders", "payment#pay", "A1"), `["r","orders","payment#pay","A1","req"]`},
		{wire.RequestNonceKey("a\"b", "x", "y", ""), `["a\"b","x","y","req"]`},
	} {
		if c.got != c.want {
			t.Errorf("nonce key %s, want %s", c.got, c.want)
		}
	}
	if wire.RequestNonceKey("a|orders", "x", "payment", "") == wire.RequestNonceKey("a", "orders|x", "payment", "") {
		t.Error("two requests whose parts differ only in where a | falls share a nonce key")
	}
	if wire.ResponseNonceKey("r", "payment", "resp") == wire.RequestNonceKey("r", "payment", "resp", "") {
		t.Error("a response key and a request key share their text")
	}
	for name, key := range map[string]func(){
		"request":  func() { wire.RequestNonceKey("r"+surrogate, "orders", "payment", "") },
		"response": func() { wire.ResponseNonceKey("r", "payment", surrogate) },
	} {
		if !panics(key) {
			t.Errorf("a %s key with a part that is not UTF-8 did not panic", name)
		}
	}
}

// TestCheckResponseNonceKey spends the response key of the sent chain's rid and last stamp's rcv, whole
// (operation included).
func TestCheckResponseNonceKey(t *testing.T) {
	rc := okCase(t)
	cache := &recordingCache{}
	rc.cfg.Nonces = cache
	wantOK(t, check(t, rc, rc.header))
	want := []string{`["rid-http-1","payment","resp"]`}
	if !slices.Equal(cache.keys, want) || cache.keys[0] != wire.ResponseNonceKey("rid-http-1", "payment", "") {
		t.Fatalf("nonce keys %q, want %q", cache.keys, want)
	}
}

// TestCheckResponseCacheError answers with the nonce cache's error, which ctx reaches, and no verdict.
func TestCheckResponseCacheError(t *testing.T) {
	rc := okCase(t)
	rc.cfg.Nonces = &recordingCache{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := wire.CheckResponse(ctx, rc.verifier(), rc.sent, rc.sentBlocks, &rc.proof, rc.header, rc.status,
		rc.body, rc.caller, "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cache's context.Canceled", err)
	}
	if got.Result.OK() || got.Result.HandOver != nil || got.Response(influence) != nil {
		t.Fatalf("check = %+v alongside an error", got)
	}
	if got.ResultHash != wire.ResultHash(rc.status, rc.body) {
		t.Fatalf("ResultHash = %s, want the response's", got.ResultHash)
	}
}

// TestCheckResponseChecksTheSentBlocks checks a response against the blocks the call sent, then the response's
// own: the hand-over holds each stamp's entry, the response stamp's last; a sent block other than the one its
// stamp committed to is EXTENSION_MISMATCH, and so are blocks that together pass the wire limit. Sent blocks
// that are not one per stamp sent are a program fault.
func TestCheckResponseChecksTheSentBlocks(t *testing.T) {
	rc := okCase(t)
	ext, err := verify.NewExtensions([]string{"example"})
	if err != nil {
		t.Fatal(err)
	}
	rc.cfg.Extensions = ext
	sentBlocks := stamp.Blocks{stamp.EmptyBlock, newBlock(t, "example", "7")}
	respBlock := newBlock(t, "example", "8")
	sent, header := signedCall(t, rc, sentBlocks, respBlock)
	run := func(blocks stamp.Blocks, header string) wire.ResponseCheck {
		got, err := wire.CheckResponse(t.Context(), rc.verifier(), sent, blocks, &rc.proof, header, rc.status, rc.body,
			rc.caller, "")
		if err != nil {
			t.Fatalf("CheckResponse: %v", err)
		}
		return got
	}

	got := run(sentBlocks, header)
	if plain(got.Result) != okSigner {
		t.Fatalf("Result = %+v, want %+v", plain(got.Result), okSigner)
	}
	want := verify.StampItems{Svc: "payment", Named: true, Items: []string{"8"}}
	if r := got.Response("example"); r == nil || !handover.Same(*r, want) {
		t.Fatalf(`Response("example") = %+v, want %+v`, r, want)
	}
	under, ok := got.Result.HandOver.Under("example")
	wantUnder := []verify.StampItems{{Svc: "gateway"}, {Svc: "orders", Named: true, Items: []string{"7"}}, want}
	if !ok || !slices.EqualFunc(under, wantUnder, handover.Same) {
		t.Fatalf(`Under("example") = %+v, %t, want %+v`, under, ok, wantUnder)
	}

	altered := stamp.Blocks{stamp.EmptyBlock, newBlock(t, "example", "9")}
	refused(t, run(altered, header), rc, reason.ExtensionMismatch)

	big := func(n string) stamp.Block { return newBlock(t, "example", `"`+strings.Repeat(n, 140000)+`"`) }
	bigSent := stamp.Blocks{stamp.EmptyBlock, big("a")}
	bigChain, bigHeader := signedCall(t, rc, bigSent, big("b"))
	got, err = wire.CheckResponse(t.Context(), rc.verifier(), bigChain, bigSent, &rc.proof, bigHeader, rc.status,
		rc.body, rc.caller, "")
	if err != nil {
		t.Fatalf("CheckResponse: %v", err)
	}
	refused(t, got, rc, reason.ExtensionMismatch)

	for _, blocks := range []stamp.Blocks{nil, {stamp.EmptyBlock}, append(slices.Clone(sentBlocks), respBlock)} {
		if !panics(func() { run(blocks, header) }) {
			t.Errorf("%d sent blocks for %d stamps sent did not panic", len(blocks), len(sent))
		}
	}
}

// TestResponseIsNilUnlessOKAndActedOn hands out the response stamp's own entry only from a check that gave OK, and
// only for a name the caller acts on.
func TestResponseIsNilUnlessOKAndActedOn(t *testing.T) {
	rc := okCase(t)
	if r := (wire.ResponseCheck{}).Response(influence); r != nil {
		t.Fatalf("the zero ResponseCheck's Response = %+v", r)
	}
	wrong := rc
	wrong.caller = "gateway"
	if r := check(t, wrong, wrong.header).Response(influence); r != nil {
		t.Fatalf("a refused check's Response = %+v", r)
	}
	none, err := verify.NewExtensions(nil)
	if err != nil {
		t.Fatal(err)
	}
	notActing := rc
	notActing.cfg.Extensions = none
	got := check(t, notActing, notActing.header)
	if plain(got.Result) != okSigner {
		t.Fatalf("Result = %+v, want %+v", plain(got.Result), okSigner)
	}
	if r := got.Response(influence); r != nil {
		t.Fatalf("Response at a caller not acting on influence = %+v", r)
	}
	wantOK(t, check(t, rc, rc.header))
}

// TestEncodeChain writes a chain's token, which reads back as the chain, and refuses a chain that is empty
// or holds a stamp no signer may sign.
func TestEncodeChain(t *testing.T) {
	rc := okCase(t)
	tok, err := wire.EncodeChain(rc.sent)
	if err != nil {
		t.Fatalf("EncodeChain: %v", err)
	}
	if got, code := stamp.ReadChain(tok); code != reason.OK || !slices.Equal(got, rc.sent) {
		t.Fatalf("the token reads as %+v, %s", got, code)
	}
	if tok, err := wire.EncodeChain(nil); err == nil {
		t.Fatalf("EncodeChain(nil) = %q", tok)
	}
	bad := slices.Clone(rc.sent)
	bad[1].Inst = "ord-" + noncharacter
	if tok, err := wire.EncodeChain(bad); err == nil {
		t.Fatalf("EncodeChain wrote a stamp no signer may sign as %q", tok)
	}
}

// TestEncodeProof writes the mesh proof's token as v4.json holds it, and refuses a proof that can't be
// written.
func TestEncodeProof(t *testing.T) {
	rc := okCase(t)
	tok, err := wire.EncodeProof(rc.proof)
	if err != nil {
		t.Fatalf("EncodeProof: %v", err)
	}
	want := vectors.Load(t, "v4.json").Get("policies").Get("mesh").Get("proofTokens").Get("gateway/orders/payment").Str()
	if tok != want {
		t.Fatalf("EncodeProof = %s, want %s", tok, want)
	}
	bad := rc.proof
	bad.RootID = "mesh\xff"
	if tok, err := wire.EncodeProof(bad); err == nil {
		t.Fatalf("EncodeProof wrote a root id that is not UTF-8 as %q", tok)
	}
}

// TestEncodeBlocksWritesTheToken writes the blocks' token, one block per stamp in the order given, and refuses
// blocks whose wire bytes would pass the wire limit rather than drop any.
func TestEncodeBlocksWritesTheToken(t *testing.T) {
	tok, err := wire.EncodeBlocks(stamp.Blocks{stamp.EmptyBlock})
	if err != nil {
		t.Fatalf("EncodeBlocks: %v", err)
	}
	if got := decode(t, tok); got != `[{"items":{},"requires":[]}]` {
		t.Fatalf("the token holds %s", got)
	}
	two := stamp.Blocks{newBlock(t, "example", "7"), stamp.EmptyBlock}
	tok, err = wire.EncodeBlocks(two)
	if err != nil {
		t.Fatalf("EncodeBlocks: %v", err)
	}
	if got := decode(t, tok); got != `[{"items":{"example":[7]},"requires":[]},{"items":{},"requires":[]}]` {
		t.Fatalf("the token holds %s", got)
	}
	big := func(n string) stamp.Block { return newBlock(t, "example", `"`+strings.Repeat(n, 140000)+`"`) }
	if tok, err := wire.EncodeBlocks(stamp.Blocks{big("a"), big("b")}); err == nil {
		t.Fatalf("EncodeBlocks wrote blocks past the wire limit as a token of %d characters", len(tok))
	}
}

// TestEncodeResponseWritesBlockThenStamp writes the "response ok" case's header byte for byte from its stamp and
// block: the token of exactly {"block":<block>,"stamp":<stamp>}. It refuses a stamp no signer may sign and a
// header past the wire limit.
func TestEncodeResponseWritesBlockThenStamp(t *testing.T) {
	rc := okCase(t)
	blockValue, stampValue := attestation(t, rc.header)
	bw, err := json.Wire(blockValue)
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	block, err := stamp.ParseBlock(bw)
	if err != nil {
		t.Fatalf("the case's block: %v", err)
	}
	sw, err := json.Wire(json.Arr(stampValue))
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	resp, code := stamp.ParseChain(sw)
	if code != reason.OK {
		t.Fatalf("the case's response stamp: %s", code)
	}
	got, err := wire.EncodeResponse(resp[0], block)
	if err != nil {
		t.Fatalf("EncodeResponse: %v", err)
	}
	if got != rc.header {
		t.Fatalf("EncodeResponse = %s, want %s", got, rc.header)
	}
	stampText, err := resp[0].Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if text := decode(t, got); text != `{"block":`+string(block.Wire())+`,"stamp":`+string(stampText)+`}` {
		t.Fatalf("the header holds %s", text)
	}
	empty, err := wire.EncodeResponse(resp[0], stamp.EmptyBlock)
	if err != nil {
		t.Fatalf("EncodeResponse with the empty block: %v", err)
	}
	if text := decode(t, empty); text != `{"block":{"items":{},"requires":[]},"stamp":`+string(stampText)+`}` {
		t.Fatalf("the header holds %s", text)
	}

	bad := resp[0]
	bad.Rcv = "or" + noncharacter + "ders"
	if tok, err := wire.EncodeResponse(bad, block); err == nil {
		t.Fatalf("EncodeResponse wrote a stamp no signer may sign as %q", tok)
	}
	huge := newBlock(t, "example", `"`+strings.Repeat("a", 262000)+`"`)
	if tok, err := wire.EncodeResponse(resp[0], huge); err == nil {
		t.Fatalf("EncodeResponse wrote a header past the wire limit as a token of %d characters", len(tok))
	}
}

// FuzzCheckResponseHeader checks the "response ok" case under any header value: CheckResponse never
// panics, always returns the result hash, and hands out the response's entry only with an OK check.
func FuzzCheckResponseHeader(f *testing.F) {
	rc := okCase(f)
	for _, s := range []string{rc.header, rc.header + " ", rc.header + nbsp, "", " ", "e30", "W10", rc.header[1:]} {
		f.Add(s)
	}
	hash := wire.ResultHash(rc.status, rc.body)
	f.Fuzz(func(t *testing.T, header string) {
		got := check(t, rc, header)
		if got.ResultHash != hash {
			t.Fatalf("ResultHash = %s, want %s", got.ResultHash, hash)
		}
		if r := got.Response(influence); !got.Result.OK() && r != nil {
			t.Fatalf("Response %+v with %s", r, got.Result.Reason)
		}
	})
}

// influence is the extension the "response ok" case's caller acts on.
const influence = "influence"

// okCase returns http-v4.json's "response ok" case, read.
func okCase(t testing.TB) responseCase {
	t.Helper()
	var rc *responseCase
	vectors.Load(t, "http-v4.json").Get("responses").Each(func(name string, c vectors.Node) {
		if name == "response ok" {
			r := readResponseCase(t, c)
			rc = &r
		}
	})
	if rc == nil {
		t.Fatal(`http-v4.json has no "response ok" case`)
	}
	return *rc
}

// check runs CheckResponse once on rc with header, under a verifier of its own.
func check(t testing.TB, rc responseCase, header string) wire.ResponseCheck {
	t.Helper()
	got, err := wire.CheckResponse(t.Context(), rc.verifier(), rc.sent, rc.sentBlocks, &rc.proof, header, rc.status,
		rc.body, rc.caller, "")
	if err != nil {
		t.Fatalf("CheckResponse: %v", err)
	}
	return got
}

// wantOK fails t unless got is the "response ok" case's OK check, handing out the response stamp's entry.
func wantOK(t *testing.T, got wire.ResponseCheck) {
	t.Helper()
	if plain(got.Result) != okSigner {
		t.Fatalf("Result = %+v, want %+v", plain(got.Result), okSigner)
	}
	if r := got.Response(influence); r == nil || !handover.Same(*r, okResponse) {
		t.Fatalf("Response = %+v, want %+v", r, okResponse)
	}
}

// refused fails t unless got is a refusal for code that names no one, hands nothing over and has rc's result
// hash.
func refused(t *testing.T, got wire.ResponseCheck, rc responseCase, code reason.Code) {
	t.Helper()
	if w := (verify.Result{Reason: code}); got.Result != w {
		t.Errorf("Result = %+v, want %+v", got.Result, w)
	}
	if r := got.Response(influence); r != nil {
		t.Errorf("Response = %+v on a check that failed", r)
	}
	if h := wire.ResultHash(rc.status, rc.body); got.ResultHash != h {
		t.Errorf("ResultHash = %s, want %s", got.ResultHash, h)
	}
}

// plain returns r without its hand-over, for comparing the rest with ==.
func plain(r verify.Result) verify.Result {
	r.HandOver = nil
	return r
}

// attestation returns the block and stamp the response header holds.
func attestation(t *testing.T, header string) (block, s json.Value) {
	t.Helper()
	v, err := json.ReadToken(header)
	if err != nil {
		t.Fatalf("the header: %v", err)
	}
	block, okB := json.Field(v, "block")
	s, okS := json.Field(v, "stamp")
	if !okB || !okS {
		t.Fatal("the header lacks block or stamp")
	}
	return block, s
}

// withStamp returns the token of the header holding block and s.
func withStamp(t *testing.T, block, s json.Value) string {
	t.Helper()
	return token(t, json.Obj(json.Member{Name: "block", Value: block}, json.Member{Name: "stamp", Value: s}))
}

// token returns v's token.
func token(t *testing.T, v json.Value) string {
	t.Helper()
	tok, err := json.Token(v)
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	return tok
}

// decode returns the text a token holds, decoded apart from the package under test.
func decode(t *testing.T, tok string) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("the token: %v", err)
	}
	return string(b)
}

// newBlock returns the block naming name with items, each the canonical text of one value.
func newBlock(t *testing.T, name string, items ...string) stamp.Block {
	t.Helper()
	b, err := stamp.NewBlock(map[string][]string{name: items}, nil)
	if err != nil {
		t.Fatalf("NewBlock: %v", err)
	}
	return b
}

// signedCall signs, under the vector keys, the call the "response ok" case describes, gateway to orders to
// payment, with each sent stamp committing to its block of sentBlocks, and payment's response to rc's status and
// body committing to respBlock. It returns the chain sent and the response header.
func signedCall(t *testing.T, rc responseCase, sentBlocks stamp.Blocks, respBlock stamp.Block) (stamp.Chain, string) {
	t.Helper()
	now := rc.cfg.Now()
	sign := func(s stamp.Stamp) stamp.Stamp {
		key, _ := vectors.VectorKey(t, s.Svc)
		signed, err := stamp.Sign(s, key)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return signed
	}
	gw := sign(stamp.Stamp{Svc: "gateway", Inst: "gw-1", RID: "rid-blocks", TS: now - 1000, Rcv: "orders", Bind: "b",
		Ext: sentBlocks[0].Commit()})
	ord := sign(stamp.Stamp{Svc: "orders", Inst: "ord-1", RID: "rid-blocks", TS: now - 500, Rcv: "payment", Bind: "b",
		Ext: sentBlocks[1].Commit(), Prev: gw.Sig})
	bind, err := stamp.ResponseBinding(wire.ResultHash(rc.status, rc.body), "rid-blocks")
	if err != nil {
		t.Fatal(err)
	}
	resp := sign(stamp.Stamp{Svc: "payment", Inst: "pay-1", RID: "rid-blocks", TS: now, Rcv: "orders", Bind: bind,
		Ext: respBlock.Commit(), Prev: ord.Sig})
	header, err := wire.EncodeResponse(resp, respBlock)
	if err != nil {
		t.Fatalf("EncodeResponse: %v", err)
	}
	return stamp.Chain{gw, ord}, header
}

// panics reports whether f panics.
func panics(f func()) (did bool) {
	defer func() { did = recover() != nil }()
	f()
	return false
}

// sha returns b64url(SHA-256(s)), computed apart from the package under test.
func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// recordingCache is a NonceCache that records each key offered and never remembers one, and honours its
// context.
type recordingCache struct {
	keys []string
}

func (c *recordingCache) SeenBefore(ctx context.Context, key string, _ int64) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	c.keys = append(c.keys, key)
	return false, nil
}

func (c *recordingCache) TTL() int64 { return verify.NonceTTLMs }

// TestCheckResponseNonceKeyKeepsTheOperation spends the response key of <service>#<operation> when the sent
// chain's last rcv names an operation, so a second check of the same response is a replay and the service's key
// alone is left unspent.
func TestCheckResponseNonceKeyKeepsTheOperation(t *testing.T) {
	rc := okCase(t)
	now := rc.cfg.Now()
	gwKey, _ := vectors.VectorKey(t, "gateway")
	ordKey, _ := vectors.VectorKey(t, "orders")
	sign := func(s stamp.Stamp, k ed25519.PrivateKey) stamp.Stamp {
		signed, err := stamp.Sign(s, k)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		return signed
	}
	sent := stamp.Chain{sign(stamp.Stamp{Svc: "gateway", Inst: "gw-1", RID: "rid-op", TS: now, Rcv: "orders#createOrder",
		Bind: "b"}, gwKey)}
	hash := wire.ResultHash(200, []byte("ok"))
	bind, err := stamp.ResponseBinding(hash, "rid-op")
	if err != nil {
		t.Fatal(err)
	}
	resp := sign(stamp.Stamp{Svc: "orders", Inst: "ord-1", RID: "rid-op", TS: now, Rcv: "gateway", Bind: bind,
		Prev: sent[0].Sig}, ordKey)
	header, err := wire.EncodeResponse(resp, stamp.EmptyBlock)
	if err != nil {
		t.Fatal(err)
	}

	salt := []byte("0123456789abcdef")
	root, err := policy.LeafHash(salt, "gateway/orders#createOrder")
	if err != nil {
		t.Fatal(err)
	}
	proof := policy.Proof{LeafSalt: salt, RootID: "ops"}
	rc.cfg.Roots = []verify.PinnedRoot{{Root: root, RootID: "ops", NotAfter: rc.cfg.PolicyNotAfter}}
	rc.cfg.AllowedOrigins = []string{"gateway"}
	cache := verify.NewMemoryNonceCache(verify.NonceTTLMs)
	rc.cfg.Nonces = cache
	v := rc.verifier()
	sentBlocks := stamp.Blocks{stamp.EmptyBlock}

	got, err := wire.CheckResponse(t.Context(), v, sent, sentBlocks, &proof, header, 200, []byte("ok"), "gateway", "")
	if err != nil || got.Result.Reason != reason.OK {
		t.Fatalf("CheckResponse = %+v, %v, want OK", got.Result, err)
	}
	got, err = wire.CheckResponse(t.Context(), v, sent, sentBlocks, &proof, header, 200, []byte("ok"), "gateway", "")
	if err != nil || got.Result.Reason != reason.Replay {
		t.Fatalf("a second CheckResponse = %+v, %v, want REPLAY", got.Result, err)
	}
	for key, want := range map[string]bool{
		`["rid-op","orders#createOrder","resp"]`: true,
		`["rid-op","orders","resp"]`:             false,
	} {
		if seen, err := cache.SeenBefore(t.Context(), key, now); err != nil || seen != want {
			t.Errorf("SeenBefore(%s) = %v, %v, want %v", key, seen, err, want)
		}
	}
}
