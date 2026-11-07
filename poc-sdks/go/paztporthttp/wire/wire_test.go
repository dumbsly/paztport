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

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
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

// okLabels are the labels the "response ok" case's attestation carries.
var okLabels = []influence.Label{{Class: influence.Private, CID: "cid-receipt-1", Owner: "alice"}}

// okSigner is the suspect an OK check of the "response ok" case names.
var okSigner = verify.Result{Reason: reason.OK, SuspectSvc: "payment", SuspectInst: "pay-1"}

// TestHeaderNames pins the header names, the content type and the handshake path the spec gives.
func TestHeaderNames(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{wire.Chain, "X-Path-Chain"},
		{wire.Proof, "X-Path-Proof"},
		{wire.Influence, "X-Path-Influence"},
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
				if got.Result != okSigner || !slices.Equal(got.Labels, okLabels) {
					t.Fatalf("check = %+v, want OK with the case's labels", got)
				}
				return
			}
			refused(t, got, rc, reason.ChainMissing)
		})
	}
}

// TestCheckResponseShape refuses a header that does not hold exactly labels and stamp, or whose labels
// are not well formed, as CHAIN_MISSING; the stamp itself is the verifier's to read.
func TestCheckResponseShape(t *testing.T) {
	rc := okCase(t)
	labels, stampValue := attestation(t, rc.header)
	member := func(name string, v json.Value) json.Member { return json.Member{Name: name, Value: v} }
	for _, c := range []struct {
		name    string
		members []json.Member
	}{
		{"an extra member", []json.Member{member("labels", labels), member("stamp", stampValue), member("x", json.I(0))}},
		{"an extra null member", []json.Member{
			member("labels", labels), member("sess", json.Null()), member("stamp", stampValue),
		}},
		{"no labels", []json.Member{member("stamp", stampValue)}},
		{"no stamp", []json.Member{member("labels", labels)}},
		{"no members", nil},
		{"labels an object", []json.Member{member("labels", json.Obj()), member("stamp", stampValue)}},
		{"labels null", []json.Member{member("labels", json.Null()), member("stamp", stampValue)}},
		{"a label of an unknown class", []json.Member{
			member("labels", json.Arr(json.Obj(member("cid", json.S("c")), member("cls", json.S("secret"))))),
			member("stamp", stampValue),
		}},
		{"a label with an empty owner", []json.Member{
			member("labels", json.Arr(json.Obj(member("cid", json.S("c")), member("cls", json.S("private")),
				member("owner", json.S(""))))),
			member("stamp", stampValue),
		}},
		{"a label with an extra member", []json.Member{
			member("labels", json.Arr(json.Obj(member("cid", json.S("cid-receipt-1")), member("cls", json.S("private")),
				member("owner", json.S("alice")), member("x", json.S(""))))),
			member("stamp", stampValue),
		}},
		{"a stamp that is not a stamp", []json.Member{member("labels", labels), member("stamp", json.I(3))}},
	} {
		t.Run(c.name, func(t *testing.T) {
			refused(t, check(t, rc, token(t, json.Obj(c.members...))), rc, reason.ChainMissing)
		})
	}
	t.Run("bytes not canonical", func(t *testing.T) {
		b, err := json.Wire(json.Obj(
			json.Member{Name: "labels", Value: labels}, json.Member{Name: "stamp", Value: stampValue},
		))
		if err != nil {
			t.Fatalf("Wire: %v", err)
		}
		lb, err := json.Wire(labels)
		if err != nil {
			t.Fatalf("Wire: %v", err)
		}
		sb, err := json.Wire(stampValue)
		if err != nil {
			t.Fatalf("Wire: %v", err)
		}
		for name, text := range map[string]string{
			"members reordered": `{"stamp":` + string(sb) + `,"labels":` + string(lb) + `}`,
			"a space":           `{"labels": ` + string(lb) + `,"stamp":` + string(sb) + `}`,
			"a trailing space":  string(b) + " ",
		} {
			t.Run(name, func(t *testing.T) {
				header := base64.RawURLEncoding.EncodeToString([]byte(text))
				refused(t, check(t, rc, header), rc, reason.ChainMissing)
			})
		}
	})
	t.Run("an array", func(t *testing.T) {
		refused(t, check(t, rc, token(t, json.Arr(labels, stampValue))), rc, reason.ChainMissing)
	})
}

// TestCheckResponseStampToVerifier hands the response stamp to the verifier unread, so its live order
// answers for it: the policy's window first, then the chain's reading.
func TestCheckResponseStampToVerifier(t *testing.T) {
	rc := okCase(t)
	labels, stampValue := attestation(t, rc.header)
	header := func(s json.Value) string {
		return token(t, json.Obj(json.Member{Name: "labels", Value: labels}, json.Member{Name: "stamp", Value: s}))
	}
	notAStamp := header(json.Obj(json.Member{Name: "v", Value: json.I(3)}))
	piped := make([]json.Member, 0, len(stampValue.Members()))
	for _, m := range stampValue.Members() {
		if m.Name == "inst" {
			m.Value = json.S("pay|1")
		}
		piped = append(piped, m)
	}

	refused(t, check(t, rc, notAStamp), rc, reason.ChainMissing)
	refused(t, check(t, rc, header(json.Obj(piped...))), rc, reason.BadSignature)

	expired := rc
	expired.cfg.PolicyNotAfter = rc.cfg.Now() - 1
	refused(t, check(t, expired, notAStamp), expired, reason.PolicyExpired)
}

// TestCheckResponseSentChain checks the chain the caller passes: none is CHAIN_MISSING, a rid the
// response binding cannot carry is BINDING_MISMATCH, and the chain is left as it was.
func TestCheckResponseSentChain(t *testing.T) {
	rc := okCase(t)
	t.Run("nil", func(t *testing.T) {
		c := rc
		c.sent = nil
		refused(t, check(t, c, c.header), c, reason.ChainMissing)
	})
	t.Run("empty", func(t *testing.T) {
		c := rc
		c.sent = stamp.Chain{}
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
	t.Run("a stamp with no wire form", func(t *testing.T) {
		c := rc
		c.sent = slices.Clone(rc.sent)
		c.sent[1].Inst = "ord|1"
		refused(t, check(t, c, c.header), c, reason.ChainMissing)
	})
	t.Run("left as it was", func(t *testing.T) {
		spare := stamp.Stamp{Svc: "spare"}
		backing := append(slices.Clone(rc.sent), spare)
		c := rc
		c.sent = backing[:len(rc.sent)]
		if got := check(t, c, c.header); got.Result != okSigner {
			t.Fatalf("Result = %+v, want %+v", got.Result, okSigner)
		}
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
			got, err := wire.CheckResponse(t.Context(), rc.verifier(), rc.sent, proof, rc.header, rc.status, rc.body,
				rc.caller)
			if err != nil {
				t.Fatalf("CheckResponse: %v", err)
			}
			w := verify.Result{Reason: reason.PathNotAllowed, SuspectSvc: "payment", SuspectInst: "pay-1"}
			if got.Result != w {
				t.Fatalf("Result = %+v, want %+v", got.Result, w)
			}
			if got.Labels != nil {
				t.Fatalf("Labels = %+v on a check that failed", got.Labels)
			}
		})
	}
}

// TestCheckResponseNonceKey spends the key <rid>|<target>|resp, the target being the sent chain's last
// rcv.
func TestCheckResponseNonceKey(t *testing.T) {
	rc := okCase(t)
	cache := &recordingCache{}
	rc.cfg.Nonces = cache
	if got := check(t, rc, rc.header); got.Result != okSigner {
		t.Fatalf("Result = %+v, want %+v", got.Result, okSigner)
	}
	if want := []string{"rid-http-1|payment|resp"}; !slices.Equal(cache.keys, want) {
		t.Fatalf("nonce keys %q, want %q", cache.keys, want)
	}
}

// TestCheckResponseCacheError answers with the nonce cache's error, which ctx reaches, and no verdict.
func TestCheckResponseCacheError(t *testing.T) {
	rc := okCase(t)
	rc.cfg.Nonces = &recordingCache{}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got, err := wire.CheckResponse(ctx, rc.verifier(), rc.sent, &rc.proof, rc.header, rc.status, rc.body,
		rc.caller)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the cache's context.Canceled", err)
	}
	if got.Result.OK() || got.Labels != nil {
		t.Fatalf("check = %+v alongside an error", got)
	}
	if got.ResultHash != wire.ResultHash(rc.status, rc.body) {
		t.Fatalf("ResultHash = %s, want the response's", got.ResultHash)
	}
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
	bad[1].Inst = "ord|1"
	if tok, err := wire.EncodeChain(bad); err == nil {
		t.Fatalf("EncodeChain wrote a stamp no signer may sign as %q", tok)
	}
}

// TestEncodeProof writes the mesh proof's token as v3.json holds it, and refuses a proof that can't be
// written.
func TestEncodeProof(t *testing.T) {
	rc := okCase(t)
	tok, err := wire.EncodeProof(rc.proof)
	if err != nil {
		t.Fatalf("EncodeProof: %v", err)
	}
	want := vectors.Load(t, "v3.json").Get("policies").Get("mesh").Get("proofTokens").Get("gateway/orders/payment").Str()
	if tok != want {
		t.Fatalf("EncodeProof = %s, want %s", tok, want)
	}
	bad := rc.proof
	bad.RootID = "mesh\xff"
	if tok, err := wire.EncodeProof(bad); err == nil {
		t.Fatalf("EncodeProof wrote a root id that is not UTF-8 as %q", tok)
	}
}

// TestEncodeInfluence sends no header for no influence, and otherwise the entries in the order given.
func TestEncodeInfluence(t *testing.T) {
	for _, none := range [][]influence.Entry{nil, {}} {
		if tok, err := wire.EncodeInfluence(none); tok != "" || err != nil {
			t.Fatalf("EncodeInfluence(%#v) = %q, %v, want no header", none, tok, err)
		}
	}
	es := []influence.Entry{
		{Class: influence.ThirdParty, Src: "web:z", H: "h-2"},
		{Class: influence.Private, Src: "http:orders", H: "h-1", CID: "", HasCID: true, Owner: "alice"},
	}
	tok, err := wire.EncodeInfluence(es)
	if err != nil {
		t.Fatalf("EncodeInfluence = %q, %v", tok, err)
	}
	if got, err := influence.ReadEntries(tok); err != nil || !slices.Equal(got, es) {
		t.Fatalf("the token reads as %+v, %v", got, err)
	}
	if tok, err := wire.EncodeInfluence([]influence.Entry{{Class: "secret", Src: "s", H: "h"}}); err == nil || tok != "" {
		t.Fatalf("EncodeInfluence of an unknown class = %q, %v", tok, err)
	}
}

// TestEncodeResponse writes the "response ok" case's header byte for byte from its stamp and labels.
func TestEncodeResponse(t *testing.T) {
	rc := okCase(t)
	_, stampValue := attestation(t, rc.header)
	b, err := json.Wire(json.Arr(stampValue))
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	resp, code := stamp.ParseChain(b)
	if code != reason.OK {
		t.Fatalf("the case's response stamp: %s", code)
	}
	got, err := wire.EncodeResponse(resp[0], okLabels)
	if err != nil {
		t.Fatalf("EncodeResponse: %v", err)
	}
	if got != rc.header {
		t.Fatalf("EncodeResponse = %s, want %s", got, rc.header)
	}

	none, err := wire.EncodeResponse(resp[0], nil)
	if err != nil {
		t.Fatalf("EncodeResponse with no labels: %v", err)
	}
	if ls, _ := attestation(t, none); ls.Kind() != json.KindArray || len(ls.Items()) != 0 {
		t.Fatal("no labels are not written as []")
	}

	bad := resp[0]
	bad.Rcv = "or|ders"
	if tok, err := wire.EncodeResponse(bad, okLabels); err == nil {
		t.Fatalf("EncodeResponse wrote a stamp no signer may sign as %q", tok)
	}
	if tok, err := wire.EncodeResponse(resp[0], []influence.Label{{Class: "secret", CID: "c"}}); err == nil {
		t.Fatalf("EncodeResponse wrote a label of an unknown class as %q", tok)
	}
}

// FuzzCheckResponseHeader checks the "response ok" case under any header value: CheckResponse never
// panics, always returns the result hash, and returns labels only with an OK check.
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
		if !got.Result.OK() && got.Labels != nil {
			t.Fatalf("labels %+v with %s", got.Labels, got.Result.Reason)
		}
	})
}

// okCase returns http-v3.json's "response ok" case, read.
func okCase(t testing.TB) responseCase {
	t.Helper()
	var rc *responseCase
	vectors.Load(t, "http-v3.json").Get("responses").Each(func(name string, c vectors.Node) {
		if name == "response ok" {
			r := readResponseCase(t, c)
			rc = &r
		}
	})
	if rc == nil {
		t.Fatal(`http-v3.json has no "response ok" case`)
	}
	return *rc
}

// check runs CheckResponse once on rc with header, under a verifier of its own.
func check(t testing.TB, rc responseCase, header string) wire.ResponseCheck {
	t.Helper()
	got, err := wire.CheckResponse(t.Context(), rc.verifier(), rc.sent, &rc.proof, header, rc.status, rc.body,
		rc.caller)
	if err != nil {
		t.Fatalf("CheckResponse: %v", err)
	}
	return got
}

// refused fails t unless got is a refusal for code that names no one, carries no labels and has rc's
// result hash.
func refused(t *testing.T, got wire.ResponseCheck, rc responseCase, code reason.Code) {
	t.Helper()
	if w := (verify.Result{Reason: code}); got.Result != w {
		t.Errorf("Result = %+v, want %+v", got.Result, w)
	}
	if got.Labels != nil {
		t.Errorf("Labels = %+v on a check that failed", got.Labels)
	}
	if h := wire.ResultHash(rc.status, rc.body); got.ResultHash != h {
		t.Errorf("ResultHash = %s, want %s", got.ResultHash, h)
	}
}

// attestation returns the labels and stamp the response header holds.
func attestation(t *testing.T, header string) (labels, s json.Value) {
	t.Helper()
	v, err := json.ReadToken(header)
	if err != nil {
		t.Fatalf("the header: %v", err)
	}
	labels, okL := json.Field(v, "labels")
	s, okS := json.Field(v, "stamp")
	if !okL || !okS {
		t.Fatal("the header lacks labels or stamp")
	}
	return labels, s
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

// TestCheckResponseNonceKeyUsesTheBareTarget spends <rid>|<service>|resp when the sent chain's last rcv names an
// operation, so a second check of the same response is a replay and the key holds no '#'.
func TestCheckResponseNonceKeyUsesTheBareTarget(t *testing.T) {
	rc := okCase(t)
	now := rc.cfg.Now()
	gwKey, _ := vectors.V3Key(t, "gateway")
	ordKey, _ := vectors.V3Key(t, "orders")
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
	bind, err := stamp.ResponseBinding(hash, "rid-op", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp := sign(stamp.Stamp{Svc: "orders", Inst: "ord-1", RID: "rid-op", TS: now, Rcv: "gateway", Bind: bind,
		Prev: sent[0].Sig}, ordKey)
	header, err := wire.EncodeResponse(resp, nil)
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

	got, err := wire.CheckResponse(t.Context(), v, sent, &proof, header, 200, []byte("ok"), "gateway")
	if err != nil || got.Result.Reason != reason.OK {
		t.Fatalf("CheckResponse = %+v, %v, want OK", got.Result, err)
	}
	got, err = wire.CheckResponse(t.Context(), v, sent, &proof, header, 200, []byte("ok"), "gateway")
	if err != nil || got.Result.Reason != reason.Replay {
		t.Fatalf("a second CheckResponse = %+v, %v, want REPLAY", got.Result, err)
	}
	if seen, err := cache.SeenBefore(t.Context(), "rid-op|orders|resp", now); err != nil || !seen {
		t.Fatalf("SeenBefore(rid-op|orders|resp) = %v, %v, want true", seen, err)
	}
}
