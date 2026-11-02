// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"bytes"
	"crypto/ed25519"
	"slices"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
)

// handshake is a handshake to change: v3.json's sessionReply case "entry-key form attested", read.
type handshake struct {
	req    session.Request
	reply  session.Reply
	wire   []byte // the reply's bytes
	pin    string // the server's policy key
	entry  string // the server's entry service
	now    int64
	signer ed25519.PrivateKey // the entry service's key, which signs the reply
	client ed25519.PrivateKey // the client's policy key
	server ed25519.PrivateKey // the server's policy key
}

func attestedHandshake(t *testing.T) handshake {
	t.Helper()
	v3 := vectors.Load(t, "v3.json")
	var c vectors.Node
	v3.Get("sessionReply").Each(func(name string, n vectors.Node) {
		if name == "entry-key form attested" {
			c = n.With(t)
		}
	})
	req, err := session.ReadRequest(c.Get("requestToken").Str())
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	wire := decode(t, c.Get("replyToken").Str())
	reply, err := session.ParseReply(wire)
	if err != nil {
		t.Fatalf("ParseReply: %v", err)
	}
	h := handshake{req: req, reply: reply, wire: wire, pin: pub(t, v3, c.Get("pin").Str()),
		entry: c.Get("serverEntry").Str(), now: c.Get("now").Int()}
	h.signer, _ = vectors.V3Key(t, h.entry)
	h.client, _ = vectors.V3Key(t, "client-policy")
	h.server, _ = vectors.V3Key(t, "server-policy")
	if got := session.CheckReply(wire, req, h.pin, h.entry, h.now); got != session.Attested {
		t.Fatalf("the handshake's reply is %s", got)
	}
	return h
}

// sign returns reply, its session id derived again from req and signed by key, as its bytes.
func (h handshake) sign(t *testing.T, req session.Request, reply session.Reply, key ed25519.PrivateKey) []byte {
	t.Helper()
	id, ok := session.ID(req, reply.ServerRoot, reply.Nonce)
	if !ok {
		t.Fatal("ID: no session id")
	}
	reply.Sess = id
	signed, err := session.SignReply(reply, key)
	if err != nil {
		t.Fatalf("SignReply: %v", err)
	}
	b, err := signed.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	return b
}

// TestID checks the session id a handshake's messages give: the vector's own, the one DeriveID gives for
// their decoded parts, and none for a present root whose sig does not decode or a nonce of another length.
func TestID(t *testing.T) {
	h := attestedHandshake(t)
	id, ok := session.ID(h.req, h.reply.ServerRoot, h.reply.Nonce)
	if !ok || id != h.reply.Sess {
		t.Fatalf("ID = %q, %t; want the reply's %q", id, ok, h.reply.Sess)
	}
	derived, ok := session.DeriveID(decode(t, h.req.ClientRoot.Sig), decode(t, h.reply.ServerRoot.Sig),
		decode(t, h.req.Nonce), decode(t, h.reply.Nonce), h.req.ClientPolicyKey, h.req.ClientKeyring)
	if !ok || derived != id {
		t.Fatalf("DeriveID = %q, %t; want ID's %q", derived, ok, id)
	}
	if other, ok := session.ID(h.req, nil, h.reply.Nonce); ok && other == id {
		t.Fatal("ID gave a handshake without the server root the same id")
	}

	root := *h.reply.ServerRoot
	root.Sig = "!"
	if got, ok := session.ID(h.req, &root, h.reply.Nonce); ok {
		t.Errorf("ID took a server root whose sig does not decode, as %q", got)
	}
	req := h.req
	clientRoot := *req.ClientRoot
	clientRoot.Sig = ""
	req.ClientRoot = &clientRoot
	if got, ok := session.ID(req, h.reply.ServerRoot, h.reply.Nonce); ok {
		t.Errorf("ID took a client root with an empty sig, as %q", got)
	}
	if got, ok := session.ID(h.req, h.reply.ServerRoot, h.reply.Nonce[1:]); ok {
		t.Errorf("ID took a server nonce of another length, as %q", got)
	}
}

// signersByPub returns the private key of each of v3.json's keys, by its public key.
func signersByPub(t *testing.T, v3 vectors.Node) map[string]ed25519.PrivateKey {
	t.Helper()
	signers := map[string]ed25519.PrivateKey{}
	for _, name := range v3.With(t).Get("keys").Names() {
		priv, _ := vectors.V3Key(t, name)
		signers[pub(t, v3, name)] = priv
	}
	return signers
}

// replace returns the canonical bytes of the object wire holds, its member name set to v, added when
// absent.
func replace(t *testing.T, wire []byte, name string, v json.Value) []byte {
	t.Helper()
	return edit(t, wire, name, &v)
}

// edit is replace, and takes the member out when v is nil.
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

// TestEmptyKeyringSig pins an asymmetry the spec makes: a reply whose serverKeyringSig is empty reads, and
// fails the check as BAD_SIGNATURE, since an empty text is a signature that does not verify; a request whose
// clientKeyringSig is empty does not read, and the server answers Invalid params.
func TestEmptyKeyringSig(t *testing.T) {
	h := attestedHandshake(t)
	wire := replace(t, h.wire, "serverKeyringSig", json.S(""))
	if _, err := session.ParseReply(wire); err != nil {
		t.Fatalf("ParseReply refused a reply with an empty serverKeyringSig: %v", err)
	}
	if got := session.CheckReply(wire, h.req, h.pin, h.entry, h.now); got != session.BadSignature {
		t.Fatalf("CheckReply = %s, want %s", got, session.BadSignature)
	}

	req, err := h.req.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if _, err := session.ParseRequest(replace(t, req, "clientKeyringSig", json.S(""))); err == nil {
		t.Fatal("ParseRequest read a request with an empty clientKeyringSig")
	}
	empty := h.req
	empty.ClientKeyringSig = ""
	if _, err := empty.Wire(); err == nil {
		t.Fatal("Wire wrote a request with an empty clientKeyringSig")
	}
}

// TestNullServerRoot checks an unsafe reply with no server root, in either form: it reads, keeps its null
// root through writing and signing, and is UNSAFE. The same reply saying "attested" fails the check, as
// does one whose request had no client root.
func TestNullServerRoot(t *testing.T) {
	h := attestedHandshake(t)
	policyForm := h.reply
	policyForm.ServerKeyringSig, policyForm.ServerKeyringNotAfter, policyForm.ServerReplyCert = nil, nil, nil
	for _, form := range []struct {
		name  string
		reply session.Reply
		key   ed25519.PrivateKey
	}{
		{"entry-key form", h.reply, h.signer},
		{"policy-key form", policyForm, h.server},
	} {
		t.Run(form.name, func(t *testing.T) {
			reply := form.reply
			reply.ServerRoot = nil
			reply.Status = session.StatusUnsafe
			wire := h.sign(t, h.req, reply, form.key)
			if !bytes.Contains(wire, []byte(`"serverRoot":null`)) {
				t.Fatalf("Wire wrote %s, without a null serverRoot", wire)
			}
			read, err := session.ParseReply(wire)
			if err != nil {
				t.Fatalf("ParseReply: %v", err)
			}
			if read.ServerRoot != nil {
				t.Fatalf("ParseReply read the root %+v from null", *read.ServerRoot)
			}
			roundTrip(t, read, wire)
			if got := session.CheckReply(wire, h.req, h.pin, h.entry, h.now); got != session.Unsafe {
				t.Fatalf("CheckReply = %s, want %s", got, session.Unsafe)
			}

			reply.Status = session.StatusAttested
			wire = h.sign(t, h.req, reply, form.key)
			if got := session.CheckReply(wire, h.req, h.pin, h.entry, h.now); got != session.BadSignature {
				t.Fatalf("an attested reply with no server root: CheckReply = %s, want %s", got,
					session.BadSignature)
			}
		})
	}

	noRoot := h.req
	noRoot.ClientRoot = nil
	for status, want := range map[string]session.Check{session.StatusAttested: session.BadSignature, session.StatusUnsafe: session.Unsafe} {
		reply := h.reply
		reply.Status = status
		wire := h.sign(t, noRoot, reply, h.signer)
		if got := session.CheckReply(wire, noRoot, h.pin, h.entry, h.now); got != want {
			t.Fatalf("a request with no client root, a reply %s: CheckReply = %s, want %s", status, got, want)
		}
	}
}

// TestSessionIDMismatch checks that a reply signed over another session id, or one that names a nonce
// that is not 16 bytes, so that there is no session id, fails as BAD_SIGNATURE.
func TestSessionIDMismatch(t *testing.T) {
	h := attestedHandshake(t)
	reply := h.reply
	reply.Sess = b64.Encode(make([]byte, 32))
	signed, err := session.SignReply(reply, h.signer)
	if err != nil {
		t.Fatalf("SignReply: %v", err)
	}
	wire, err := signed.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if got := session.CheckReply(wire, h.req, h.pin, h.entry, h.now); got != session.BadSignature {
		t.Fatalf("another session id: CheckReply = %s, want %s", got, session.BadSignature)
	}

	// With no session id, not even an empty sess matches.
	for _, sess := range []string{h.reply.Sess, ""} {
		reply = h.reply
		reply.Nonce = b64.Encode(make([]byte, 15))
		reply.Sess = sess
		if signed, err = session.SignReply(reply, h.signer); err != nil {
			t.Fatalf("SignReply: %v", err)
		}
		if wire, err = signed.Wire(); err != nil {
			t.Fatalf("Wire: %v", err)
		}
		if got := session.CheckReply(wire, h.req, h.pin, h.entry, h.now); got != session.BadSignature {
			t.Fatalf("a 15-byte nonce, sess %q: CheckReply = %s, want %s", sess, got, session.BadSignature)
		}
	}
}

// TestCheckOrder checks that each step of the client's check outranks the next: a reply that fails two of
// them gives the earlier one's code.
func TestCheckOrder(t *testing.T) {
	h := attestedHandshake(t)
	other := pub(t, vectors.Load(t, "v3.json"), "client-policy")

	// Malformed, and naming another policy key.
	wire := replace(t, replace(t, h.wire, "serverPolicyKey", json.S(other)), "status", json.S("pending"))
	if got := session.CheckReply(wire, h.req, h.pin, h.entry, h.now); got != session.MalformedReply {
		t.Fatalf("malformed and another key: CheckReply = %s, want %s", got, session.MalformedReply)
	}
	// Naming another policy key, and so signed by no key the pin allows.
	if got := session.CheckReply(h.wire, h.req, other, h.entry, h.now); got != session.PinMismatch {
		t.Fatalf("another pin: CheckReply = %s, want %s", got, session.PinMismatch)
	}
	// A bad signature, on an unsafe reply.
	wire = replace(t, h.wire, "status", json.S(session.StatusUnsafe))
	if got := session.CheckReply(wire, h.req, h.pin, h.entry, h.now); got != session.BadSignature {
		t.Fatalf("an unsafe reply signed as attested: CheckReply = %s, want %s", got, session.BadSignature)
	}
}

// TestAttestedOffline checks what the offline reading adds to the live check: the client's own root and
// keyring verify under its policy key and are current at the time judged. Each request here gives the same
// session id, or a reply signed again for its own, so the live check still attests it.
func TestAttestedOffline(t *testing.T) {
	h := attestedHandshake(t)
	at := h.now
	if !session.AttestedOffline(h.wire, h.req, h.pin, h.entry, at) {
		t.Fatal("AttestedOffline = false for the attested handshake")
	}

	badRingSig := h.req
	badRingSig.ClientKeyringSig = h.req.ClientRoot.Sig
	moved := *h.req.ClientRoot
	moved.NotAfter++
	badRoot := h.req
	badRoot.ClientRoot = &moved
	for name, req := range map[string]session.Request{"keyring signature": badRingSig, "root signature": badRoot} {
		if got := session.CheckReply(h.wire, req, h.pin, h.entry, at); got != session.Attested {
			t.Fatalf("%s: CheckReply = %s, want %s", name, got, session.Attested)
		}
		if session.AttestedOffline(h.wire, req, h.pin, h.entry, at) {
			t.Fatalf("%s: AttestedOffline = true for a client %s that does not verify", name, name)
		}
	}

	rootBytes, err := h.req.ClientRoot.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}
	root, err := policy.SignRoot(rootBytes, h.req.ClientRoot.RootID, at-1, h.client)
	if err != nil {
		t.Fatalf("SignRoot: %v", err)
	}
	expiredRoot := h.req
	expiredRoot.ClientRoot = &root
	ring, err := policy.SignKeyring(h.req.ClientKeyring, h.req.ClientPolicyKey, at-1, h.client)
	if err != nil {
		t.Fatalf("SignKeyring: %v", err)
	}
	expiredRing := session.NewRequest(h.req.ClientRoot, h.req.ClientPolicyKey, ring, h.req.Nonce)
	for name, req := range map[string]session.Request{"root": expiredRoot, "keyring": expiredRing} {
		wire := h.sign(t, req, h.reply, h.signer)
		if !session.AttestedOffline(wire, req, h.pin, h.entry, at-1) {
			t.Fatalf("a client %s at its notAfter: AttestedOffline = false", name)
		}
		if session.AttestedOffline(wire, req, h.pin, h.entry, at) {
			t.Fatalf("a client %s 1 ms after its notAfter: AttestedOffline = true", name)
		}
	}

	unsafe := h.reply
	unsafe.Status = session.StatusUnsafe
	if session.AttestedOffline(h.sign(t, h.req, unsafe, h.signer), h.req, h.pin, h.entry, at) {
		t.Fatal("AttestedOffline = true for an unsafe reply")
	}
}

// TestParseRequestRefuses checks each member's rule in reading a request, beyond the cases v3.json pins:
// each request here is the attested handshake's with one member changed.
func TestParseRequestRefuses(t *testing.T) {
	h := attestedHandshake(t)
	wire, err := h.req.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	for _, c := range []struct {
		name   string
		member string
		value  json.Value
	}{
		{"a client root that is a string", "clientRoot", json.S("root")},
		{"a client root with another member", "clientRoot", json.Obj(json.Member{Name: "rootId", Value: json.S("r")})},
		{"a policy key that is not a string", "clientPolicyKey", json.I(1)},
		{"a keyring that is not an object", "clientKeyring", json.S("pi")},
		{"a keyring with a key that is not a string", "clientKeyring", json.Obj(json.Member{Name: "pi", Value: json.I(1)})},
		{"a keyring window that is a string", "clientKeyringNotAfter", json.S("4102444800000")},
		{"a keyring window that is null", "clientKeyringNotAfter", json.Null()},
		{"a nonce that is not a string", "nonce", json.I(1)},
		{"a member the request does not have", "serverEntry", json.S("mcp-entry")},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := replace(t, wire, c.member, c.value)
			if _, err := session.ParseRequest(b); err == nil {
				t.Fatal("ParseRequest read it")
			}
			if _, err := session.ReadRequest(b64.Encode(b)); err == nil {
				t.Fatal("ReadRequest read it")
			}
		})
	}
	if _, err := session.ParseRequest(append(wire, '\n')); err == nil {
		t.Fatal("ParseRequest read a request followed by a newline")
	}
	if _, err := session.ReadRequest("!"); err == nil {
		t.Fatal("ReadRequest read a token that is not base64url")
	}
}

// TestParseReplyRefuses checks each member's rule in reading a reply, beyond the cases v3.json pins: each
// reply here is the attested handshake's with one member changed, and the client's check of it is
// MALFORMED_REPLY.
func TestParseReplyRefuses(t *testing.T) {
	h := attestedHandshake(t)
	for _, c := range []struct {
		name   string
		member string
		value  *json.Value // nil: the member removed
	}{
		{"a server root that is a string", "serverRoot", ptr(json.S("root"))},
		{"a policy key that is not a string", "serverPolicyKey", ptr(json.I(1))},
		{"a keyring that is not an object", "serverKeyring", ptr(json.S("mcp-entry"))},
		{"a keyring with a key that is not a string", "serverKeyring", ptr(json.Obj(json.Member{Name: "mcp-entry", Value: json.I(1)}))},
		{"a keyring signature that is not a string", "serverKeyringSig", ptr(json.I(1))},
		{"a keyring window that is a string", "serverKeyringNotAfter", ptr(json.S("4102444800000"))},
		{"a certificate that is a string", "serverReplyCert", ptr(json.S("cert"))},
		{"a certificate with no member", "serverReplyCert", ptr(json.Obj())},
		{"a nonce that is not a string", "nonce", ptr(json.I(1))},
		{"a session id that is not a string", "sess", ptr(json.I(1))},
		{"a status that is not a string", "status", ptr(json.I(1))},
		{"a status other than attested or unsafe", "status", ptr(json.S("pending"))},
		{"a disabled list that is not an array", "disabled", ptr(json.S("tool"))},
		{"a disabled list with a tool that is not a string", "disabled", ptr(json.Arr(json.S("tool"), json.I(1)))},
		{"a sig that is not a string", "sig", ptr(json.I(1))},
		{"no sig", "sig", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := edit(t, h.wire, c.member, c.value)
			if _, err := session.ParseReply(b); err == nil {
				t.Fatal("ParseReply read it")
			}
			if got := session.CheckReply(b, h.req, h.pin, h.entry, h.now); got != session.MalformedReply {
				t.Fatalf("CheckReply = %s, want %s", got, session.MalformedReply)
			}
		})
	}
	if got := session.CheckReply(append(h.wire, '\n'), h.req, h.pin, h.entry, h.now); got != session.MalformedReply {
		t.Fatalf("a reply followed by a newline: CheckReply = %s, want %s", got, session.MalformedReply)
	}
	if got := session.CheckReply(nil, h.req, h.pin, h.entry, h.now); got != session.MalformedReply {
		t.Fatalf("no reply: CheckReply = %s, want %s", got, session.MalformedReply)
	}
}

func ptr(v json.Value) *json.Value { return &v }

// TestWritersRefuse checks that a request or reply built in code is written only when its reader would read
// what is written.
func TestWritersRefuse(t *testing.T) {
	h := attestedHandshake(t)
	requests := map[string]func(*session.Request){
		"a keyring name that is not a route node": func(r *session.Request) {
			r.ClientKeyring = map[string]string{"a/b": "key"}
		},
		"a keyring window outside [0, 2^53 - 1]": func(r *session.Request) { r.ClientKeyringNotAfter = -1 },
		"a nonce that is not valid UTF-8":        func(r *session.Request) { r.Nonce = "\xff" },
	}
	for name, change := range requests {
		req := h.req
		change(&req)
		if _, err := req.Wire(); err == nil {
			t.Errorf("Request.Wire wrote %s", name)
		}
	}
	window := int64(4102444800000)
	replies := map[string]func(*session.Reply){
		"a status other than attested or unsafe": func(r *session.Reply) { r.Status = "pending" },
		"a keyring name that is not a route node": func(r *session.Reply) {
			r.ServerKeyring = map[string]string{"..": "key"}
		},
		"a keyring signature without its window": func(r *session.Reply) { r.ServerKeyringNotAfter = nil },
		"a server root outside its window": func(r *session.Reply) {
			root := *r.ServerRoot
			root.NotAfter = -1
			r.ServerRoot = &root
		},
		"a certificate outside its window": func(r *session.Reply) {
			cert := *r.ServerReplyCert
			cert.NotAfter = -1
			r.ServerReplyCert = &cert
		},
		"a keyring window outside [0, 2^53 - 1]": func(r *session.Reply) {
			n := window + json.MaxSafe
			r.ServerKeyringNotAfter = &n
		},
	}
	for name, change := range replies {
		reply := h.reply
		change(&reply)
		if _, err := reply.Wire(); err == nil {
			t.Errorf("Reply.Wire wrote %s", name)
		}
		if _, err := reply.SigningBytes(); err == nil {
			t.Errorf("SigningBytes signed %s", name)
		}
		if _, err := session.SignReply(reply, h.signer); err == nil {
			t.Errorf("SignReply signed %s", name)
		}
	}
	if _, err := session.SignReply(h.reply, nil); err == nil {
		t.Error("SignReply signed with no key")
	}
}

// TestSignReplyReplacesSig checks that signing covers no earlier sig: a reply signed twice has one
// signature, the same both times.
func TestSignReplyReplacesSig(t *testing.T) {
	h := attestedHandshake(t)
	reply := h.reply
	reply.Sig = "earlier"
	again, err := session.SignReply(reply, h.signer)
	if err != nil || again.Sig != h.reply.Sig {
		t.Fatalf("SignReply signed %s, %v; want %s", again.Sig, err, h.reply.Sig)
	}
}

// TestNewRequest checks that a request built from the client's material writes the request it was read
// from, and keeps a copy of the root and keyring it was given.
func TestNewRequest(t *testing.T) {
	h := attestedHandshake(t)
	root := *h.req.ClientRoot
	kf := h.req.KeyringFile()
	if !kf.Verifies(h.req.ClientPolicyKey) {
		t.Fatal("the request's KeyringFile does not verify under its policy key")
	}
	want, err := h.req.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	req := session.NewRequest(&root, h.req.ClientPolicyKey, kf, h.req.Nonce)
	root.NotAfter = 0
	kf.Services["pi"] = "changed"
	got, err := req.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("NewRequest wrote %s, want %s", got, want)
	}

	unsafe := session.NewRequest(nil, h.req.ClientPolicyKey, h.req.KeyringFile(), h.req.Nonce)
	b, err := unsafe.Wire()
	if err != nil || !bytes.Contains(b, []byte(`"clientRoot":null`)) {
		t.Fatalf("a request with no root wrote %s, %v", b, err)
	}
	read, err := session.ParseRequest(b)
	if err != nil || read.ClientRoot != nil {
		t.Fatalf("ParseRequest read %+v, %v; want no client root", read.ClientRoot, err)
	}
}

// TestOpensSession checks the lengths a request must have to open a session at all.
func TestOpensSession(t *testing.T) {
	h := attestedHandshake(t)
	if !session.OpensSession(h.req) {
		t.Fatal("OpensSession = false for the attested handshake's request")
	}
	noRoot := h.req
	noRoot.ClientRoot = nil
	if !session.OpensSession(noRoot) {
		t.Fatal("OpensSession = false for a request with no client root")
	}
	sig := func(s string) func(*session.Request) {
		return func(r *session.Request) {
			root := *r.ClientRoot
			root.Sig = s
			r.ClientRoot = &root
		}
	}
	for name, change := range map[string]func(*session.Request){
		"a 15-byte nonce":                  func(r *session.Request) { r.Nonce = b64.Encode(make([]byte, 15)) },
		"a 17-byte nonce":                  func(r *session.Request) { r.Nonce = b64.Encode(make([]byte, 17)) },
		"a nonce that is not base64url":    func(r *session.Request) { r.Nonce = r.Nonce + "=" },
		"a 63-byte root signature":         sig(b64.Encode(make([]byte, 63))),
		"a 65-byte root signature":         sig(b64.Encode(make([]byte, 65))),
		"an empty root signature":          sig(""),
		"a root signature not base64url":   sig(strings.Repeat("A", 85) + "="),
		"a policy key that is not UTF-8":   func(r *session.Request) { r.ClientPolicyKey = "\xff" },
		"a keyring key that is not UTF-8":  func(r *session.Request) { r.ClientKeyring = map[string]string{"pi": "\xff"} },
		"a keyring name that is not UTF-8": func(r *session.Request) { r.ClientKeyring = map[string]string{"\xff": "k"} },
	} {
		req := h.req
		change(&req)
		if session.OpensSession(req) {
			t.Errorf("OpensSession = true for %s", name)
		}
	}
}

// TestNewNonce checks that a nonce is 16 bytes, as base64url, and fresh.
func TestNewNonce(t *testing.T) {
	a, b := session.NewNonce(), session.NewNonce()
	if n := decode(t, a); len(n) != 16 {
		t.Fatalf("NewNonce gave %d bytes", len(n))
	}
	if a == b {
		t.Fatal("NewNonce gave the same nonce twice")
	}
}

// TestDeriveIDLengths checks that every part of a session id must be exactly its length, a root signature
// that is present and empty included, or there is none.
func TestDeriveIDLengths(t *testing.T) {
	sig, nonce := make([]byte, 64), make([]byte, 16)
	keyring := map[string]string{"pi": "k"}
	if _, ok := session.DeriveID(sig, sig, nonce, nonce, "p", keyring); !ok {
		t.Fatal("DeriveID refused parts of the right lengths")
	}
	if _, ok := session.DeriveID(nil, nil, nonce, nonce, "p", nil); !ok {
		t.Fatal("DeriveID refused absent roots and an empty keyring")
	}
	for _, n := range []int{0, 15, 17} {
		short := make([]byte, n)
		for name, parts := range map[string][4][]byte{
			"client nonce": {sig, sig, short, nonce},
			"server nonce": {sig, sig, nonce, short},
		} {
			if _, ok := session.DeriveID(parts[0], parts[1], parts[2], parts[3], "p", keyring); ok {
				t.Errorf("DeriveID took a %d-byte %s", n, name)
			}
		}
	}
	for _, n := range []int{0, 63, 65} {
		wrong := make([]byte, n)
		if _, ok := session.DeriveID(wrong, sig, nonce, nonce, "p", keyring); ok {
			t.Errorf("DeriveID took a %d-byte client root signature", n)
		}
		if _, ok := session.DeriveID(sig, wrong, nonce, nonce, "p", keyring); ok {
			t.Errorf("DeriveID took a %d-byte server root signature", n)
		}
	}
	if _, ok := session.DeriveID(sig, sig, nonce, nonce, "\xff", keyring); ok {
		t.Error("DeriveID took a policy key that is not UTF-8")
	}
	both, _ := session.DeriveID(sig, sig, nonce, nonce, "p", keyring)
	clientOnly, _ := session.DeriveID(sig, nil, nonce, nonce, "p", keyring)
	serverOnly, _ := session.DeriveID(nil, sig, nonce, nonce, "p", keyring)
	if both == clientOnly || both == serverOnly || clientOnly == serverOnly {
		t.Fatal("DeriveID gave one id for different roots present")
	}
}

// TestStatus checks the server's status beyond the cases v3.json pins: no client root, no root of the
// server's own, an own root that does not verify under the server's own policy key, and no pinned client
// key.
func TestStatus(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	var c vectors.Node
	v3.Get("sessionStatus").Each(func(name string, n vectors.Node) {
		if name == "attested" {
			c = n.With(t)
		}
	})
	req, err := session.ReadRequest(c.Get("requestToken").Str())
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	root, err := policy.ParseRootFile([]byte(c.Get("serverRootFile").Str()))
	if err != nil {
		t.Fatalf("ParseRootFile: %v", err)
	}
	kf, err := policy.ParseKeyringFile([]byte(c.Get("serverKeyringFile").Str()))
	if err != nil {
		t.Fatalf("ParseKeyringFile: %v", err)
	}
	own, client := pub(t, v3, "server-policy"), pub(t, v3, "client-policy")
	now := c.Get("now").Int()
	if got := session.Status(req, &root, kf, own, []string{client}, now); got != session.StatusAttested {
		t.Fatalf("Status = %q for the attested case", got)
	}
	noRoot := req
	noRoot.ClientRoot = nil
	for name, got := range map[string]string{
		"no client root":                    session.Status(noRoot, &root, kf, own, []string{client}, now),
		"no root of its own":                session.Status(req, nil, kf, own, []string{client}, now),
		"its own root under another key":    session.Status(req, &root, kf, client, []string{client}, now),
		"its own policy key that is no key": session.Status(req, &root, kf, "key", []string{client}, now),
		"no pinned client key":              session.Status(req, &root, kf, own, nil, now),
	} {
		if got != session.StatusUnsafe {
			t.Errorf("%s: Status = %q, want unsafe", name, got)
		}
	}
}

// TestKeyringFile checks that a request's keyring is the one its fields present, so that its signature is
// checked over the request's own window.
func TestKeyringFile(t *testing.T) {
	h := attestedHandshake(t)
	kf := h.req.KeyringFile()
	if kf.Policy != h.req.ClientPolicyKey || kf.Sig != h.req.ClientKeyringSig ||
		kf.NotAfter != h.req.ClientKeyringNotAfter || len(kf.Services) != len(h.req.ClientKeyring) {
		t.Fatalf("KeyringFile = %+v, for the request %+v", kf, h.req)
	}
	moved := h.req
	moved.ClientKeyringNotAfter++
	if moved.KeyringFile().Verifies(h.req.ClientPolicyKey) {
		t.Fatal("a keyring whose window moved verifies")
	}
	kf.Services["pi"] = "changed"
	if !h.req.KeyringFile().Verifies(h.req.ClientPolicyKey) {
		t.Fatal("changing a KeyringFile's services changed the request's keyring")
	}
}

// TestCertificateForEntry checks that the certificate must be for the entry service the client configured,
// even when it names the key the keyring holds for that service.
func TestCertificateForEntry(t *testing.T) {
	h := attestedHandshake(t)
	key := h.reply.ServerKeyring[h.entry]
	for svc, want := range map[string]session.Check{h.entry: session.Attested, "github-tools": session.BadSignature} {
		cert, err := policy.IssueReplyCert(h.pin, svc, key, h.reply.ServerReplyCert.NotAfter, h.server)
		if err != nil {
			t.Fatalf("IssueReplyCert: %v", err)
		}
		reply := h.reply
		reply.ServerReplyCert = &cert
		wire := h.sign(t, h.req, reply, h.signer)
		if got := session.CheckReply(wire, h.req, h.pin, h.entry, h.now); got != want {
			t.Errorf("a certificate for %s with the entry's key: CheckReply = %s, want %s", svc, got, want)
		}
	}
}
