// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"bytes"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
)

// TestRequestVectors replays v3.json's sessionRequest cases: each token is read as the server reads it,
// and is OK or MALFORMED. A request that reads writes back to exactly its bytes, and ParseRequest reads
// those bytes as ReadRequest reads the token.
func TestRequestVectors(t *testing.T) {
	cases := vectors.Load(t, "v3.json").Get("sessionRequest")
	seen := map[string]int{}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			tok := c.Get("requestToken").Str()
			wire := decode(t, tok)
			req, err := session.ReadRequest(tok)
			_, parseErr := session.ParseRequest(wire)
			expected := c.Get("expected").Str()
			seen[expected]++
			switch expected {
			case "OK":
				if err != nil || parseErr != nil {
					t.Fatalf("ReadRequest: %v; ParseRequest: %v", err, parseErr)
				}
				got, err := req.Wire()
				if err != nil || !bytes.Equal(got, wire) {
					t.Fatalf("Wire = %s, %v; want the bytes read, %s", got, err, wire)
				}
			case "MALFORMED":
				if err == nil || parseErr == nil {
					t.Fatalf("ReadRequest: %v; ParseRequest: %v; want both refused", err, parseErr)
				}
			default:
				t.Fatalf("the case expects %q", expected)
			}
		})
	})
	if seen["OK"] == 0 || seen["MALFORMED"] == 0 {
		t.Fatalf("the cases expect %v; want OK and MALFORMED among them", seen)
	}
}

// TestReplyVectors replays v3.json's sessionReply cases: the client's check of each reply against the
// request it sent, its pin and its entry service at now, and the offline reading of the same handshake at
// the same time, attested exactly when the live check is. A reply that reads writes back to exactly its
// bytes, its signing bytes are those bytes less sig, and one the check accepts is signed again by the key
// that signed it, which reproduces its sig since Ed25519 is deterministic.
func TestReplyVectors(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	signers := signersByPub(t, v3)
	seen := map[session.Check]int{}
	v3.Get("sessionReply").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			req, err := session.ReadRequest(c.Get("requestToken").Str())
			if err != nil {
				t.Fatalf("ReadRequest: %v", err)
			}
			wire := decode(t, c.Get("replyToken").Str())
			pin := pub(t, v3, c.Get("pin").Str())
			entry, now := c.Get("serverEntry").Str(), c.Get("now").Int()
			want := session.Check(c.Get("expected").Str())
			seen[want]++

			if got := session.CheckReply(wire, req, pin, entry, now); got != want {
				t.Fatalf("CheckReply = %s, want %s", got, want)
			}
			if got := session.AttestedOffline(wire, req, pin, entry, now); got != (want == session.Attested) {
				t.Fatalf("AttestedOffline = %v, want %v", got, want == session.Attested)
			}

			reply, err := session.ParseReply(wire)
			if (err != nil) != (want == session.MalformedReply) {
				t.Fatalf("ParseReply: %v, for a case that expects %s", err, want)
			}
			if err != nil {
				return
			}
			roundTrip(t, reply, wire)
			if want == session.Attested || want == session.Unsafe {
				key := reply.ServerPolicyKey
				if reply.ServerReplyCert != nil {
					key = reply.ServerReplyCert.Key
				}
				again, err := session.SignReply(reply, signers[key])
				if err != nil || again.Sig != reply.Sig {
					t.Fatalf("SignReply signed %s, %v; want %s", again.Sig, err, reply.Sig)
				}
			}
		})
	})
	for _, check := range []session.Check{session.Attested, session.Unsafe, session.MalformedReply,
		session.PinMismatch, session.BadSignature} {
		if seen[check] == 0 {
			t.Errorf("no case expects %s", check)
		}
	}
}

// roundTrip checks that reply, read from wire, writes back to exactly wire, and that its signing bytes are
// the session reply prefix and wire's value less sig, written again: every member as received.
func roundTrip(t *testing.T, reply session.Reply, wire []byte) {
	t.Helper()
	got, err := reply.Wire()
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatalf("Wire = %s, %v; want the bytes read, %s", got, err, wire)
	}
	v, err := json.ReadWire(wire)
	if err != nil {
		t.Fatalf("ReadWire: %v", err)
	}
	var unsigned []json.Member
	for _, m := range v.Members() {
		if m.Name != "sig" {
			unsigned = append(unsigned, m)
		}
	}
	body, err := json.Wire(json.Obj(unsigned...))
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	msg, err := session.ReplySigningBytes(reply)
	if want := append([]byte("paztport-session-reply\n"), body...); err != nil || !bytes.Equal(msg, want) {
		t.Fatalf("ReplySigningBytes = %q, %v; want %q", msg, err, want)
	}
}

// TestStatusVectors replays v3.json's sessionStatus cases: the server's status for each request at now,
// against its own root and keyring, read from their files, its policy key and the client keys it pinned.
func TestStatusVectors(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	seen := map[string]int{}
	v3.Get("sessionStatus").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
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
			own := pub(t, v3, c.Get("serverPolicyKey").Str())
			if !kf.Verifies(own) {
				t.Fatal("the server's keyring does not verify under its policy key")
			}
			var pinned []string
			c.Get("pinned").Each(func(_ string, name vectors.Node) { pinned = append(pinned, pub(t, v3, name.Str())) })
			want := c.Get("expected").Str()
			seen[want]++
			if got := session.Status(req, &root, kf, own, pinned, c.Get("now").Int()); got != want {
				t.Fatalf("Status = %q, want %q", got, want)
			}
		})
	})
	if seen["attested"] == 0 || seen["unsafe"] == 0 {
		t.Fatalf("the cases expect %v; want attested and unsafe among them", seen)
	}
}

// TestDeriveIDVectors replays v3.json's fixedInputs, each length consecutive bytes from start, and the
// deriveSessionId cases built from them, a null root signature being an absent root.
func TestDeriveIDVectors(t *testing.T) {
	v3 := vectors.Load(t, "v3.json")
	inputs := map[string][]byte{}
	v3.Get("fixedInputs").Each(func(name string, in vectors.Node) {
		b := make([]byte, in.Get("length").Int())
		for i := range b {
			b[i] = byte(in.Get("start").Int() + int64(i))
		}
		if got := b64.Encode(b); got != in.Get("encoded").Str() {
			t.Fatalf("fixedInputs.%s encodes as %s, want %s", name, got, in.Get("encoded").Str())
		}
		inputs[name] = b
	})
	d := v3.Get("deriveSessionId")
	policyKey := d.Get("keys").Get("clientPolicyKey").Str()
	keyring := map[string]string{}
	d.Get("keys").Get("clientKeyring").Each(func(svc string, key vectors.Node) { keyring[svc] = key.Str() })
	d.Get("cases").Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			sig := func(member string) []byte {
				if n := c.Get(member); !n.IsNull() {
					return inputs[n.Str()]
				}
				return nil
			}
			got, ok := session.DeriveID(sig("clientRootSig"), sig("serverRootSig"), inputs["clientNonce"],
				inputs["serverNonce"], policyKey, keyring)
			if !ok || got != c.Get("expected").Str() {
				t.Fatalf("DeriveID = %s, %v; want %s", got, ok, c.Get("expected").Str())
			}
		})
	})
}

// decode returns the bytes of token tok.
func decode(t *testing.T, tok string) []byte {
	t.Helper()
	b, err := b64.Decode(tok)
	if err != nil {
		t.Fatalf("a token that does not decode: %v", err)
	}
	return b
}

// pub returns the public key of v3.json's key called name, as base64url SubjectPublicKeyInfo.
func pub(t *testing.T, v3 vectors.Node, name string) string {
	t.Helper()
	return v3.With(t).Get("keys").Get(name).Get("pub").Str()
}
