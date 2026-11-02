// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
)

// checks are the outcomes of the client's check.
var checks = []session.Check{session.Attested, session.Unsafe, session.MalformedReply, session.PinMismatch,
	session.BadSignature}

// FuzzParseReply reads any bytes as a reply, seeded with v3.json's sessionReply replies. It never panics.
// A reply that reads writes back to exactly the bytes it was read from and has signing bytes, and the
// client's check of any bytes, against the first case's request, pin and entry service, is one of its
// outcomes, MALFORMED_REPLY exactly when the bytes do not read.
func FuzzParseReply(f *testing.F) {
	v3 := vectors.Load(f, "v3.json")
	cases := v3.Get("sessionReply")
	cases.Each(func(_ string, c vectors.Node) {
		b, err := b64.Decode(c.Get("replyToken").Str())
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	})
	first := cases.Index(0)
	req, err := session.ReadRequest(first.Get("requestToken").Str())
	if err != nil {
		f.Fatal(err)
	}
	pin := v3.Get("keys").Get(first.Get("pin").Str()).Get("pub").Str()
	entry, now := first.Get("serverEntry").Str(), first.Get("now").Int()
	f.Fuzz(func(t *testing.T, b []byte) {
		check := session.CheckReply(b, req, pin, entry, now)
		if !slices.Contains(checks, check) {
			t.Fatalf("CheckReply = %q", check)
		}
		session.AttestedOffline(b, req, pin, entry, now)
		reply, err := session.ParseReply(b)
		if (err != nil) != (check == session.MalformedReply) {
			t.Fatalf("ParseReply: %v, and CheckReply = %s", err, check)
		}
		if err != nil {
			return
		}
		if w, err := reply.Wire(); err != nil || !bytes.Equal(w, b) {
			t.Fatalf("Wire = %q, %v; want the bytes read", w, err)
		}
		if _, err := session.ReplySigningBytes(reply); err != nil {
			t.Fatalf("ReplySigningBytes: %v", err)
		}
	})
}

// FuzzParseRequest reads any bytes as a request, seeded with v3.json's sessionRequest requests. It never
// panics, a request that reads writes back to exactly the bytes it was read from, and the server's own
// checks of it never panic either.
func FuzzParseRequest(f *testing.F) {
	v3 := vectors.Load(f, "v3.json")
	v3.Get("sessionRequest").Each(func(_ string, c vectors.Node) {
		b, err := b64.Decode(c.Get("requestToken").Str())
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	})
	f.Fuzz(func(t *testing.T, b []byte) {
		req, err := session.ParseRequest(b)
		if err != nil {
			return
		}
		if w, err := req.Wire(); err != nil || !bytes.Equal(w, b) {
			t.Fatalf("Wire = %q, %v; want the bytes read", w, err)
		}
		session.OpensSession(req)
		// The client's own material, standing in for the server's, so that Status can reach every check.
		var own policy.Root
		if req.ClientRoot != nil {
			own = *req.ClientRoot
		}
		session.Status(req, own, req.KeyringFile(), req.ClientPolicyKey, []string{req.ClientPolicyKey}, 0)
	})
}
