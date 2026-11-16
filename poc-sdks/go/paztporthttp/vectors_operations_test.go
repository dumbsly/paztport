// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// TestOperationsReceiveVectors replays http-v4.json's operations.receive: the receiver enters the request
// under the name its embedder's routing gives, and its answer is compared with expected. The harness plays
// the embedder: Name is the service, '#' and the case's operation when the chain's last rcv names an
// operation and the case has one, and the service otherwise. A case on rules material holds the keyed
// table as the receiver's own.
func TestOperationsReceiveVectors(t *testing.T) {
	file := vectors.Load(t, "http-v4.json")
	cases := file.Get("operations").Get("receive")
	if cases.Len() != 11 {
		t.Fatalf("http-v4.json has %d operations.receive cases, want 11", cases.Len())
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			req := caseRequest(t, c.Get("request"))
			service := c.Get("service").Str()
			r := &paztporthttp.Receiver{Name: embedderName(t, c, req, service)}
			if c.Has("material") {
				table, err := policy.ReadOperationTable([]byte(file.Get("operations").Get("keyed").Get("file").Str()))
				if err != nil {
					t.Fatalf("ReadOperationTable: %v", err)
				}
				r.Operations = &table
			}
			r.Verifier = operationsVerifier(t, c)
			got := answerOf(r.Accept(t.Context(), req, nil, caseMode(t, c.Get("mode")))).refusal
			want := "null"
			if r := c.Get("expected").Get("refusal"); !r.IsNull() {
				body, err := hex.DecodeString(r.Get("body").Str())
				if err != nil {
					t.Fatalf("the refusal's body: %v", err)
				}
				want = fmt.Sprintf("%d %s", r.Get("status").Int(), body)
			}
			if got != want {
				t.Fatalf("refusal %s, want %s", got, want)
			}
		})
	})
}

// embedderName returns the name the embedder gives the receiver for the case's request.
func embedderName(t *testing.T, c vectors.Node, req paztporthttp.InboundRequest, service string) string {
	t.Helper()
	tok, ok := wire.HeaderValue(req.Chain)
	if !ok {
		return service
	}
	chain, code := stamp.ReadChain(tok)
	if code != "OK" || len(chain) == 0 {
		return service
	}
	if op := c.Get("operation"); !op.IsNull() && policy.Service(chain[len(chain)-1].Rcv) != chain[len(chain)-1].Rcv {
		return service + "#" + op.Str()
	}
	return service
}

// operationsVerifier returns the verifier of an operations.receive case: pinned to the root of the rules
// material or the v4.json policy it names, with the keyring, windows and extension settings the case gives and
// a nonce cache holding its spent keys.
func operationsVerifier(t *testing.T, c vectors.Node) *verify.Verifier {
	t.Helper()
	rootText, rootID := "", ""
	if c.Has("material") {
		m := vectors.Rules(t).Get("material").Get(c.Get("material").Str()).Get("root")
		rootText, rootID = m.Get("root").Str(), m.Get("rootId").Str()
	} else {
		p := vectors.Load(t, "v4.json").Get("policies").Get(c.Get("policy").Str())
		rootText, rootID = p.Get("root").Str(), p.Get("rootId").Str()
	}
	root, err := b64.Decode(rootText)
	if err != nil {
		t.Fatalf("the root: %v", err)
	}
	ring := policy.Keyring{}
	r := c.Get("keyring")
	for _, svc := range r.Names() {
		_, ring[svc] = vectors.RulesKey(t, r.Get(svc).Str())
	}
	now, notAfter := c.Get("now").Int(), c.Get("policyNotAfter").Int()
	nonces := verify.NewMemoryNonceCache(c.Get("nonceTtlMs").Int())
	if c.Has("spent") {
		for _, k := range c.Get("spent").Strs() {
			if _, err := nonces.SeenBefore(t.Context(), k, now); err != nil {
				t.Fatalf("SeenBefore: %v", err)
			}
		}
	}
	return verify.New(verify.Config{
		Keyrings:       []verify.PinnedKeyring{{Keys: ring, NotAfter: notAfter}},
		Roots:          []verify.PinnedRoot{{Root: root, RootID: rootID, NotAfter: notAfter}},
		PolicyNotAfter: notAfter,
		AllowedOrigins: c.Get("allowedOrigins").Strs(),
		Sess:           c.Get("sess").Str(),
		Nonces:         nonces,
		Now:            func() int64 { return now },
		CallMaxAgeMs:   c.Get("callMaxAgeMs").Int(),
		RunMaxAgeMs:    c.Get("runMaxAgeMs").Int(),
		Extensions:     caseSettings(t, c),
	})
}
