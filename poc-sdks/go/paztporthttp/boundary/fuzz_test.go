// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package boundary_test

import (
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/boundary"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
)

// FuzzAnswer feeds any status and bytes as the partner's answer to every step of an exchange: the full
// handshake, then the replacement or the call. The egress never panics and never errs on the partner's
// bytes, every exchange ends within three answers, and a call goes out only in a session whose id has the
// spec's form. It is seeded with a genuine reply.
func FuzzAnswer(f *testing.F) {
	seed := newFixture(f, []string{"attested"}, "unsafe")
	_, step := seed.begin(f)
	status, reply := seed.partner.serve(f, step)
	f.Add(status, reply)
	f.Add(404, []byte(nil))
	f.Add(403, sessionUnknown)
	f.Add(200, []byte(`{}`))
	f.Add(-1, []byte{0xFF})
	g := newFixture(f, nil, "unsafe")
	f.Fuzz(func(t *testing.T, status int, body []byte) {
		// A new egress each time, so that every input meets the full handshake first.
		e, err := boundary.New(g.cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		x, _, err := e.Begin(g.a, g.a.Influence, "/charge", charge)
		if err != nil {
			t.Fatalf("Begin: %v", err)
		}
		for answers := 1; ; answers++ {
			next, more, err := x.Answer(status, body)
			if err != nil {
				t.Fatalf("Answer: %v", err)
			}
			if !more {
				break
			}
			if answers == 3 {
				t.Fatal("the exchange did not end within three answers")
			}
			if next.Path != wire.SessionPath {
				if id, err := b64.Decode(header(next, wire.Session)); err != nil || len(id) != 32 {
					t.Fatalf("a call went out in the session %q", header(next, wire.Session))
				}
			}
		}
		if _, done := x.Result(); !done {
			t.Fatal("the exchange has no outcome")
		}
	})
}
