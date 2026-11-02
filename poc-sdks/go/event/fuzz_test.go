// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package event_test

import (
	"bytes"
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/event"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
)

// FuzzAccept offers any body to a fresh responder holding events.json's keyring and allowed signers, at
// the time of its accepted cases, seeded with every body the file gives. It never panics, and its answer
// is one of the eight refusals with no event, or an event with an id that writes back to the bytes it was
// read from.
func FuzzAccept(f *testing.F) {
	file := vectors.Load(f, "events.json")
	file.Get("verify").Each(func(_ string, c vectors.Node) {
		f.Add([]byte(c.Get("body").Str()))
		c.Get("earlier").Each(func(_ string, e vectors.Node) {
			f.Add([]byte(e.Get("body").Str()))
		})
	})
	keyring, allowed := responderConfig(f, file.Get("responder"))
	f.Fuzz(func(t *testing.T, body []byte) {
		r := event.NewResponder(keyring, allowed, func() int64 { return t0 })
		got, refusal := r.Accept(body)
		if refusal != "" {
			if !slices.Contains(refusals, refusal) || got != (event.Event{}) {
				t.Fatalf("Accept = %+v, %q", got, refusal)
			}
			return
		}
		wire, err := got.Wire()
		if err != nil || got.EventID == "" || !bytes.Equal(wire, payloadOf(t, body)) {
			t.Fatalf("Accept = %+v, which writes %s, %v", got, wire, err)
		}
	})
}
