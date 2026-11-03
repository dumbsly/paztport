// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package event_test

import (
	"bytes"
	"math"
	"slices"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/event"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/exact"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
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
		r := event.NewResponder([]policy.Keyring{keyring}, allowed, func() int64 { return t0 })
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

// FuzzAcceptSigned signs any payload with payment's key, so that every input reaches the event reader, and
// offers it to a fresh responder at any two times. It is seeded with the payload of every body events.json
// gives, at pairs of times at the window's and the memory's limits and at both ends of int64. It never
// panics. An answer is accepted only when the payload is an event with an id that writes back to the
// payload and is within the window; the second offer of an accepted id is refused while the id is
// remembered; and a body refused before the window is refused the same way at any time.
func FuzzAcceptSigned(f *testing.F) {
	file := vectors.Load(f, "events.json")
	times := [][2]int64{
		{t0, t0}, {t0, t0 + 60000}, {t0, t0 + 60001}, {t0 - 30000, t0 + 30001},
		{0, 0}, {math.MinInt64, t0}, {t0, math.MaxInt64},
	}
	file.Get("verify").Each(func(_ string, c vectors.Node) {
		if payload, ok := payloadIn([]byte(c.Get("body").Str())); ok {
			for _, at := range times {
				f.Add(payload, at[0], at[1])
			}
		}
	})
	priv, pub := vectors.V3Key(f, "payment")
	keyring := policy.Keyring{"payment": pub}
	f.Fuzz(func(t *testing.T, payload []byte, now1, now2 int64) {
		text := b64.Encode(payload)
		sig, err := keys.Sign(priv, event.EnvelopeSigningBytes(text))
		if err != nil {
			t.Fatal(err)
		}
		b, err := event.Envelope{Signer: "payment", Payload: text, Sig: b64.Encode(sig)}.Wire()
		if err != nil {
			t.Fatal(err)
		}
		now := now1
		r := event.NewResponder([]policy.Keyring{keyring}, []string{"payment"}, func() int64 { return now })
		first, refusal1 := r.Accept(b)
		check(t, first, refusal1, payload, now1)
		now = now2
		second, refusal2 := r.Accept(b)
		check(t, second, refusal2, payload, now2)

		switch {
		case refusal1 == "" && exact.AtMost(now2, now1, 60000) && refusal2 != event.RepeatedEventID &&
			refusal2 != event.OutsideWindow:
			t.Fatalf("an id accepted at %d is offered again at %d: %q", now1, now2, refusal2)
		case refusal1 != "" && refusal1 != event.OutsideWindow && refusal2 != refusal1:
			t.Fatalf("a body refused %q at %d is refused %q at %d", refusal1, now1, refusal2, now2)
		}
	})
}

// check fails t unless Accept's answer at now is a refusal with no event, or an event with an id, within
// the window of now, that writes back to payload.
func check(t *testing.T, got event.Event, refusal event.Refusal, payload []byte, now int64) {
	t.Helper()
	if refusal != "" {
		if !slices.Contains(refusals, refusal) || got != (event.Event{}) {
			t.Fatalf("Accept = %+v, %q", got, refusal)
		}
		return
	}
	wire, err := got.Wire()
	if err != nil || got.EventID == "" || !bytes.Equal(wire, payload) {
		t.Fatalf("Accept = %+v, which writes %s, %v", got, wire, err)
	}
	if !exact.AtMost(now, got.TS, event.WindowMs) || !exact.AtMost(got.TS, now, event.WindowMs) {
		t.Fatalf("Accept at %d of an event with ts %d", now, got.TS)
	}
}

// payloadIn returns the bytes of the payload of envelope body, if body has one that decodes.
func payloadIn(body []byte) ([]byte, bool) {
	v, err := json.ReadWire(body)
	if err != nil {
		return nil, false
	}
	payload, err := json.String(v, "payload")
	if err != nil {
		return nil, false
	}
	b, err := b64.Decode(payload)
	return b, err == nil
}
