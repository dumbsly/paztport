// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package event_test

import (
	"crypto/ed25519"
	"math"
	"sync"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/event"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

const (
	t0      = 1767225600000
	maxSafe = 1<<53 - 1
)

// sample is an attributable event, sent at t0.
var sample = event.Event{
	Reason:      "PATH_NOT_ALLOWED",
	SuspectSvc:  "search",
	SuspectInst: "search-1",
	RID:         "rid-1",
	TS:          t0,
	EventID:     "event-1",
}

// clock is a responder's clock that a test sets. A test sets it only between calls to Accept, so a
// responder never reads it as it changes.
type clock struct{ now int64 }

func (c *clock) read() int64 { return c.now }

// newResponder returns a responder that takes events from payment alone, and the clock it reads.
func newResponder(t *testing.T) (*event.Responder, *clock) {
	t.Helper()
	_, pub := vectors.V3Key(t, "payment")
	c := &clock{now: t0}
	return event.NewResponder(policy.Keyring{"payment": pub}, []string{"payment"}, c.read), c
}

// body returns ev signed by payment, as the body a responder receives.
func body(t testing.TB, ev event.Event) []byte {
	t.Helper()
	priv, _ := vectors.V3Key(t, "payment")
	wire, err := ev.Wire()
	if err != nil {
		t.Fatalf("Wire: %v", err)
	}
	env, err := event.SignEnvelope("payment", wire, priv)
	if err != nil {
		t.Fatalf("SignEnvelope: %v", err)
	}
	b, err := env.Wire()
	if err != nil {
		t.Fatalf("Envelope.Wire: %v", err)
	}
	return b
}

// sentAt returns sample sent at ts.
func sentAt(ts int64) event.Event {
	ev := sample
	ev.TS = ts
	return ev
}

// TestWindow pins the window at its limits, |now - ts| <= WindowMs either way, and at both ends of int64,
// where now - ts does not fit an int64 and must not wrap into the window. A clock may read any int64; a
// ts is a protocol integer.
func TestWindow(t *testing.T) {
	if event.WindowMs != 30000 {
		t.Fatalf("WindowMs = %d, want 30000", event.WindowMs)
	}
	tests := []struct {
		name    string
		now, ts int64
		want    event.Refusal
	}{
		{"now", t0, t0, ""},
		{"at the window, in the past", t0 + 30000, t0, ""},
		{"at the window, in the future", t0 - 30000, t0, ""},
		{"1 ms past the window, in the past", t0 + 30001, t0, event.OutsideWindow},
		{"1 ms past the window, in the future", t0 - 30001, t0, event.OutsideWindow},
		{"ts 0 at a clock before the epoch", -30000, 0, ""},
		{"ts 0 at a clock 1 ms further back", -30001, 0, event.OutsideWindow},
		{"the largest ts, at the window", maxSafe + 30000, maxSafe, ""},
		{"the largest ts, 1 ms past it", maxSafe + 30001, maxSafe, event.OutsideWindow},
		{"the least clock, ts 0", math.MinInt64, 0, event.OutsideWindow},
		{"the least clock", math.MinInt64, t0, event.OutsideWindow},
		{"the least clock, the largest ts", math.MinInt64, maxSafe, event.OutsideWindow},
		{"the clock after the least, ts 0", math.MinInt64 + 1, 0, event.OutsideWindow},
		{"the largest clock, ts 0", math.MaxInt64, 0, event.OutsideWindow},
		{"the largest clock, the largest ts", math.MaxInt64, maxSafe, event.OutsideWindow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, c := newResponder(t)
			c.now = tt.now
			want := sentAt(tt.ts)
			if tt.want != "" {
				want = event.Event{}
			}
			if got, refusal := r.Accept(body(t, sentAt(tt.ts))); refusal != tt.want || got != want {
				t.Fatalf("Accept at %d of ts %d = %+v, %q; want %q", tt.now, tt.ts, got, refusal, tt.want)
			}
		})
	}
}

// TestRemembered pins how long a responder remembers an accepted id: from the now it was accepted at until
// 60000 ms later, inclusive, whatever the ts of the event that offers it again, and also at an earlier
// now, should the clock step back. A refused event spends no id.
func TestRemembered(t *testing.T) {
	tests := []struct {
		name   string
		offset int64 // from the now the id was accepted at
		want   event.Refusal
	}{
		{"at once", 0, event.RepeatedEventID},
		{"60000 ms later", 60000, event.RepeatedEventID},
		{"60001 ms later", 60001, ""},
		{"with the clock 30000 ms back", -30000, event.RepeatedEventID},
		{"with the clock 60001 ms back", -60001, event.RepeatedEventID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, c := newResponder(t)
			if _, refusal := r.Accept(body(t, sample)); refusal != "" {
				t.Fatalf("the first Accept: %q", refusal)
			}
			c.now = t0 + tt.offset
			again := sentAt(c.now)
			again.Reason = "REPLAY"
			if got, refusal := r.Accept(body(t, again)); refusal != tt.want {
				t.Fatalf("Accept %d ms on = %+v, %q; want %q", tt.offset, got, refusal, tt.want)
			}
		})
	}

	t.Run("a refused event spends no id", func(t *testing.T) {
		r, c := newResponder(t)
		c.now = t0 + 30001
		if _, refusal := r.Accept(body(t, sample)); refusal != event.OutsideWindow {
			t.Fatalf("Accept of a stale event: %q", refusal)
		}
		if _, refusal := r.Accept(body(t, sentAt(c.now))); refusal != "" {
			t.Fatalf("Accept of a fresh event under the same id: %q", refusal)
		}
	})

	t.Run("a repeated id is not renewed", func(t *testing.T) {
		r, c := newResponder(t)
		r.Accept(body(t, sample))
		c.now = t0 + 60000
		if _, refusal := r.Accept(body(t, sentAt(c.now))); refusal != event.RepeatedEventID {
			t.Fatalf("Accept at the end of the memory: %q", refusal)
		}
		c.now = t0 + 60001
		if _, refusal := r.Accept(body(t, sentAt(c.now))); refusal != "" {
			t.Fatalf("Accept once forgotten: %q", refusal)
		}
	})

	t.Run("a forgotten id is remembered afresh", func(t *testing.T) {
		r, c := newResponder(t)
		r.Accept(body(t, sample))
		c.now = t0 + 60001
		if _, refusal := r.Accept(body(t, sentAt(c.now))); refusal != "" {
			t.Fatalf("Accept once forgotten: %q", refusal)
		}
		c.now = t0 + 120001
		if _, refusal := r.Accept(body(t, sentAt(c.now))); refusal != event.RepeatedEventID {
			t.Fatalf("Accept 60000 ms after it was accepted again: %q", refusal)
		}
	})
}

// TestAllowListFirst offers an event from a signer that is neither allowed nor in the keyring: it is
// refused as not allowed, since a name not on the allow-list is the sender's own text and is never looked
// up.
func TestAllowListFirst(t *testing.T) {
	r, _ := newResponder(t)
	priv, _ := vectors.V3Key(t, "payment")
	wire, err := sample.Wire()
	if err != nil {
		t.Fatal(err)
	}
	env, err := event.SignEnvelope("billing", wire, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.Wire()
	if err != nil {
		t.Fatal(err)
	}
	if _, refusal := r.Accept(b); refusal != event.SignerNotAllowed {
		t.Fatalf("Accept: %q, want %s", refusal, event.SignerNotAllowed)
	}
}

// TestOneIDFrom64Goroutines offers one body from 64 goroutines at once: one of them is accepted, and every
// other is refused as a repeated id.
func TestOneIDFrom64Goroutines(t *testing.T) {
	r, _ := newResponder(t)
	b := body(t, sample)
	var (
		start    = make(chan struct{})
		wg       sync.WaitGroup
		mu       sync.Mutex
		refusals = map[event.Refusal]int{}
	)
	for range 64 {
		wg.Go(func() {
			<-start
			_, refusal := r.Accept(b)
			mu.Lock()
			refusals[refusal]++
			mu.Unlock()
		})
	}
	close(start)
	wg.Wait()
	if refusals[""] != 1 || refusals[event.RepeatedEventID] != 63 || len(refusals) != 2 {
		t.Fatalf("64 offers of one id gave %v; want one accepted and 63 %s", refusals, event.RepeatedEventID)
	}
}

// TestResponderKeepsItsOwnConfig changes the keyring, its key and the allowed signers a responder was made
// with, after it was made: the responder still accepts the event, and once the key is deleted from the
// keyring it was given, still verifies it, so the event is refused only as repeated.
func TestResponderKeepsItsOwnConfig(t *testing.T) {
	_, pub := vectors.V3Key(t, "payment")
	keyring := policy.Keyring{"payment": append(ed25519.PublicKey(nil), pub...)}
	allowed := []string{"payment"}
	r := event.NewResponder(keyring, allowed, func() int64 { return t0 })
	keyring["payment"][0] ^= 1
	allowed[0] = "orders"
	if _, refusal := r.Accept(body(t, sample)); refusal != "" {
		t.Fatalf("Accept: %q", refusal)
	}
	delete(keyring, "payment")
	if _, refusal := r.Accept(body(t, sample)); refusal != event.RepeatedEventID {
		t.Fatalf("Accept again: %q", refusal)
	}
}

// TestRefusalText pins each refusal's text, the spec's name for it.
func TestRefusalText(t *testing.T) {
	want := []string{"MALFORMED_ENVELOPE", "SIGNER_NOT_ALLOWED", "UNKNOWN_SIGNER", "BAD_SIGNATURE",
		"MALFORMED_EVENT", "NO_EVENT_ID", "OUTSIDE_WINDOW", "REPEATED_EVENT_ID"}
	for i, refusal := range refusals {
		if string(refusal) != want[i] {
			t.Errorf("refusal %d is %q, want %q", i, refusal, want[i])
		}
	}
}

// TestEventWireRefuses writes events no responder would accept, or that have no wire bytes: each is
// refused, not written.
func TestEventWireRefuses(t *testing.T) {
	tests := []struct {
		name string
		edit func(*event.Event)
	}{
		{"no id", func(e *event.Event) { e.EventID = "" }},
		{"a negative ts", func(e *event.Event) { e.TS = -1 }},
		{"a ts past 2^53 - 1", func(e *event.Event) { e.TS = maxSafe + 1 }},
		{"a reason that is not UTF-8", func(e *event.Event) { e.Reason = "\xff" }},
		{"a rid holding a noncharacter", func(e *event.Event) { e.RID = "rid-\xef\xbf\xbf" }},
		{"an id holding the bytes of a lone surrogate", func(e *event.Event) { e.EventID = "\xed\xa0\x80" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := sample
			tt.edit(&ev)
			if b, err := ev.Wire(); err == nil {
				t.Fatalf("Wire = %s, want a refusal", b)
			}
		})
	}
	if b, err := sentAt(maxSafe).Wire(); err != nil {
		t.Fatalf("Wire of the largest ts: %s, %v", b, err)
	}
}

// TestSignEnvelopeRefuses signs bytes a responder would not read as an event with an id, and signs with a
// key that is not an Ed25519 private key: each is refused, with no envelope.
func TestSignEnvelopeRefuses(t *testing.T) {
	priv, _ := vectors.V3Key(t, "payment")
	wire, err := sample.Wire()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		wire []byte
		key  ed25519.PrivateKey
	}{
		{"not JSON", []byte("not json"), priv},
		{"an array", []byte("[]"), priv},
		{"whitespace around the event", append(append([]byte(" "), wire...), ' '), priv},
		{"no id", []byte(`{"audit":false,"reason":"REPLAY","rid":"","suspectInst":"","suspectSvc":"","ts":0}`), priv},
		{"a null id", []byte(`{"audit":false,"eventId":null,"reason":"REPLAY","rid":"","suspectInst":"","suspectSvc":"","ts":0}`), priv},
		{"another member", []byte(`{"audit":false,"eventId":"e","kid":"k","reason":"REPLAY","rid":"","suspectInst":"","suspectSvc":"","ts":0}`), priv},
		{"a short key", wire, priv[:32]},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if env, err := event.SignEnvelope("payment", tt.wire, tt.key); err == nil || env != (event.Envelope{}) {
				t.Fatalf("SignEnvelope = %+v, %v; want a refusal", env, err)
			}
		})
	}
}

// TestEnvelopeWireRefuses writes an envelope whose signer has no UTF-8 form: it is refused, not written.
func TestEnvelopeWireRefuses(t *testing.T) {
	env := event.Envelope{Signer: "pay\xffment", Payload: "e30", Sig: "AAAA"}
	if b, err := env.Wire(); err == nil {
		t.Fatalf("Wire = %s, want a refusal", b)
	}
}

// TestAttributable checks each condition of attributable on its own: an event that is attributable but for
// one of them is not.
func TestAttributable(t *testing.T) {
	if !sample.Attributable() {
		t.Fatalf("the sample is not attributable")
	}
	tests := []struct {
		name string
		edit func(*event.Event)
	}{
		{"an audit event", func(e *event.Event) { e.Audit = true }},
		{"no suspect service", func(e *event.Event) { e.SuspectSvc = "" }},
		{"no suspect instance", func(e *event.Event) { e.SuspectInst = "" }},
		{"a reason off the list", func(e *event.Event) { e.Reason = "INFLUENCE_DENIED" }},
		{"a reason with a trailing space", func(e *event.Event) { e.Reason = "PATH_NOT_ALLOWED " }},
	}
	for _, tt := range tests {
		ev := sample
		tt.edit(&ev)
		if ev.Attributable() {
			t.Errorf("%s is attributable", tt.name)
		}
	}
}
