// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package event_test

import (
	"bytes"
	"crypto/ed25519"
	"strconv"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/event"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// refusals are the eight refusals, as the spec names them.
var refusals = []event.Refusal{
	event.MalformedEnvelope, event.SignerNotAllowed, event.UnknownSigner, event.BadSignature,
	event.MalformedEvent, event.NoEventID, event.OutsideWindow, event.RepeatedEventID,
}

// TestEnvelopeVectors replays events.json's envelope cases: the event writes to exactly eventJson, and
// signing it as the case's signer gives its payload, its signing bytes (the domain prefix and the payload's
// text) and its sig, since Ed25519 is deterministic. The envelope's body is the one a responder accepts.
func TestEnvelopeVectors(t *testing.T) {
	cases := vectors.Load(t, "events.json").Get("envelope")
	if cases.Len() != 3 {
		t.Fatalf("envelope has %d cases, want 3", cases.Len())
	}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			signer := c.Get("signer").Str()
			priv, pub := vectors.V3Key(t, signer)
			ev := eventOf(c.Get("event"))
			wire, err := ev.Wire()
			if err != nil || string(wire) != c.Get("eventJson").Str() {
				t.Fatalf("Wire = %s, %v; want %s", wire, err, c.Get("eventJson").Str())
			}
			env, err := event.SignEnvelope(signer, wire, priv)
			if err != nil {
				t.Fatalf("SignEnvelope: %v", err)
			}
			payload := c.Get("payload").Str()
			if env.Signer != signer || env.Payload != payload || env.Sig != c.Get("sig").Str() {
				t.Fatalf("SignEnvelope = %+v; want signer %s, payload %s, sig %s", env, signer, payload,
					c.Get("sig").Str())
			}
			signing, err := b64.Decode(c.Get("signingBytes").Str())
			if err != nil {
				t.Fatalf("signingBytes: %v", err)
			}
			if got := event.EnvelopeSigningBytes(payload); !bytes.Equal(got, signing) {
				t.Fatalf("EnvelopeSigningBytes = %q, want %q", got, signing)
			}
			if string(signing) != "paztport-event\n"+payload || event.Domain != "paztport-event\n" {
				t.Fatalf("the signing bytes are %q under the domain %q", signing, event.Domain)
			}

			body, err := env.Wire()
			want := `{"payload":"` + payload + `","sig":"` + env.Sig + `","signer":"` + signer + `"}`
			if err != nil || string(body) != want {
				t.Fatalf("Envelope.Wire = %s, %v; want %s", body, err, want)
			}
			r := event.NewResponder([]policy.Keyring{{signer: pub}}, []string{signer}, func() int64 { return ev.TS })
			if got, refusal := r.Accept(body); refusal != "" || got != ev {
				t.Fatalf("Accept = %+v, %q; want %+v", got, refusal, ev)
			}
		})
	})
}

// TestAttributableVectors replays events.json's attributable cases: whether a responder may act against
// the event's suspect.
func TestAttributableVectors(t *testing.T) {
	cases := vectors.Load(t, "events.json").Get("attributable")
	if cases.Len() != 27 {
		t.Fatalf("attributable has %d cases, want 27", cases.Len())
	}
	seen := map[bool]int{}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			want := c.Get("expected").Bool()
			seen[want]++
			if got := eventOf(c.Get("event")).Attributable(); got != want {
				t.Fatalf("Attributable = %t, want %t", got, want)
			}
		})
	})
	if seen[true] != 13 {
		t.Errorf("%d cases are attributable; want the 13 of the allow-list", seen[true])
	}
}

// TestVerifyVectors replays events.json's verify cases, each against a fresh responder holding the case's
// keyrings, or the file's keyring when it gives none, the file's allowed signers and no event ids: each
// earlier body is offered at its now, in order, then body uses times at the case's now, and the last answer
// is compared. An accepted event is the one the case gives, and writes back to exactly the payload's bytes.
func TestVerifyVectors(t *testing.T) {
	file := vectors.Load(t, "events.json")
	cases := file.Get("verify")
	if cases.Len() != 78 {
		t.Fatalf("verify has %d cases, want 78", cases.Len())
	}
	seen := map[event.Refusal]int{}
	cases.Each(func(name string, c vectors.Node) {
		t.Run(name, func(t *testing.T) {
			c := c.With(t)
			got, refusal := replay(t, file.With(t), c)
			expected := c.Get("expected")
			if expected.Get("refusal").IsNull() {
				seen[""]++
				want := eventOf(expected.Get("event"))
				if refusal != "" || got != want {
					t.Fatalf("Accept = %+v, %q; want %+v", got, refusal, want)
				}
				wire, err := got.Wire()
				if err != nil || !bytes.Equal(wire, payloadOf(t, []byte(c.Get("body").Str()))) {
					t.Fatalf("Wire = %s, %v; want the payload's bytes", wire, err)
				}
				return
			}
			want := event.Refusal(expected.Get("refusal").Str())
			seen[want]++
			if !expected.Get("event").IsNull() {
				t.Fatalf("a refused case gives an event")
			}
			if refusal != want || got != (event.Event{}) {
				t.Fatalf("Accept = %+v, %q; want %q and no event", got, refusal, want)
			}
		})
	})
	if seen[""] == 0 {
		t.Errorf("no case is accepted")
	}
	for _, refusal := range refusals {
		if seen[refusal] == 0 {
			t.Errorf("no case is refused %s", refusal)
		}
	}
}

// TestVerifyVectorsReadTheOptionalKeyrings checks that the replay reads the keyrings a case may carry,
// though no committed case carries them yet: every verify case, given the file's keyring as its keyrings,
// whole or split one service to a keyring, gives the answer it gives under the file's keyring. And the
// case's keyrings are what is used: without the signer's key, an event it signed has no key.
func TestVerifyVectorsReadTheOptionalKeyrings(t *testing.T) {
	file := vectors.Load(t, "events.json")
	// The file's keyring by key name, each service to the name of the key in keys that it holds.
	byName := map[string]string{}
	file.Get("keys").Each(func(name string, k vectors.Node) {
		byName[k.Get("pub").Str()] = name
	})
	ring := file.Get("responder").Get("keyring")
	var whole, split []string
	for _, svc := range ring.Names() {
		name, ok := byName[ring.Get(svc).Str()]
		if !ok {
			t.Fatalf("no key in keys is the responder's for %s", svc)
		}
		member := strconv.Quote(svc) + ": " + strconv.Quote(name)
		whole = append(whole, member)
		split = append(split, "{"+member+"}")
	}
	for _, keyrings := range []string{"[{" + strings.Join(whole, ", ") + "}]", "[" + strings.Join(split, ", ") + "]"} {
		file.Get("verify").Each(func(name string, c vectors.Node) {
			t.Run(name+" under "+keyrings, func(t *testing.T) {
				c := c.With(t)
				wantEvent, wantRefusal := replay(t, file.With(t), c)
				with := c.Rewrite(nil, vectors.Member{Name: "keyrings", Text: keyrings})
				if got, refusal := replay(t, file.With(t), with); got != wantEvent || refusal != wantRefusal {
					t.Fatalf("Accept = %+v, %q; want %+v, %q", got, refusal, wantEvent, wantRefusal)
				}
			})
		})
	}
	var accepted vectors.Node
	file.Get("verify").Each(func(name string, c vectors.Node) {
		if name == "accepted" {
			accepted = c
		}
	})
	keyless := accepted.Rewrite(nil, vectors.Member{Name: "keyrings", Text: `[{"search": "search"}]`})
	if _, refusal := replay(t, file, keyless); refusal != event.UnknownSigner {
		t.Fatalf("Accept under a keyring without the signer's key: %q, want %s", refusal, event.UnknownSigner)
	}
}

// replay runs case c of events.json's verify section and returns the last answer.
func replay(t *testing.T, file, c vectors.Node) (event.Event, event.Refusal) {
	t.Helper()
	keyring, allowed := responderConfig(t, file.Get("responder"))
	keyrings := []policy.Keyring{keyring}
	if c.Has("keyrings") {
		keyrings = nil
		c.Get("keyrings").Each(func(_ string, ring vectors.Node) {
			k := policy.Keyring{}
			ring.Each(func(svc string, name vectors.Node) {
				k[svc] = publicKey(t, file.Get("keys").Get(name.Str()).Get("pub"))
			})
			keyrings = append(keyrings, k)
		})
	}
	var now int64
	r := event.NewResponder(keyrings, allowed, func() int64 { return now })
	c.Get("earlier").Each(func(_ string, e vectors.Node) {
		now = e.Get("now").Int()
		r.Accept([]byte(e.Get("body").Str()))
	})
	now = c.Get("now").Int()
	body := []byte(c.Get("body").Str())
	uses := c.Get("uses").Int()
	if uses < 1 {
		t.Fatalf("the case offers its body %d times", uses)
	}
	var got event.Event
	var refusal event.Refusal
	for range uses {
		got, refusal = r.Accept(body)
	}
	return got, refusal
}

// responderConfig returns the keyring and allowed signers of events.json's responder.
func responderConfig(t testing.TB, n vectors.Node) (policy.Keyring, []string) {
	t.Helper()
	keyring := policy.Keyring{}
	n.Get("keyring").Each(func(svc string, pub vectors.Node) {
		keyring[svc] = publicKey(t, pub)
	})
	var allowed []string
	n.Get("allowedSigners").Each(func(_ string, s vectors.Node) {
		allowed = append(allowed, s.Str())
	})
	return keyring, allowed
}

// publicKey returns the public key n holds as text.
func publicKey(t testing.TB, n vectors.Node) ed25519.PublicKey {
	t.Helper()
	key, err := keys.ParsePublic(n.Str())
	if err != nil {
		t.Fatalf("the key %s: %v", n.Raw(), err)
	}
	return key
}

// eventOf returns the event whose seven fields n gives.
func eventOf(n vectors.Node) event.Event {
	return event.Event{
		Reason:      n.Get("reason").Str(),
		SuspectSvc:  n.Get("suspectSvc").Str(),
		SuspectInst: n.Get("suspectInst").Str(),
		RID:         n.Get("rid").Str(),
		Audit:       n.Get("audit").Bool(),
		TS:          n.Get("ts").Int(),
		EventID:     n.Get("eventId").Str(),
	}
}

// payloadOf returns the bytes of the payload of envelope body.
func payloadOf(t *testing.T, body []byte) []byte {
	t.Helper()
	v, err := json.ReadWire(body)
	if err != nil {
		t.Fatalf("the body: %v", err)
	}
	payload, err := json.String(v, "payload")
	if err != nil {
		t.Fatalf("the body: %v", err)
	}
	b, err := b64.Decode(payload)
	if err != nil {
		t.Fatalf("the payload: %v", err)
	}
	return b
}
