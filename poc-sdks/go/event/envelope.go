// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package event

import (
	"crypto/ed25519"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
)

// Domain is the prefix of the bytes an event's signer signs. It keeps an event signature from being read as
// a stamp's, or as anything else the same key signs.
const Domain = "paztport-event\n"

// Envelope is a signed event, as it travels to the responder.
type Envelope struct {
	// Signer is the service whose key signed the event, which the responder looks its key up by. It is not
	// signed, but a name other than the signer's own looks up another key, and the signature fails.
	Signer string
	// Payload is the base64url of the event's wire bytes.
	Payload string
	// Sig is the base64url of the Ed25519 signature, by Signer's key, over EnvelopeSigningBytes(Payload).
	Sig string
}

// envelopeMembers are an envelope's members.
var envelopeMembers = []string{"payload", "sig", "signer"}

// SignEnvelope signs eventWire, an event's wire bytes as Event.Wire writes them, as signer, whose private key
// is key. It refuses bytes a responder would not read as an event with an id, and a key that is not
// ed25519.PrivateKeySize bytes long.
func SignEnvelope(signer string, eventWire []byte, key ed25519.PrivateKey) (Envelope, error) {
	e, err := readEvent(eventWire)
	if err != nil {
		return Envelope{}, fmt.Errorf("paztport event: the bytes are not an event: %w", err)
	}
	if e.EventID == "" {
		return Envelope{}, errNoID
	}
	payload := b64.Encode(eventWire)
	sig, err := keys.Sign(key, EnvelopeSigningBytes(payload))
	if err != nil {
		return Envelope{}, fmt.Errorf("paztport event: can't sign the event: %w", err)
	}
	return Envelope{Signer: signer, Payload: payload, Sig: b64.Encode(sig)}, nil
}

// EnvelopeSigningBytes returns the bytes an event's signer signs: Domain, then payload, the base64url text
// exactly as sent, so that a responder verifies the text it was given.
func EnvelopeSigningBytes(payload string) []byte {
	return []byte(Domain + payload)
}

// Wire returns the envelope's canonical bytes: the body sent to the responder. It refuses text with no
// UTF-8 form or holding a noncharacter.
func (e Envelope) Wire() ([]byte, error) {
	b, err := json.Wire(json.Obj(
		json.Member{Name: "signer", Value: json.S(e.Signer)},
		json.Member{Name: "payload", Value: json.S(e.Payload)},
		json.Member{Name: "sig", Value: json.S(e.Sig)},
	))
	if err != nil {
		return nil, fmt.Errorf("paztport event: the envelope can't be written: %w", err)
	}
	return b, nil
}

// readEnvelope reads an envelope from body: exactly the canonical bytes of one object whose signer,
// payload and sig are strings, and which has no other member.
func readEnvelope(body []byte) (Envelope, error) {
	v, err := json.ReadWire(body)
	if err != nil {
		return Envelope{}, err
	}
	if err := json.Exactly(v, envelopeMembers, nil); err != nil {
		return Envelope{}, err
	}
	var e Envelope
	if e.Signer, err = json.String(v, "signer"); err != nil {
		return Envelope{}, err
	}
	if e.Payload, err = json.String(v, "payload"); err != nil {
		return Envelope{}, err
	}
	if e.Sig, err = json.String(v, "sig"); err != nil {
		return Envelope{}, err
	}
	return e, nil
}
