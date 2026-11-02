// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package event

import (
	"slices"
	"sync"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/b64"
	"github.com/dumbsly/paztport/poc-sdks/go/internal/exact"
	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// Refusal is why a responder refused a body, as the spec names it. A refusal's name is for the
// responder's own log: the sender is told only that the event was refused, the same for every refusal, so
// the answer tells it nothing about the allowed signers, the keyring or the window.
type Refusal string

// The refusals, in the order a responder checks for them.
const (
	// MalformedEnvelope means the body is not an envelope.
	MalformedEnvelope Refusal = "MALFORMED_ENVELOPE"
	// SignerNotAllowed means the signer is not one the responder takes events from.
	SignerNotAllowed Refusal = "SIGNER_NOT_ALLOWED"
	// UnknownSigner means the signer is allowed, but the keyring has no key for it.
	UnknownSigner Refusal = "UNKNOWN_SIGNER"
	// BadSignature means the signature does not decode, or does not verify.
	BadSignature Refusal = "BAD_SIGNATURE"
	// MalformedEvent means the signed payload is not an event.
	MalformedEvent Refusal = "MALFORMED_EVENT"
	// NoEventID means the event has no id.
	NoEventID Refusal = "NO_EVENT_ID"
	// OutsideWindow means the event's ts is more than WindowMs from the responder's clock.
	OutsideWindow Refusal = "OUTSIDE_WINDOW"
	// RepeatedEventID means the responder has already accepted an event with this id.
	RepeatedEventID Refusal = "REPEATED_EVENT_ID"
)

// WindowMs is how far, in milliseconds, an event's ts may be from the responder's clock, either way.
const WindowMs = 30000

// idTTLMs is how long a responder remembers an id after accepting it: twice the window, since an event is
// fresh from WindowMs before its ts to WindowMs after, so a replay of an id is stale once it is forgotten.
const idTTLMs = 2 * WindowMs

// Responder decides whether an event body may reach whatever acts on it. It is safe for use by many
// goroutines. Make one with NewResponder.
type Responder struct {
	keyring policy.Keyring
	allowed []string
	now     func() int64

	mu   sync.Mutex
	seen map[string]int64 // each accepted id that is still remembered, and the now it was accepted at
}

// NewResponder returns a responder that takes events from allowedSigners alone, looks each signer's key up
// in keyring by its own name, and reads the time, in milliseconds since the Unix epoch, from now. It keeps
// its own copy of keyring, every key in it, and allowedSigners, so changing them later changes nothing. It
// remembers no ids yet. A nil keyring or allowedSigners is empty, so the responder refuses every event.
// NewResponder panics if now is nil: no responder can run without a clock, and that is a fault in the
// program, not in any event.
func NewResponder(keyring policy.Keyring, allowedSigners []string, now func() int64) *Responder {
	if now == nil {
		panic("paztport event: a Responder needs a clock")
	}
	own := make(policy.Keyring, len(keyring))
	for svc, key := range keyring {
		own[svc] = slices.Clone(key)
	}
	return &Responder{
		keyring: own,
		allowed: slices.Clone(allowedSigners),
		now:     now,
		seen:    make(map[string]int64),
	}
}

// Accept checks body, the bytes received, as an event, and returns the event with an empty Refusal when it
// is accepted, or the zero Event and the first check that fails, in this order:
//
//  1. body is exactly the canonical bytes of an envelope, an object of exactly a string signer, payload
//     and sig (MalformedEnvelope);
//  2. the signer is allowed (SignerNotAllowed);
//  3. the keyring has a key for the signer (UnknownSigner);
//  4. sig is canonical base64url, and verifies under that key over EnvelopeSigningBytes(payload)
//     (BadSignature);
//  5. payload is canonical base64url of exactly the canonical bytes of an event, every member of its type
//     and no other member, but for an absent or null eventId, which is left to check 6 (MalformedEvent);
//  6. eventId is present and is neither null nor "": any other string is an id (NoEventID);
//  7. |now - ts| <= WindowMs, computed exactly (OutsideWindow);
//  8. the id is not one the responder remembers (RepeatedEventID). It is then remembered, from now, for
//     twice WindowMs.
//
// The allow-list comes before the keyring, so a name not on it, the sender's own text, is never looked up.
// Nothing past the envelope is read until an allowed key's signature has verified, so a malformed event
// can only come from an allowed signer. The id is checked last, so a forged, stale or malformed body never
// spends an id the real signer will use: a refused body changes nothing.
//
// Accept never panics on any body.
func (r *Responder) Accept(body []byte) (Event, Refusal) {
	env, err := readEnvelope(body)
	if err != nil {
		return Event{}, MalformedEnvelope
	}
	if !slices.Contains(r.allowed, env.Signer) {
		return Event{}, SignerNotAllowed
	}
	key, ok := r.keyring[env.Signer]
	if !ok {
		return Event{}, UnknownSigner
	}
	sig, err := b64.Decode(env.Sig)
	if err != nil || !keys.Verify(key, EnvelopeSigningBytes(env.Payload), sig) {
		return Event{}, BadSignature
	}
	payload, err := b64.Decode(env.Payload)
	if err != nil {
		return Event{}, MalformedEvent
	}
	e, err := readEvent(payload)
	if err != nil {
		return Event{}, MalformedEvent
	}
	if e.EventID == "" {
		return Event{}, NoEventID
	}
	now := r.now()
	if !exact.AtMost(now, e.TS, WindowMs) || !exact.AtMost(e.TS, now, WindowMs) {
		return Event{}, OutsideWindow
	}
	if !r.firstSighting(e.EventID, now) {
		return Event{}, RepeatedEventID
	}
	return e, ""
}

// firstSighting remembers id at now, and reports whether it was not already remembered. It first forgets
// every id accepted more than idTTLMs before now. A remembered id stays as it was: offering it again does
// not renew it.
func (r *Responder) firstSighting(id string, now int64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for seenID, at := range r.seen {
		if !exact.AtMost(now, at, idTTLMs) {
			delete(r.seen, seenID)
		}
	}
	if _, ok := r.seen[id]; ok {
		return false
	}
	r.seen[id] = now
	return true
}
