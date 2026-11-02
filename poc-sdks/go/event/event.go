// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package event

import (
	"errors"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
)

// Event reports one request a verifying service did not verify as OK.
type Event struct {
	// Reason is the reason code the signer's verifier gave the request. It is the signer's text, so it may
	// be a code this SDK does not know.
	Reason string
	// SuspectSvc and SuspectInst are the suspect the result names, or "" for none.
	SuspectSvc, SuspectInst string
	// RID is the rid of the refused chain's origin stamp, as received, or "" when no chain was read. It is
	// not verified, so it is for matching the event with the signer's own logs only.
	RID string
	// Audit is true when the signer runs in audit mode, so it reported the failure but did not refuse the
	// request.
	Audit bool
	// TS is when the event was signed, a protocol integer.
	TS int64
	// EventID is the event's id, which must not be "". A signer never reuses one, and should make it a
	// random (version 4) UUID: a responder remembers the ids of every signer together, so a guessable id
	// would let one signer spend another's.
	EventID string
}

var (
	// eventMembers are an event's members but eventId, which may be absent and is checked apart.
	eventMembers  = []string{"audit", "reason", "rid", "suspectInst", "suspectSvc", "ts"}
	eventIDMember = []string{"eventId"}

	errNoID = errors.New("paztport event: the event has no id")
)

// Wire returns the event's canonical bytes: the bytes SignEnvelope signs, and the only bytes a responder
// reads as this event. It refuses an event with no id, a ts outside [0, 2^53 - 1], and text with no UTF-8
// form or holding a noncharacter, none of which a responder accepts.
func (e Event) Wire() ([]byte, error) {
	if e.EventID == "" {
		return nil, errNoID
	}
	b, err := json.Wire(json.Obj(
		json.Member{Name: "reason", Value: json.S(e.Reason)},
		json.Member{Name: "suspectSvc", Value: json.S(e.SuspectSvc)},
		json.Member{Name: "suspectInst", Value: json.S(e.SuspectInst)},
		json.Member{Name: "rid", Value: json.S(e.RID)},
		json.Member{Name: "audit", Value: json.B(e.Audit)},
		json.Member{Name: "ts", Value: json.I(e.TS)},
		json.Member{Name: "eventId", Value: json.S(e.EventID)},
	))
	if err != nil {
		return nil, fmt.Errorf("paztport event: the event can't be written: %w", err)
	}
	return b, nil
}

// clientPathNotAllowed is an MCP server's name for PATH_NOT_ALLOWED against the client's policy. No verifier
// in this SDK gives it, so it is not a reason.Code, but an event that reports it is attributable.
const clientPathNotAllowed = "CLIENT_PATH_NOT_ALLOWED"

// Attributable reports whether a responder may act against the event's suspect: the event is not from
// audit mode, it names both a service and an instance, and its reason is one of the codes that report what
// the sender did. The reasons are an allow-list, since a reason is the signer's text: a code this SDK does
// not know is never acted on. Any other reason is the verifier's own policy running out, a sound chain
// refused for what shaped it, or a code that is never a live verdict on a request.
func (e Event) Attributable() bool {
	return !e.Audit && e.SuspectSvc != "" && e.SuspectInst != "" && attributableReason(e.Reason)
}

// attributableReason reports whether reason is on the allow-list of attributable reasons.
func attributableReason(r string) bool {
	switch r {
	case string(reason.ChainMissing), string(reason.BadOrigin), string(reason.BadSignature),
		string(reason.BrokenLink), string(reason.Expired), string(reason.RIDMismatch),
		string(reason.BindingMismatch), string(reason.Replay), string(reason.PathNotAllowed),
		string(reason.SessionUnknown), clientPathNotAllowed, string(reason.InfluenceMismatch),
		string(reason.PeerMismatch):
		return true
	}
	return false
}

// readEvent reads an event from its wire bytes: exactly the canonical bytes of one object with each of the
// event's members, of its type, and no other, ts a protocol integer. An absent or null eventId reads as
// "", which a responder refuses as having no id rather than as malformed; one that is present otherwise
// must be a string.
func readEvent(b []byte) (Event, error) {
	v, err := json.ReadWire(b)
	if err != nil {
		return Event{}, err
	}
	if err := json.Exactly(v, eventMembers, eventIDMember); err != nil {
		return Event{}, err
	}
	var e Event
	if e.Reason, err = json.String(v, "reason"); err != nil {
		return Event{}, err
	}
	if e.SuspectSvc, err = json.String(v, "suspectSvc"); err != nil {
		return Event{}, err
	}
	if e.SuspectInst, err = json.String(v, "suspectInst"); err != nil {
		return Event{}, err
	}
	if e.RID, err = json.String(v, "rid"); err != nil {
		return Event{}, err
	}
	if e.Audit, err = json.Bool(v, "audit"); err != nil {
		return Event{}, err
	}
	if e.TS, err = json.Integer(v, "ts"); err != nil {
		return Event{}, err
	}
	if id, ok := json.Field(v, "eventId"); ok && id.Kind() != json.KindNull {
		if e.EventID, err = json.String(v, "eventId"); err != nil {
			return Event{}, err
		}
	}
	return e, nil
}
