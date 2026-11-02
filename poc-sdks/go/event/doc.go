// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package event builds, signs and checks the events a verifying service sends its responder: one for each
// request whose live verification does not give OK, with the result's reason and suspect, so that the
// responder may act, for example by isolating the named instance.
//
// An [Event] travels as its canonical (JCS) bytes, which [Event.Wire] writes, inside a signed [Envelope]:
// [SignEnvelope] signs the base64url text of those bytes, the payload, over the bytes
//
//	utf8("paztport-event\n" || payload)
//
// that [EnvelopeSigningBytes] returns, and [Envelope.Wire] writes the body sent to the responder. The
// prefix, [Domain], keeps an event signature from being read as a stamp, or as anything else the same key
// signs. This package sends nothing: the code that embeds it carries the body, over HTTP as a POST to the
// responder's /events path.
//
// Anyone who can reach a responder can send it a body, so a [Responder] accepts an event only when an
// allowed signer signed it, its ts is within [WindowMs] of the responder's clock, either way, and its id is
// one the responder has not accepted before. [Responder.Accept] runs the spec's checks in the spec's order
// and answers with the first [Refusal], never an error, and a refused body changes nothing. The envelope and
// the event are each read strictly, from bytes that must be exactly their canonical bytes, with nothing
// converted or filled in, so every implementation reads the same event from the same body.
//
// An accepted event is not by itself a reason to act. A responder acts against a suspect only on an event
// that is [Event.Attributable]: not from audit mode, naming both a service and an instance, and with a
// reason that reports what the sender did.
//
// Times are int64 milliseconds since the Unix epoch, and the window is computed exactly, so no clock at
// either end of int64 passes it by wrapping.
package event
