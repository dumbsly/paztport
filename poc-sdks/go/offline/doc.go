// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package offline verifies a record set again later, such as a client's evidence file, with no clock to be
// fresh against: its recorded calls, and the recorded handshakes that opened the sessions they were made in.
//
// A [RecordSet] is one record set being verified again. [RecordSet.Verify] runs the live verifier's checks
// in the live order on one recorded chain, with the spec's offline differences. Check 0 runs against no
// clock: the record's own time stands in for one, and a pinned keyring or root counts for a record when
// that time is at most its notAfter, so a record that no keyring, or no root, counts for is POLICY_EXPIRED.
// Check 7 compares the stamps' times with the ones recorded beside them (TIME_MISMATCH; a record with no
// time fails it), holds the chain to the age limits (EXPIRED; a limit not set is its live default) and
// requires the origin to bind the run's recorded prompt (PROMPT_MISMATCH). Checks 9a and 9b run on the recorded
// blocks, 9b with the Config's own [verify.Extensions]; check 9c never runs offline, since a record does not hold
// the actsOn it was checked against live. There is no check 10, since a record has no transport and so no peer.
// Check 11 refuses a nonce key spent anywhere in the record set, which a live cache that forgets after its
// window can't show; the record set holds the keys its chains have spent. A record that verifies hands over its
// items, verified, as the live verifier does.
//
// [Record] reads a recorded handshake into a [RecordedSession]. The handshake carries no signed time, so it
// is judged at the time of each record that relies on it: [RecordedSession.AttestedAt] takes a call's last
// stamp's ts, which the client signed. Its limits are the certificate's notAfter, in the entry-key form, and
// the notAfter of each root and keyring on both sides, so one session can be attested for the calls recorded
// up to its limits and not for those after them. [RecordSet.Call] verifies a call recorded in a session, with
// the Config [RecordedSession.CallConfig] gives: an extension's [ItemCheck] reads the items of a call that
// verifies, before the session's limits, and a call that verifies past one of them is OUTSIDE_SESSION; a call in
// a session that is not attested at all has no result. [RecordedSession.ResponseNotAfter] gives the limit a
// response recorded in the session is checked with, and none where the server's signatures do not verify.
//
// A record set is read in order, by one goroutine, since Verify and Call spend keys in it. Times are int64
// milliseconds since the Unix epoch, and every difference between them is computed exactly, so no time or
// limit at either end of int64 passes a check by wrapping.
package offline
