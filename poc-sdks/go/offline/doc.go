// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package offline verifies a record set again later, such as a client's evidence file, with no clock to be
// fresh against: its recorded calls, and the recorded handshakes that opened the sessions they were made in.
//
// [Verify] runs the live verifier's checks in the live order on one recorded chain, with the spec's offline
// differences. There is no check 0: the record's own times stand in for a clock. Check 7 compares the
// stamps' times with the ones recorded beside them (TIME_MISMATCH), holds the chain to the age limits
// (EXPIRED) and requires the origin to bind the run's recorded prompt (PROMPT_MISMATCH). Check 10 refuses a
// nonce key spent anywhere in the record set, which a live cache that forgets after its window can't show.
// There is no check 12, since a record has no transport and so no peer. The [Config] carries the record
// set's spent keys, and Verify adds each chain's own.
//
// [Record] reads a recorded handshake into a [RecordedSession]. The handshake carries no signed time, so it
// is judged at the time of each record that relies on it: [RecordedSession.AttestedAt] takes a call's last
// stamp's ts, which the client signed. Its limits are the certificate's notAfter, in the entry-key form, and
// the notAfter of each root and keyring on both sides, so one session can be attested for the calls recorded
// up to its limits and not for those after them. A [RecordSet] holds the spent keys every call of one record
// set is checked against, and [RecordSet.CallInSession] gives a verified call past one of its session's
// limits OUTSIDE_SESSION.
//
// A record set is read in order, by one goroutine: Verify writes to the Config's spent keys. Times are int64
// milliseconds since the Unix epoch, and every difference between them is computed exactly, so no time or
// limit at either end of int64 passes a check by wrapping.
package offline
