// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package session opens a session between two organisations: the handshake's request and reply, the
// client's check of the reply, the server's decision to attest, and the session id that binds the two.
//
// The handshake has no transport here. A client sends a [Request]: its signed root (or none, to ask for an
// unsafe session), its policy key, its signed keyring and a fresh nonce from [NewNonce]. A server reads it
// with [ParseRequest] or [ReadRequest], which refuse a malformed request (the server answers Invalid
// params), checks [OpensSession], decides the session's status with [Status], derives its id with [ID]
// and signs a [Reply] with [SignReply]. The client then judges the reply's bytes with
// [CheckReply], whose [Check] is the first of the spec's checks that fails, in the spec's order: the reply
// reads, it names the pinned policy key, its signature, roots and session id hold, and then its status.
//
// A reply comes in one of two forms, told apart only by which members are present, never by which key
// verifies. In the entry-key form the reply carries the policy key's signature over the server's keyring
// and a reply certificate for the server's entry service, and the entry service's key signs the reply, so
// the policy key can stay offline. In the policy-key form it carries neither, and the policy key signs.
// The reply's signature covers the reply as received, less its sig:
//
//	"paztport-session-reply\n" || JCS(reply without sig)
//
// which [Reply.SigningBytes] returns. A reply reads only from its canonical bytes, so a [Reply] read by
// [ParseReply] writes back to exactly the bytes it was read from.
//
// The two sides hold their material to the same windows: a root or keyring counts only once the policy
// key's signature over it verifies, and only until its notAfter. [AttestedOffline] judges a recorded
// handshake at the time of the record, where [CheckReply] judges it at the client's clock.
//
// Times are int64 milliseconds since the Unix epoch.
package session
