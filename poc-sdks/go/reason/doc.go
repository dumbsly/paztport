// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package reason holds the reason codes a verification gives: [OK], or the one reason it was rejected.
//
// A verifier returns a code, never an error, so a malformed or forged input is an answer, not a failure.
// Each code's text is the spec's, so it can be sent, logged and compared as it is.
//
// The codes come from three places. A live verifier gives [OK], the codes from [ChainMissing] to [PolicyExpired]
// and those of checks 9a to 9c. An offline verifier gives the same but [PeerMismatch], and also [TimeMismatch],
// [PromptMismatch] and [OutsideSession], which are never sent live: a client must not take them for a
// server's verdict. A server deciding on a call may also answer [InfluenceDenied] or [UnsafeSession].
// [ExtensionMismatch], [ExtensionNotAllowed] and [ExtensionRequired] are the codes of the spec's checks 9a to 9c.
// [InfluenceMismatch] is an extension's code, not a check of the live order: the influence extension gives it, live
// and offline, for an item that does not read.
package reason
