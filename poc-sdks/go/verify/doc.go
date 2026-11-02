// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package verify checks chains received live: the spec's live order of checks, its windows, the nonce
// cache that stops replays, and who a result names.
//
// A [Verifier] holds a [Config]: the keyring and root it pins, the origins and session it allows, its
// clock, its freshness windows and its [NonceCache]. [Pinned] fills one in from a keyring file and a root
// that verify under the pinned policy key and are current, recording the earlier of their windows. For
// each request, [Verifier.Verify] takes an [Input], the tokens that came with the request and what the
// receiver knows of it, and runs checks 0 to 12 in the spec's order. The first that fails is the
// [Result], whose reason.Code is the spec's for that check; a request that passes them all is OK. The
// order is part of the protocol: two verifiers that ran the checks in another order would give
// different codes for the same request.
//
// Check 0 is about the verifier's own material, not the request: once its clock passes the policy's
// window, no keyring or root it holds says which keys and routes the policy owner allows. So it comes
// first, before the chain is read, and it names no one and spends no nonce key. The nonce cache is
// consulted only after checks 1 to 9 have held, and a cache that forgets sooner than twice the call
// window refuses every key before recording any, since it could forget a key while a replay of it is
// still fresh. A context passed to Verify reaches only the nonce cache, which may block on a store.
//
// A Result names a suspect, the party a responder may act against, for the verifier's own logs and
// events, never for the caller. With a [Peer], the sender the transport authenticated, every result but
// POLICY_EXPIRED names the peer. Without one, only OK and PATH_NOT_ALLOWED name the last stamp's svc and
// inst: by then its signature, receiver, times, binding and nonce key have held, so its key really signed
// this request for this receiver. Any earlier name would be unsigned, or belong to another request.
//
// Times and windows are int64 milliseconds since the Unix epoch, and every difference between them is
// computed exactly: a clock or a window at either end of int64 never passes a check by wrapping.
package verify
