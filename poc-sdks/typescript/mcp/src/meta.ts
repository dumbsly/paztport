// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The names Paztport uses on MCP messages: its `_meta` members, each of whose values but META_CALL_ID's is a token,
// the base64url of the object's JCS bytes (spec wire.md, JSON), and its handshake method, SESSION_METHOD.

/** A tools/call's chain: the run's origin, then the calling hop's stamp. */
export const META_CHAIN = "paztport/chain";
/** A tools/call's proof of its route. */
export const META_PROOF = "paztport/proof";
/** A tools/call's blocks, one per stamp of its chain, each committed to by its stamp's `ext` (spec wire.md, MCP). */
export const META_EXTENSIONS = "paztport/extensions";
/** Carries the toolCallId that bindMcpCall covers, as a plain string. */
export const META_CALL_ID = "paztport/callId";
/** A result's attestation: the response chain's blocks, the chain, the server's route proof and the result hash. */
export const META_ATTESTATION = "paztport/attestation";
/** The JSON-RPC method of the session handshake. */
export const SESSION_METHOD = "paztport/session";
/** Carries a server refusal (or an audit-mode verdict) on a tools/call result. */
export const META_VERDICT = "paztport/verdict";
