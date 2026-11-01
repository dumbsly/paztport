// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The names Paztport uses on MCP messages: its `_meta` members, each of whose values but META_CALL_ID's is a token,
// the base64url of the object's JCS bytes (spec wire.md, JSON), and its handshake method, SESSION_METHOD.

export const META_CHAIN = "paztport/chain";
export const META_PROOF = "paztport/proof";
export const META_INFLUENCE = "paztport/influence";
/** Carries the toolCallId that bindMcpCall covers, as a plain string. */
export const META_CALL_ID = "paztport/callId";
export const META_ATTESTATION = "paztport/attestation";
export const SESSION_METHOD = "paztport/session";
/** Carries a server refusal (or an audit-mode verdict) on a tools/call result. */
export const META_VERDICT = "paztport/verdict";
