// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

export type ReasonCode =
  | "OK"
  | "CHAIN_MISSING"
  | "BAD_ORIGIN"
  | "BAD_SIGNATURE"
  | "BROKEN_LINK"
  | "EXPIRED"
  | "RID_MISMATCH"
  | "BINDING_MISMATCH"
  | "REPLAY"
  | "PATH_NOT_ALLOWED"
  | "SESSION_UNKNOWN"
  | "CLIENT_PATH_NOT_ALLOWED"
  | "INFLUENCE_MISMATCH"
  | "INFLUENCE_DENIED"
  | "UNSAFE_SESSION"
  | "SCOPE_DENIED"
  | "UNCHECKABLE"
  | "TIME_MISMATCH"
  | "PROMPT_MISMATCH"
  | "PEER_MISMATCH";

/** Codes only the offline verifier of a recorded chain gives; no live verifier or server returns them. */
export type OfflineReasonCode = "TIME_MISMATCH" | "PROMPT_MISMATCH";

/**
 * A typed verification outcome, naming a suspect for the responder's quarantine decision. With a transport
 * peer, the suspect is that authenticated sender, at every check, OK included: `suspectSvc` is its service and
 * `suspectInst` its address. Without one, `suspectSvc` names the last service that provably sent the request,
 * proven by its key, and `suspectInst` the instance that service reported in its own stamp; they are set only
 * for `OK` and `PATH_NOT_ALLOWED`, and every other rejection leaves them empty, because the name would be
 * unsigned or the genuine stamp would belong to another request. A v3 stamp binds its receiver, so a chain
 * forwarded unchanged to another receiver is BINDING_MISMATCH, and names no one without a peer.
 */
export type VerifyResult = { ok: boolean; reason: ReasonCode; suspectSvc: string; suspectInst: string };
