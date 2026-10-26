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
  | "UNCHECKABLE";

/**
 * A typed verification outcome. `suspectSvc` names the last service that provably sent the request,
 * proven by its key, and `suspectInst` the instance that service reported in its own stamp, for the
 * responder's quarantine decision. They are set only for `OK` and
 * `PATH_NOT_ALLOWED`; every other rejection leaves them empty, because the name would be unsigned or
 * the genuine stamp would belong to another request. A stamp does not bind its receiver, so a chain
 * forwarded unchanged to another receiver can still blame its last signer.
 */
export type VerifyResult = { ok: boolean; reason: ReasonCode; suspectSvc: string; suspectInst: string };
