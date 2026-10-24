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
  | "UNSAFE_SESSION";

export type VerifyResult = { ok: boolean; reason: ReasonCode; suspectSvc: string; suspectInst: string };
