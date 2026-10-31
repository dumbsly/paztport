// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import type { OfflineReasonCode, ReasonCode } from "./reason.ts";

/**
 * Every refusal code a live verifier can give (a server's verdicts are ReasonCodes; the offline-only
 * codes are not among them). A Record, so tsc flags a code added to the library and missing here.
 */
const REFUSAL_CODES: Record<Exclude<ReasonCode, "OK" | OfflineReasonCode>, true> = {
  CHAIN_MISSING: true,
  BAD_ORIGIN: true,
  BAD_SIGNATURE: true,
  BROKEN_LINK: true,
  EXPIRED: true,
  RID_MISMATCH: true,
  BINDING_MISMATCH: true,
  REPLAY: true,
  PATH_NOT_ALLOWED: true,
  SESSION_UNKNOWN: true,
  CLIENT_PATH_NOT_ALLOWED: true,
  INFLUENCE_MISMATCH: true,
  INFLUENCE_DENIED: true,
  UNSAFE_SESSION: true,
  SCOPE_DENIED: true,
  UNCHECKABLE: true,
  PEER_MISMATCH: true,
  POLICY_EXPIRED: true,
};

/**
 * A refusal reason from a server, made safe to show: it is server data that reaches the model, so anything but a
 * code a live verifier gives (an offline-only code included) becomes "UNKNOWN".
 */
export function sanitiseVerdictReason(reason: unknown): string {
  return typeof reason === "string" && Object.hasOwn(REFUSAL_CODES, reason) ? reason : "UNKNOWN";
}
