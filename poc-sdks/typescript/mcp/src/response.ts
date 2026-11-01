// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { verifyResponse } from "@paztport/core";
import type { ContentLabel, V3Config, VerifyResult } from "@paztport/core";
import { META_ATTESTATION, META_VERDICT } from "./meta.ts";
import { readVerdict, type Verdict } from "./verdict.ts";

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The own `_meta` member `name` of a result, or undefined when the result has no such member. */
function metaOf(result: Record<string, unknown>, name: string): unknown {
  const meta = result._meta;
  return isObject(meta) && Object.hasOwn(meta, name) ? meta[name] : undefined;
}

/**
 * Hands the attestation token in `result._meta` to core's response check, its last stamp naming `call.receiver`, the
 * client that made the call; an attestation that is not a string is CHAIN_MISSING. A client re-checking a recorded
 * response passes the time it recorded verifying it as `cfg.now`: the receiver records a response, so no stamp time
 * is known to match, unlike a call, which verifyRecordedCall checks against the time its own hop stamped it. Never
 * throws.
 */
export function verifyMcpResponse(
  result: Record<string, unknown>,
  call: { rid: string; toolCallId: string; receiver: string },
  cfg: Omit<V3Config, "nonceKey">,
): { result: VerifyResult; labels: ContentLabel[] } {
  const attestation = metaOf(result, META_ATTESTATION);
  if (typeof attestation !== "string") {
    return { result: { ok: false, reason: "CHAIN_MISSING", suspectSvc: "", suspectInst: "" }, labels: [] };
  }
  return verifyResponse(attestation, result, call, cfg);
}

/**
 * Whether a tools/call result has a server refusal's shape: isError true, and a `_meta` that holds only a verdict
 * token that reads and is not an audit note. A refusal is unsigned by design, so this is all that can be checked of
 * one; it counts as a refusal only when it answers a call that verified.
 */
export function hasRefusalShape(result: Record<string, unknown>): boolean {
  const meta = result._meta;
  if (result.isError !== true || !isObject(meta)) {
    return false;
  }
  const keys = Object.keys(meta);
  if (keys.length !== 1 || keys[0] !== META_VERDICT) {
    return false;
  }
  const token = meta[META_VERDICT];
  if (typeof token !== "string") {
    return false;
  }
  let verdict: Verdict;
  try {
    verdict = readVerdict(token);
  } catch {
    return false;
  }
  return verdict.audit !== true;
}
