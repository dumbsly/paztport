// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { verifyResponse } from "@paztport/core";
import type { ContentLabel, V2Config, VerifyResult } from "@paztport/core";
import { META_ATTESTATION, META_VERDICT } from "./meta.ts";

/** Reads the attestation from `result._meta` and hands it to core's response check; never throws. */
export function verifyMcpResponse(
  result: Record<string, unknown>,
  call: { rid: string; toolCallId: string },
  cfg: Omit<V2Config, "nonceKey">,
): { result: VerifyResult; labels: ContentLabel[] } {
  let att: unknown;
  try {
    const meta = result._meta;
    att = typeof meta === "object" && meta !== null && !Array.isArray(meta)
      ? (meta as Record<string, unknown>)[META_ATTESTATION]
      : undefined;
  } catch {
    att = undefined;
  }
  return verifyResponse(att, result, call, cfg);
}

/**
 * Whether a tools/call result has a server refusal's shape: isError true, and a `_meta` that holds only a
 * non-audit verdict. A refusal is unsigned by design, so this is all that can be checked of one; it counts
 * as a refusal only when it answers a call that verified.
 */
export function hasRefusalShape(result: Record<string, unknown>): boolean {
  const meta = result._meta;
  if (result.isError !== true || typeof meta !== "object" || meta === null || Array.isArray(meta)) {
    return false;
  }
  const keys = Object.keys(meta);
  if (keys.length !== 1 || keys[0] !== META_VERDICT) {
    return false;
  }
  const verdict = (meta as Record<string, unknown>)[META_VERDICT];
  return typeof verdict === "object" && verdict !== null && !Array.isArray(verdict) && (verdict as Record<string, unknown>).audit !== true;
}
