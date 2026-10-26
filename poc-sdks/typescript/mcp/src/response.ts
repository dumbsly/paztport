// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { verifyResponse } from "@paztport/core";
import type { ContentLabel, V2Config, VerifyResult } from "@paztport/core";
import { META_ATTESTATION } from "./meta.ts";

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
