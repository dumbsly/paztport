// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readToken } from "@paztport/core";

/** A server's verdict on a tools/call: its reason, and `audit` when the call ran anyway in audit mode. */
export type Verdict = { reason: string; audit?: true };

/**
 * Reads a verdict from its token: MalformedJson for bytes that do not read, an Error naming the member for a verdict
 * other than exactly a string `reason` and, optionally, an `audit` that is `true`. The reason is server data: a
 * client shows only a code it knows (sanitiseVerdictReason).
 */
export function readVerdict(token: string): Verdict {
  const v = readToken(token);
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error("not an object");
  if (!Object.hasOwn(v, "reason")) throw new Error("no member reason");
  for (const name of Object.keys(v)) {
    if (name !== "reason" && name !== "audit") throw new Error("a member the object does not define");
  }
  const reason = v.reason;
  if (typeof reason !== "string") throw new Error("member reason is not a string");
  if (!Object.hasOwn(v, "audit")) return { reason };
  if (v.audit !== true) throw new Error("member audit is not true");
  return { reason, audit: true };
}
