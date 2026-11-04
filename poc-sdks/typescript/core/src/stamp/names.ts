// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { requireValidNode } from "../policy/routes.ts";

/**
 * Refuses to stamp as a signing service (`role` "svc") or to a receiver (`role` "rcv") that is not a route node
 * (non-empty, not `.` or `..`, none of `/`, `\`, `|` or a lone surrogate): no policy can route such a name, so the
 * stamp could never verify. The message names the role and the rule, never the value, since a name can come from a
 * request or a server. `signStamp` itself does not call this, so a test can still build a deliberately bad stamp for
 * a verifier.
 */
export function requireStampableName(role: "svc" | "rcv", name: string): void {
  try {
    requireValidNode(name);
  } catch {
    throw new Error(`${role} must be a route node: non-empty, not "." or "..", and without "/", "\\", "|" or a lone surrogate`);
  }
}

/** `requireStampableName` for a stamp's `svc` and then its `rcv`. */
export function requireStampableNames(svc: string, rcv: string): void {
  requireStampableName("svc", svc);
  requireStampableName("rcv", rcv);
}
