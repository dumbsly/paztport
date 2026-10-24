// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync } from "node:fs";
import type { SessionRequest } from "@paztport/path-attest";

/**
 * Everything a third party needs to re-verify a run offline: public keys, signed roots, chains,
 * attestations, and the tool arguments and results. Never a private key. The model never sees it.
 */
export type EvidenceRecord =
  | { v: 1; type: "run"; rid: string; ts: number; prompt: string }
  | { v: 1; type: "session"; server: string; request: SessionRequest; reply: unknown; pin: string | null; status: "attested" | "unsafe"; reason?: string }
  | { v: 1; type: "call"; server: string; tool: string; callId: string; rid: string; now: number; params: { name: string; arguments: Record<string, unknown>; _meta: Record<string, unknown> } }
  | { v: 1; type: "response"; server: string; tool: string; callId: string; rid: string; now: number; result: unknown };

/**
 * Optional JSONL evidence file, separate from the events log. Unlike the events log it holds
 * arguments and results, so it is opt-in (`evidenceLog` in the config).
 */
export class EvidenceLog {
  private readonly path: string | undefined;

  /** Without a path every write is a no-op. An unwritable path throws here, not on the first write. */
  constructor(path: string | undefined) {
    this.path = path;
    if (path !== undefined) {
      appendFileSync(path, "");
    }
  }

  /** Appends one line. A failed write is dropped so tool calls never fail on logging. */
  write(r: EvidenceRecord): void {
    if (this.path === undefined) {
      return;
    }
    try {
      appendFileSync(this.path, JSON.stringify(r) + "\n");
    } catch {
      // logging is best effort
    }
  }
}
