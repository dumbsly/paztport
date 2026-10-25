// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync } from "node:fs";
import type { InfluenceEntry, LocalRules, MerkleProof, SessionRequest, SignedRoot, StampV2 } from "@paztport/path-attest";
import type { LocalVerdict, Resolved } from "./local/decide.ts";

/**
 * Everything a third party needs to re-verify a run offline: public keys, signed roots, chains,
 * attestations, and the tool arguments and results. Never a private key. The model never sees it.
 */
export type EvidenceRecord =
  | { v: 1; type: "run"; rid: string; ts: number; prompt: string }
  | { v: 1; type: "session"; server: string; request: SessionRequest; reply: unknown; pin: string | null; status: "attested" | "unsafe"; reason?: string }
  | { v: 1; type: "call"; server: string; tool: string; callId: string; rid: string; now: number; params: { name: string; arguments: Record<string, unknown>; _meta: Record<string, unknown> } }
  | { v: 1; type: "response"; server: string; tool: string; callId: string; rid: string; now: number; result: unknown }
  /** The client mesh as the session loaded it: written once per session_start in enforce mode, before any local record. */
  | {
      v: 1;
      type: "client";
      keyring: Record<string, string>;
      policyPublicKey: string;
      signedRoot: SignedRoot;
      rules: LocalRules | null;
      /** The proof for session/pi/rules:<rulesHash(rules)>; null when there are no rules. */
      rulesProof: MerkleProof | null;
    }
  /**
   * One gated built-in tool call: what the gate saw (input, resolution, influence) and decided, signed
   * as a client-mesh step chained from the run's origin. `proof` is null when the route is not listed.
   */
  | {
      v: 1;
      type: "local";
      tool: string;
      callId: string;
      rid: string;
      now: number;
      input: Record<string, unknown>;
      resolved: Resolved;
      chain: [StampV2, StampV2];
      proof: MerkleProof | null;
      influence: InfluenceEntry[];
      verdict: LocalVerdict;
    };

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
