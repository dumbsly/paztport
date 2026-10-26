// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync } from "node:fs";
import { RULES_ROUTE_PREFIX, rulesHash, type InfluenceEntry, type LocalRules, type MerkleProof, type SessionRequest, type SignedRoot, type StampV2 } from "@paztport/core";
import type { ClientMaterial } from "./keys.ts";
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
   * The step stamp's bind is bindLocalTool(tool, input, { callId, resolved, verdict, routeAllowed, rulesHash }),
   * so the decision is signed; `rulesHash` is rulesHash(rules) of the session's rules, null with none.
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
      routeAllowed: boolean;
      rulesHash: string | null;
      chain: [StampV2, StampV2];
      proof: MerkleProof | null;
      influence: InfluenceEntry[];
      verdict: LocalVerdict;
    };

export type ClientRecord = Extract<EvidenceRecord, { type: "client" }>;

/** The client record for a session's material, as the extension writes it at session_start in enforce mode. */
export function clientRecord(material: ClientMaterial): ClientRecord {
  const rules = material.rules ?? null;
  const route = rules !== null ? `session/pi/${RULES_ROUTE_PREFIX}${rulesHash(rules)}` : undefined;
  return {
    v: 1,
    type: "client",
    keyring: material.keyring,
    policyPublicKey: material.policyPublicKey,
    signedRoot: material.signedRoot,
    rules,
    rulesProof: route !== undefined && Object.hasOwn(material.proofs, route) ? material.proofs[route]! : null,
  };
}

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
