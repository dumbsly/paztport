// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { appendFileSync } from "node:fs";
import { rulesHash, rulesRoute, writeToken } from "@paztport/core";
import { CLIENT_CHAIN, type ClientMaterial } from "./keys.ts";

/**
 * Everything a third party needs to re-verify a run offline: public keys, signed roots, chains,
 * attestations, and the tool arguments and results. Never a private key. The model never sees it.
 * Every Paztport object in a record is its token, as it was sent or received.
 */
export type EvidenceRecord =
  | { v: 1; type: "run"; rid: string; ts: number; prompt: string }
  /** One handshake exchange: the request's token, and the result's `reply` when it is a string, else null. */
  | { v: 1; type: "session"; server: string; request: string; reply: string | null; pin: string | null; status: "attested" | "unsafe"; reason?: string }
  /** `_meta` as sent: the chain, proof and influence tokens, and `paztport/callId`. */
  | { v: 1; type: "call"; server: string; tool: string; callId: string; rid: string; now: number; params: { name: string; arguments: Record<string, unknown>; _meta: Record<string, string> } }
  /** `result` as received; its `_meta` holds the attestation or verdict token. */
  | { v: 1; type: "response"; server: string; tool: string; callId: string; rid: string; now: number; result: unknown }
  /**
   * The client mesh as the session loaded it: written once per session_start in enforce mode, before any local
   * record. `keyring` is the signed keyring's token (its services, policy key, window and signature), `root` the
   * signed root's, `rules` the local rules' and `rulesProof` that of the proof for session/pi/rules:<rulesHash(rules)>;
   * both are null when there are no rules.
   */
  | { v: 1; type: "client"; keyring: string; root: string; rules: string | null; rulesProof: string | null }
  /**
   * One gated built-in tool call: what the gate saw (input, influence) and decided, signed as a client-mesh step
   * chained from the run's origin. `decision` is the token of { callId, resolved, verdict, routeAllowed, rulesHash },
   * which the step stamp's bind covers with the input (bindLocalTool), so the decision is signed; `rulesHash` is
   * rulesHash(rules) of the session's rules, null with none. `chain`, `proof` and `influence` are tokens; `proof` is
   * null when the route is not listed. `input` stays a value: it is the content the binding hashes.
   */
  | {
      v: 1;
      type: "local";
      tool: string;
      callId: string;
      rid: string;
      now: number;
      input: Record<string, unknown>;
      decision: string;
      chain: string;
      proof: string | null;
      influence: string;
    };

export type ClientRecord = Extract<EvidenceRecord, { type: "client" }>;

/** The client record for a session's material, as the extension writes it at session_start in enforce mode. */
export function clientRecord(material: ClientMaterial): ClientRecord {
  const rules = material.rules ?? null;
  const route = rules !== null ? rulesRoute(CLIENT_CHAIN, rulesHash(rules)) : undefined;
  const rulesProof = route !== undefined && Object.hasOwn(material.proofs, route) ? material.proofs[route]! : null;
  return {
    v: 1,
    type: "client",
    keyring: writeToken({
      notAfter: material.keyringNotAfter,
      policy: material.policyPublicKey,
      services: material.keyring,
      sig: material.keyringSig,
    }),
    root: writeToken(material.signedRoot),
    rules: rules === null ? null : writeToken(rules),
    rulesProof: rulesProof === null ? null : writeToken(rulesProof),
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
