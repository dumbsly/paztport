// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { checkCommitments, checkRoute, checkStamps, reject } from "./chain-checks.ts";
import type { InfluenceEntry } from "./influence.ts";
import type { NonceCache } from "./nonce.ts";
import type { VerifyResult } from "./reason.ts";
import { CALL_MAX_AGE_MS, RUN_MAX_AGE_MS } from "./verify-v3.ts";

export type V2Input = {
  stamps: unknown;
  expectedBind: string;
  influence: InfluenceEntry[];
  proof: unknown;
  receiver?: string;
  /** The authenticated transport peer's service name, supplied by the transport extension (e.g. from mTLS); not checked yet. */
  peer?: string;
};

export type V2Config = {
  keyring: Record<string, string>;
  root: Uint8Array;
  rootId: string;
  allowedOrigins: string[];
  sess: string;
  nonces: NonceCache;
  nonceKey: string;
  now: number;
  callMaxAgeMs?: number;
  runMaxAgeMs?: number;
};

export function verifyChainV2(input: V2Input, cfg: V2Config): VerifyResult {
  // 1-6. Parse, delimiter, origin, signatures and links, shared rid, session.
  const checked = checkStamps(input.stamps, cfg, { accept: "v2" });
  if (typeof checked === "string") {
    return reject(checked);
  }
  const { stamps } = checked;
  const first = stamps[0]!;
  const last = stamps[stamps.length - 1]!;

  // 7. Freshness: the call stamp is recent; the run (origin) is not too old nor from the future.
  const callMax = cfg.callMaxAgeMs ?? CALL_MAX_AGE_MS;
  const runMax = cfg.runMaxAgeMs ?? RUN_MAX_AGE_MS;
  if (![cfg.now, callMax, runMax].every(Number.isFinite)) {
    return reject("EXPIRED");
  }
  if (Math.abs(cfg.now - last.ts) > callMax || cfg.now - first.ts > runMax || first.ts - cfg.now > callMax) {
    return reject("EXPIRED");
  }

  // 8-9. Binding and influence commitment.
  const commitment = checkCommitments(last, input.expectedBind, input.influence);
  if (commitment !== undefined) {
    return reject(commitment);
  }

  // 10. Replay. A cache that forgets sooner than 2x the call window fails closed, before spending the nonce.
  if (!(cfg.nonces.ttlMs >= 2 * callMax) || cfg.nonces.seenBefore(cfg.nonceKey, cfg.now)) {
    return reject("REPLAY");
  }

  // 11. Route proven against the root.
  return checkRoute(stamps, input.receiver, input.proof, cfg);
}
