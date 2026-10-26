// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { decode } from "./b64url.ts";
import { verify } from "./crypto.ts";
import { commitInfluence, parseInfluence, type InfluenceEntry } from "./influence.ts";
import { parseProof, verifyProof } from "./merkle.ts";
import type { NonceCache } from "./nonce.ts";
import type { ReasonCode, VerifyResult } from "./reason.ts";
import { parseStampsV2, signingBytesV2, type StampV2 } from "./stamp.ts";

export const CALL_MAX_AGE_MS = 5000;
export const RUN_MAX_AGE_MS = 1_800_000;
/** Nonce caches must remember keys for at least twice the call freshness window. */
export const NONCE_TTL_MS = 15_000;

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

function reject(reason: ReasonCode, suspectSvc = "", suspectInst = ""): VerifyResult {
  return { ok: false, reason, suspectSvc, suspectInst };
}

function signatureValid(publicKey: string, s: StampV2): boolean {
  try {
    return verify(publicKey, signingBytesV2(s), decode(s.sig));
  } catch {
    return false;
  }
}

function pathAllowed(proofValue: unknown, route: string, cfg: V2Config): boolean {
  try {
    const proof = parseProof(proofValue);
    return proof.rootId === cfg.rootId && verifyProof(proof, route, cfg.root);
  } catch {
    return false;
  }
}

export function verifyChainV2(input: V2Input, cfg: V2Config): VerifyResult {
  // 1. Parse.
  let stamps: StampV2[];
  try {
    stamps = parseStampsV2(input.stamps);
  } catch {
    return reject("CHAIN_MISSING");
  }

  const first = stamps[0]!;
  const last = stamps[stamps.length - 1]!;
  // Only PATH_NOT_ALLOWED names a suspect: by then the signatures, links, freshness, binding and
  // replay checks held, so the last hop's service really sent this request (its inst is that service's
  // own claim). Earlier failures may carry an unsigned name or another service's genuine stamp from a
  // replayed or altered capture.
  const fail = (reason: ReasonCode) => reject(reason);

  // 2. No delimiter in any field.
  if (stamps.some((s) => [s.svc, s.inst, s.rid, s.sess, s.bind, s.infl, s.prev].some((f) => f.includes("|")))) {
    return fail("BAD_SIGNATURE");
  }

  // 3. Origin.
  if (!cfg.allowedOrigins.includes(first.svc)) {
    return fail("BAD_ORIGIN");
  }

  // 4. Signatures and links.
  for (let i = 0; i < stamps.length; i++) {
    const s = stamps[i]!;
    const key = Object.hasOwn(cfg.keyring, s.svc) ? cfg.keyring[s.svc] : undefined;
    if (key === undefined || !signatureValid(key, s)) {
      return fail("BAD_SIGNATURE");
    }
    if (s.prev !== (i === 0 ? "" : stamps[i - 1]!.sig)) {
      return fail("BROKEN_LINK");
    }
  }

  // 5. Shared rid.
  if (stamps.some((s) => s.rid !== first.rid)) {
    return fail("RID_MISMATCH");
  }

  // 6. Session.
  if (stamps.some((s) => s.sess !== cfg.sess)) {
    return fail("SESSION_UNKNOWN");
  }

  // 7. Freshness: the call stamp is recent; the run (origin) is not too old nor from the future.
  const callMax = cfg.callMaxAgeMs ?? CALL_MAX_AGE_MS;
  const runMax = cfg.runMaxAgeMs ?? RUN_MAX_AGE_MS;
  if (![cfg.now, callMax, runMax].every(Number.isFinite)) {
    return fail("EXPIRED");
  }
  if (Math.abs(cfg.now - last.ts) > callMax || cfg.now - first.ts > runMax || first.ts - cfg.now > callMax) {
    return fail("EXPIRED");
  }

  // 8. Binding.
  if (last.bind !== input.expectedBind) {
    return fail("BINDING_MISMATCH");
  }

  // 9. Influence commitment.
  let committed: string;
  try {
    committed = commitInfluence(parseInfluence(input.influence));
  } catch {
    return fail("INFLUENCE_MISMATCH");
  }
  if (last.infl !== committed) {
    return fail("INFLUENCE_MISMATCH");
  }

  // 10. Replay. A cache that forgets sooner than 2x the call window fails closed, before spending the nonce.
  if (!(cfg.nonces.ttlMs >= 2 * callMax) || cfg.nonces.seenBefore(cfg.nonceKey, cfg.now)) {
    return fail("REPLAY");
  }

  // 11. Route proven against the root.
  const route = stamps.map((s) => s.svc).join("/") + (input.receiver !== undefined ? "/" + input.receiver : "");
  if (!pathAllowed(input.proof, route, cfg)) {
    return reject("PATH_NOT_ALLOWED", last.svc, last.inst);
  }

  return { ok: true, reason: "OK", suspectSvc: last.svc, suspectInst: last.inst };
}
