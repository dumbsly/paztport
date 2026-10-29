// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { checkCommitments, checkRoute, checkStamps, reject, type StampShape } from "../internal/chain-checks.ts";
import type { InfluenceEntry } from "../influence/influence.ts";
import type { NonceCache } from "./nonce.ts";
import type { VerifyResult } from "./reason.ts";
import { isNotAfter } from "../policy/validity.ts";

export const CALL_MAX_AGE_MS = 5000;
export const RUN_MAX_AGE_MS = 1_800_000;
/** Nonce caches must remember keys for at least twice the call freshness window. */
export const NONCE_TTL_MS = 15_000;

/** The authenticated transport peer, supplied by the transport extension (e.g. from mTLS): its service name and its address. */
export type Peer = { svc: string; inst: string };

export type V3Input = {
  stamps: unknown;
  expectedBind: string;
  influence: InfluenceEntry[];
  proof: unknown;
  /** Who received the chain: the last stamp's rcv must name it. */
  receiver: string;
  /** Whether the route ends at the receiver: true for a call, false for a response, whose receiver is off the sender's route. */
  receiverInRoute: boolean;
  /** The sender the transport authenticated; omitted or null, no peer is checked. */
  peer?: Peer | null;
};

export type V3Config = {
  keyring: Record<string, string>;
  root: Uint8Array;
  rootId: string;
  allowedOrigins: string[];
  sess: string;
  nonces: NonceCache;
  nonceKey: string;
  now: number;
  /** The earliest notAfter of the keyring and root (ms, inclusive), past which nothing verifies; required, and undefined (old-form material, with no window) or anything but an integer in [0, 2^53 − 1] fails closed. */
  policyNotAfter: number | undefined;
  callMaxAgeMs?: number;
  runMaxAgeMs?: number;
};

type LegacyResult = VerifyResult & { legacy: boolean };

/** The attribution rule, in one place: with a peer, every result of checks 1 to 12 names it; without one, the chain's own rule stands. */
function blame<R extends VerifyResult>(result: R, peer: Peer | null | undefined): R {
  return peer == null ? result : { ...result, suspectSvc: peer.svc, suspectInst: peer.inst };
}

/** Check 0: the window is an integer in [0, 2^53 − 1] and a finite `now` has not passed it; a non-finite `now` is left to check 7, which fails it as EXPIRED. */
function policyCurrent(cfg: V3Config): boolean {
  return isNotAfter(cfg.policyNotAfter) && !(Number.isFinite(cfg.now) && cfg.now > cfg.policyNotAfter);
}

/** Check 0's refusal: about the verifier's own config, not the request, so it names no suspect, not even a peer; expiry is not the sender's fault. */
const POLICY_EXPIRED: VerifyResult = { ok: false, reason: "POLICY_EXPIRED", suspectSvc: "", suspectInst: "" };

/** Checks 1 to 12 in order, for the stamps `accept` allows; the result before attribution. */
function check(input: V3Input, cfg: V3Config, accept: StampShape["accept"]): LegacyResult {
  // 1-6. Parse, delimiter, origin, signatures and links then the receivers, shared rid, session.
  const checked = checkStamps(input.stamps, cfg, { accept, receiver: input.receiver });
  if (typeof checked === "string") {
    return { ...reject(checked), legacy: false };
  }
  const { stamps, legacy } = checked;
  const done = (result: VerifyResult): LegacyResult => ({ ...result, legacy });
  const first = stamps[0]!;
  const last = stamps[stamps.length - 1]!;

  // 7. Freshness: the call stamp is recent; the run (origin) is not too old nor from the future.
  const callMax = cfg.callMaxAgeMs ?? CALL_MAX_AGE_MS;
  const runMax = cfg.runMaxAgeMs ?? RUN_MAX_AGE_MS;
  if (![cfg.now, callMax, runMax].every(Number.isFinite)) {
    return done(reject("EXPIRED"));
  }
  if (Math.abs(cfg.now - last.ts) > callMax || cfg.now - first.ts > runMax || first.ts - cfg.now > callMax) {
    return done(reject("EXPIRED"));
  }

  // 8-9. Binding and influence commitment.
  const commitment = checkCommitments(last, input.expectedBind, input.influence);
  if (commitment !== undefined) {
    return done(reject(commitment));
  }

  // 10. Replay. A cache that forgets sooner than 2x the call window fails closed, before spending the nonce.
  if (!(cfg.nonces.ttlMs >= 2 * callMax) || cfg.nonces.seenBefore(cfg.nonceKey, cfg.now)) {
    return done(reject("REPLAY"));
  }

  // 11. Route proven against the root, ending at the receiver only when it is on the route.
  const routed = checkRoute(stamps, input.receiverInRoute ? input.receiver : undefined, input.proof, cfg);
  if (!routed.ok) {
    return done(routed);
  }

  // 12. The transport peer is the last signer.
  if (input.peer != null && input.peer.svc !== last.svc) {
    return done(reject("PEER_MISMATCH"));
  }
  return done(routed);
}

/**
 * Verifies a v3 chain received live. The first failure is the result:
 * 0. now is at most `cfg.policyNotAfter` (POLICY_EXPIRED), before any stamp work: past it the keyring and root
 *    no longer say what the policy owner allows, so no later check means anything; it names no one, peer included;
 * 1. the stamps parse, all v3 (CHAIN_MISSING);
 * 2. no field holds the `|` delimiter, rcv included (BAD_SIGNATURE);
 * 3. the origin's service is allowed (BAD_ORIGIN);
 * 4. each stamp is signed by its service's key and links to the one before, over the whole chain
 *    (BAD_SIGNATURE, BROKEN_LINK); then each stamp's rcv is the next stamp's svc, and the last's is
 *    `input.receiver` (BINDING_MISMATCH);
 * 5. every stamp carries the origin's rid (RID_MISMATCH);
 * 6. every stamp is in the session (SESSION_UNKNOWN);
 * 7. the last stamp is within the call window of now, and the origin within the run's lifetime (EXPIRED);
 * 8. the last stamp binds `expectedBind` (BINDING_MISMATCH);
 * 9. and commits to the influence (INFLUENCE_MISMATCH);
 * 10. its nonce key is new to the cache (REPLAY);
 * 11. the route, the chain's services then the receiver when `receiverInRoute`, is proven against the root
 *     (PATH_NOT_ALLOWED);
 * 12. with a peer, `peer.svc` is the last stamp's svc (PEER_MISMATCH).
 * With a peer, every result of checks 1 to 12 names it as the suspect; without one, only OK and PATH_NOT_ALLOWED name the last stamp.
 */
export function verifyChainV3(input: V3Input, cfg: V3Config): VerifyResult {
  if (!policyCurrent(cfg)) return { ...POLICY_EXPIRED };
  const { legacy: _legacy, ...result } = check(input, cfg, "v3");
  return blame(result, input.peer);
}

/**
 * verifyChainV3's checks in the same order, also taking an all-v2 chain as legacy, with no receiver checks; a
 * mixed chain is CHAIN_MISSING. For re-checking a recorded response at its recorded time.
 */
export function verifyChainAcceptingLegacy(input: V3Input, cfg: V3Config): VerifyResult & { legacy: boolean } {
  if (!policyCurrent(cfg)) return { ...POLICY_EXPIRED, legacy: false };
  return blame(check(input, cfg, "v3-or-legacy-v2"), input.peer);
}
