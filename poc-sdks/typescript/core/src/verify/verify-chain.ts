// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { checkCommitments, checkRoute, checkStamps, currentAt, readOrUndefined, reject } from "../internal/chain-checks.ts";
import type { JsonValue } from "../encoding/json.ts";
import type { NonceCache } from "./nonce.ts";
import type { VerifyResult } from "./reason.ts";
import { isNotAfter } from "../policy/validity.ts";

export const CALL_MAX_AGE_MS = 5000;
export const RUN_MAX_AGE_MS = 1_800_000;
/**
 * The least time a nonce cache remembers a key, whatever the call window; the verifier also refuses a cache that
 * remembers keys for less than twice the window.
 */
export const NONCE_TTL_MS = 15_000;

/** The authenticated transport peer, supplied by the transport extension (e.g. from mTLS): its service name and its address. */
export type Peer = { svc: string; inst: string };

/**
 * What a verifier is handed for one chain: `chain`, `influence` and `proof` are the tokens received, each read only by
 * the verifier.
 */
export type VerifyInput = {
  /** The chain's token. */
  chain: string;
  expectedBind: string;
  /** The influence list's token. */
  influence: string;
  /** The route proof's token; null when none was received. */
  proof: string | null;
  /** Who received the chain: the last stamp's rcv must name it. */
  receiver: string;
  /** Whether the route ends at the receiver: true for a call, false for a response, whose receiver is off the sender's route. */
  receiverInRoute: boolean;
  /** The sender the transport authenticated; omitted or null, no peer is checked. */
  peer?: Peer | null;
};

/**
 * A keyring the verifier pins: service name to public key, verified against its policy key, and its `notAfter` (ms,
 * inclusive). It is used only while current; offline, `Infinity` is no window, for a record kind that judges the
 * keyring's window itself.
 */
export type PinnedKeyring = { keys: Readonly<Record<string, string>>; notAfter: number };

/** A signed root the verifier pins: its bytes, its `rootId` and its `notAfter`, as for a pinned keyring. */
export type PinnedRoot = { root: Uint8Array; rootId: string; notAfter: number };

export type VerifierConfig = {
  /** One or more keyrings; only those current at `now` are used. */
  keyrings: readonly PinnedKeyring[];
  /** One or more roots; only those current at `now` are used. */
  roots: readonly PinnedRoot[];
  allowedOrigins: readonly string[];
  sess: string;
  nonces: NonceCache;
  nonceKey: string;
  now: number;
  /**
   * The earlier of the latest keyring notAfter and the latest root notAfter (ms, inclusive; `pinnedNotAfter`), past
   * which nothing verifies; none, or anything but an integer in [0, 2^53 − 1], fails closed.
   */
  policyNotAfter: number | undefined;
  callMaxAgeMs?: number;
  runMaxAgeMs?: number;
};

/** The attribution rule, in one place: with a peer, every result of checks 1 to 12 names it; without one, the chain's own rule stands. */
function blame<R extends VerifyResult>(result: R, peer: Peer | null | undefined): R {
  return peer == null ? result : { ...result, suspectSvc: peer.svc, suspectInst: peer.inst };
}

/** Check 0: the window is an integer in [0, 2^53 − 1] and a finite `now` has not passed it; a non-finite `now` is left to check 7, which fails it as EXPIRED. */
function policyCurrent(cfg: VerifierConfig): boolean {
  return isNotAfter(cfg.policyNotAfter) && !(Number.isFinite(cfg.now) && cfg.now > cfg.policyNotAfter);
}

/** Check 0's refusal: about the verifier's own config, not the request, so it names no suspect, not even a peer; expiry is not the sender's fault. */
const POLICY_EXPIRED: VerifyResult = { ok: false, reason: "POLICY_EXPIRED", suspectSvc: "", suspectInst: "" };

/**
 * A VerifyInput with what the reader gave for each token: its value, or undefined for one that does not read and for no
 * proof.
 */
export type VerifyRead = Omit<VerifyInput, "chain" | "influence" | "proof"> & {
  chain: JsonValue | undefined;
  influence: JsonValue | undefined;
  proof: JsonValue | undefined;
};

/** Checks 1 to 12 in order; the result before attribution. */
function check(input: VerifyRead, cfg: VerifierConfig): VerifyResult {
  // The keyrings and roots current at now, once; a non-finite now expires none, and check 7 refuses it.
  const keyrings = currentAt(cfg.keyrings, cfg.now);
  const roots = currentAt(cfg.roots, cfg.now);

  // 1-6. Parse, delimiter, origin, signatures and links then the receivers, shared rid, session.
  const stamps = checkStamps(input.chain, { ...cfg, keyrings }, { receiver: input.receiver });
  if (typeof stamps === "string") {
    return reject(stamps);
  }
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

  // 11. Route proven against a current root, ending at the receiver only when it is on the route.
  const routed = checkRoute(stamps, input.receiverInRoute, input.proof, roots);
  if (!routed.ok) {
    return routed;
  }

  // 12. The transport peer is the last signer.
  if (input.peer != null && input.peer.svc !== last.svc) {
    return reject("PEER_MISMATCH");
  }
  return routed;
}

/**
 * Verifies a v3 chain received live. The first failure is the result:
 * 0. now is at most `cfg.policyNotAfter` (POLICY_EXPIRED), before any token is read: past it no keyring, or no
 *    root, says any longer what the policy owner allows, so no later check means anything; it names no one, peer
 *    included. The checks after it use only the keyrings and roots current at now (now ≤ their notAfter);
 * 1. the chain's token reads, as stamps all v3 (CHAIN_MISSING);
 * 2. no field holds the `|` delimiter, rcv included (BAD_SIGNATURE);
 * 3. the origin's service is allowed (BAD_ORIGIN);
 * 4. each stamp is signed under one of the keys the current keyrings give its service, and links to the one
 *    before, over the whole chain (BAD_SIGNATURE, BROKEN_LINK); then each stamp's rcv addresses the next stamp's svc,
 *    naming it or an operation of it, and the last's is `input.receiver` (BINDING_MISMATCH);
 * 5. every stamp carries the origin's rid (RID_MISMATCH);
 * 6. every stamp is in the session (SESSION_UNKNOWN);
 * 7. the last stamp is within the call window of now, and the origin within the run's lifetime (EXPIRED);
 * 8. the last stamp binds `expectedBind` (BINDING_MISMATCH);
 * 9. and commits to the influence its token holds (INFLUENCE_MISMATCH);
 * 10. its nonce key is new to the cache (REPLAY);
 * 11. the route, the first service then each rcv (the last only when `receiverInRoute`), is proven by the
 *     proof its token holds against a current root with the proof's rootId (PATH_NOT_ALLOWED);
 * 12. with a peer, `peer.svc` is the last stamp's svc (PEER_MISMATCH).
 * With a peer, every result of checks 1 to 12 names it as the suspect; without one, only OK and PATH_NOT_ALLOWED name the last stamp.
 */
export function verifyChain(input: VerifyInput, cfg: VerifierConfig): VerifyResult {
  if (!policyCurrent(cfg)) return { ...POLICY_EXPIRED };
  return verifyChainRead(
    {
      ...input,
      chain: readOrUndefined(input.chain),
      influence: readOrUndefined(input.influence),
      proof: readOrUndefined(input.proof),
    },
    cfg,
  );
}

/**
 * verifyChain on what the reader gave for each token, for a caller that has read them already. Internal: index.ts
 * does not export it.
 */
export function verifyChainRead(input: VerifyRead, cfg: VerifierConfig): VerifyResult {
  if (!policyCurrent(cfg)) return { ...POLICY_EXPIRED };
  return blame(check(input, cfg), input.peer);
}
