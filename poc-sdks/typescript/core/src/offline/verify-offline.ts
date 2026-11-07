// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { isWellFormed } from "../crypto/crypto.ts";
import { bindPrompt } from "../stamp/binding.ts";
import {
  checkCommitments, checkRoute, checkStamps, currentAt, readOrUndefined, reject, type Signers,
} from "../internal/chain-checks.ts";
import type { VerifyResult } from "../verify/reason.ts";
import { CALL_MAX_AGE_MS, RUN_MAX_AGE_MS, type VerifierConfig, type VerifyInput } from "../verify/verify-chain.ts";

export type { Signers };

/** The times a record set gives for a chain. */
export type RecordedTimes = {
  /** When the chain's last hop made it, as recorded beside it: the last stamp's ts must be this. */
  last: number;
  /**
   * The start times the run's records give, when it has any: the origin's ts must be one of them. Anything else
   * here but a Set is TIME_MISMATCH.
   */
  run?: ReadonlySet<number>;
};

export type OfflineInput = Omit<VerifyInput, "peer"> & {
  /** The rid the record files the chain under: every stamp must carry it. Defaults to the origin's. */
  rid?: string;
  /** The times the record gives. A record with none (absent at run time) fails check 7 with TIME_MISMATCH. */
  recordedTs: RecordedTimes;
  /** The run's recorded prompt, which the origin must bind; undefined when the run has none or it is in dispute. */
  prompt?: string;
};

/**
 * The keyrings and roots count for a record when its recorded time is at most their `notAfter`; a member whose
 * window its record kind judges itself has `notAfter: Infinity`, no window, and counts for every record.
 */
export type OfflineConfig = Pick<
  VerifierConfig, "keyrings" | "roots" | "allowedOrigins" | "sess" | "nonceKey"
> & {
  /** Every nonce key spent so far anywhere in the record set. A chain that reaches the replay check adds its own. */
  seen: Set<string>;
  /** For a chain that never leaves one process, such as a client's local steps: who signs it and from which instance. */
  signers?: Signers;
  /**
   * The live window's limits that need no clock: the last stamp is at most `runMaxAgeMs` after the origin, and the
   * origin at most `callMaxAgeMs` after the last stamp. Each one not configured is its live default
   * (`RUN_MAX_AGE_MS`, `CALL_MAX_AGE_MS`), so a chain's age is never unlimited; one that is not finite is EXPIRED.
   */
  runMaxAgeMs?: number;
  callMaxAgeMs?: number;
};

/** An offline verdict, with the suspect as in `VerifyResult`. */
export type OfflineResult = VerifyResult;

/**
 * Verifies a chain read back from a record set, such as a client's evidence file, with the live v3
 * verifier's checks in the live order. The first failure is the result:
 * 0. some keyring and some root count for the record, their notAfter at or after its recorded time
 *    (POLICY_EXPIRED, naming no one); with no recorded time every one counts, and check 7 refuses the record;
 *    the checks after it use only those that count;
 * 1. the chain's token reads, as stamps all v3 (CHAIN_MISSING);
 * 2. no field holds the `|` delimiter, rcv included (BAD_SIGNATURE);
 * 3. the origin's service is allowed (BAD_ORIGIN); with `signers`, it reports their instance too;
 * 4. each stamp is signed under one of the keys the keyrings give its service, and links to the one before
 *    (BAD_SIGNATURE, BROKEN_LINK);
 *    with `signers`, each is by the expected service and instance, or it is BAD_SIGNATURE; then each
 *    stamp's rcv addresses the next stamp's svc, naming it or an operation of it, and the last's is `receiver`
 *    (BINDING_MISMATCH);
 * 5. every stamp carries the record's rid (RID_MISMATCH);
 * 6. every stamp is in the session (SESSION_UNKNOWN);
 * 7. in place of the live freshness window, which has no clock to be fresh against offline: the last stamp's
 *    time is the one recorded with it, and the origin's is one of the run's recorded times (TIME_MISMATCH);
 *    a record with no recorded time is TIME_MISMATCH; then the last stamp is within the run's lifetime of the
 *    origin, and the origin not more than the call window after it, each limit its configured one or its live
 *    default (EXPIRED); then the origin binds the run's recorded prompt (PROMPT_MISMATCH);
 * 8. the last stamp binds `expectedBind` (BINDING_MISMATCH);
 * 9. and commits to the influence its token holds (INFLUENCE_MISMATCH);
 * 10. its nonce key has not been spent anywhere in the record set (REPLAY), which a live cache that forgets
 *     after its window cannot show;
 * 11. the route, the first service then each rcv (the last only when `receiverInRoute`), is proven by the
 *     proof its token holds against a root with the proof's rootId (PATH_NOT_ALLOWED).
 * Checks 1 to 6, 8, 9 and 11 are the live verifier's own code.
 */
export function verifyChainOffline(input: OfflineInput, cfg: OfflineConfig): OfflineResult {
  // 0. The keyrings and roots that count at the record's own time, once; none of either names no one.
  const t: RecordedTimes | undefined = input.recordedTs;
  const at = typeof t === "object" && t !== null && typeof t.last === "number" ? t.last : undefined;
  const keyrings = currentAt(cfg.keyrings, at);
  const roots = currentAt(cfg.roots, at);
  if (keyrings.length === 0 || roots.length === 0) {
    return reject("POLICY_EXPIRED");
  }

  // 1-6. Parse, delimiter, origin, signatures and links then the receivers, the record's rid, session.
  const shape = { receiver: input.receiver, rid: input.rid, signers: cfg.signers };
  const stamps = checkStamps(readOrUndefined(input.chain), { ...cfg, keyrings }, shape);
  if (typeof stamps === "string") {
    return reject(stamps);
  }
  const first = stamps[0]!;
  const last = stamps[stamps.length - 1]!;

  // 7. Recorded times, the age limits, then the prompt.
  if (typeof t !== "object" || t === null || last.ts !== t.last || !inRunTimes(t.run, first.ts)) {
    return reject("TIME_MISMATCH");
  }
  const runMax = cfg.runMaxAgeMs ?? RUN_MAX_AGE_MS;
  const callMax = cfg.callMaxAgeMs ?? CALL_MAX_AGE_MS;
  if (![runMax, callMax].every(Number.isFinite) || last.ts - first.ts > runMax || first.ts - last.ts > callMax) {
    return reject("EXPIRED");
  }
  if (input.prompt === undefined || !isWellFormed(input.prompt) || first.bind !== bindPrompt(input.prompt)) {
    return reject("PROMPT_MISMATCH");
  }

  // 8-9. Binding and influence commitment.
  const commitment = checkCommitments(last, input.expectedBind, readOrUndefined(input.influence));
  if (commitment !== undefined) {
    return reject(commitment);
  }

  // 10. Replay, across the whole record set.
  if (cfg.seen.has(cfg.nonceKey)) {
    return reject("REPLAY");
  }
  cfg.seen.add(cfg.nonceKey);

  // 11. Route proven against a root that counts for the record.
  return checkRoute(stamps, input.receiverInRoute, readOrUndefined(input.proof), roots);
}

/** Whether `ts` is one of `run`, the run's recorded start times, or `run` is absent; never when it is not a Set. */
function inRunTimes(run: unknown, ts: number): boolean {
  return run === undefined || (run instanceof Set && run.has(ts));
}
