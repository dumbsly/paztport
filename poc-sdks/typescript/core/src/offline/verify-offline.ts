// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { isWellFormed } from "../crypto/crypto.ts";
import { bindPrompt } from "../stamp/binding.ts";
import {
  checkCommitments, checkRoute, checkStamps, readOrUndefined, reject, type Signers,
} from "../internal/chain-checks.ts";
import type { VerifyResult } from "../verify/reason.ts";
import type { VerifierConfig, VerifyInput } from "../verify/verify-chain.ts";

export type { Signers };

/** The times a record set gives for a chain. */
export type RecordedTimes = {
  /** When the chain's last hop made it, as recorded beside it: the last stamp's ts must be this. */
  last: number;
  /** The start times the run's records give, when it has any: the origin's ts must be one of them. */
  run?: ReadonlySet<number>;
};

export type OfflineInput = Omit<VerifyInput, "peer"> & {
  /** The rid the record files the chain under: every stamp must carry it. Defaults to the origin's. */
  rid?: string;
  /** Omitted, no time is compared. */
  recordedTs?: RecordedTimes;
  /** The run's recorded prompt, which the origin must bind; undefined when the run has none or it is in dispute. */
  prompt?: string;
};

export type OfflineConfig = Pick<
  VerifierConfig, "keyring" | "root" | "rootId" | "allowedOrigins" | "sess" | "nonceKey"
> & {
  /** Every nonce key spent so far anywhere in the record set. A chain that reaches the replay check adds its own. */
  seen: Set<string>;
  /** For a chain that never leaves one process, such as a client's local steps: who signs it and from which instance. */
  signers?: Signers;
  /**
   * The live window's limits that need no clock, for a chain the live verifier checked at its last stamp's time
   * (a recorded call): the last stamp is at most `runMaxAgeMs` after the origin, and the origin at most
   * `callMaxAgeMs` after the last stamp. Omitted, the chain's age is not limited.
   */
  runMaxAgeMs?: number;
  callMaxAgeMs?: number;
};

/** An offline verdict, with the suspect as in `VerifyResult`. */
export type OfflineResult = VerifyResult;

/**
 * Verifies a chain read back from a record set, such as a client's evidence file, with the live v3
 * verifier's checks in the live order. The first failure is the result:
 * 1. the chain's token reads, as stamps all v3 (CHAIN_MISSING);
 * 2. no field holds the `|` delimiter, rcv included (BAD_SIGNATURE);
 * 3. the origin's service is allowed (BAD_ORIGIN); with `signers`, it reports their instance too;
 * 4. each stamp is signed by its service's key and links to the one before (BAD_SIGNATURE, BROKEN_LINK);
 *    with `signers`, each is by the expected service and instance, or it is BAD_SIGNATURE; then each
 *    stamp's rcv is the next stamp's svc and the last's is `receiver` (BINDING_MISMATCH);
 * 5. every stamp carries the record's rid (RID_MISMATCH);
 * 6. every stamp is in the session (SESSION_UNKNOWN);
 * 7. in place of the live freshness window, which has no clock to be fresh against offline: the last stamp's
 *    time is the one recorded with it, and the origin's is one of the run's recorded times (TIME_MISMATCH);
 *    with age limits, the last stamp is within the run's lifetime of the origin, and the origin not more than
 *    the call window after it (EXPIRED); then the origin binds the run's recorded prompt (PROMPT_MISMATCH);
 * 8. the last stamp binds `expectedBind` (BINDING_MISMATCH);
 * 9. and commits to the influence its token holds (INFLUENCE_MISMATCH);
 * 10. its nonce key has not been spent anywhere in the record set (REPLAY), which a live cache that forgets
 *     after its window cannot show;
 * 11. the route, the chain's services then the receiver when `receiverInRoute`, is proven against the root by the
 *     proof its token holds (PATH_NOT_ALLOWED).
 * Checks 1 to 6, 8, 9 and 11 are the live verifier's own code.
 * Omitting `recordedTs` skips the recorded-time check (TIME_MISMATCH), leaving only `cfg`'s age limits on the times.
 */
export function verifyChainOffline(input: OfflineInput, cfg: OfflineConfig): OfflineResult {
  // 1-6. Parse, delimiter, origin, signatures and links then the receivers, the record's rid, session.
  const shape = { receiver: input.receiver, rid: input.rid, signers: cfg.signers };
  const stamps = checkStamps(readOrUndefined(input.chain), cfg, shape);
  if (typeof stamps === "string") {
    return reject(stamps);
  }
  const first = stamps[0]!;
  const last = stamps[stamps.length - 1]!;

  // 7. Recorded times, the age limits, then the prompt.
  const t = input.recordedTs;
  if (t !== undefined && (last.ts !== t.last || (t.run !== undefined && !t.run.has(first.ts)))) {
    return reject("TIME_MISMATCH");
  }
  if (cfg.runMaxAgeMs !== undefined || cfg.callMaxAgeMs !== undefined) {
    const runMax = cfg.runMaxAgeMs ?? Number.NaN;
    const callMax = cfg.callMaxAgeMs ?? Number.NaN;
    if (![runMax, callMax].every(Number.isFinite) || last.ts - first.ts > runMax || first.ts - last.ts > callMax) {
      return reject("EXPIRED");
    }
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

  // 11. Route proven against the root.
  return checkRoute(stamps, input.receiverInRoute ? input.receiver : undefined, readOrUndefined(input.proof), cfg);
}
