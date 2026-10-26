// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { bindPrompt } from "./binding.ts";
import { checkCommitments, checkRoute, checkStamps, reject, type Signers } from "./chain-checks.ts";
import type { VerifyResult } from "./reason.ts";
import type { V2Config, V2Input } from "./verify-v2.ts";

export type { Signers };

/** The times a record set gives for a chain. */
export type RecordedTimes = {
  /** When the chain's last hop made it, as recorded beside it: the last stamp's ts must be this. */
  last: number;
  /** The start times the run's records give, when it has any: the origin's ts must be one of them. */
  run?: ReadonlySet<number>;
};

export type OfflineInput = V2Input & {
  /** The rid the record files the chain under: every stamp must carry it. Defaults to the origin's. */
  rid?: string;
  /** Omitted, no time is compared. */
  recordedTs?: RecordedTimes;
  /** The run's recorded prompt, which the origin must bind; undefined when the run has none or it is in dispute. */
  prompt?: string;
};

export type OfflineConfig = Pick<V2Config, "keyring" | "root" | "rootId" | "allowedOrigins" | "sess" | "nonceKey"> & {
  /** Every nonce key spent so far anywhere in the record set. A chain that reaches the replay check adds its own. */
  seen: Set<string>;
  /** For a chain that never leaves one process, such as a client's local steps: who signs it and from which instance. */
  signers?: Signers;
};

/**
 * Verifies a chain read back from a record set, such as a client's evidence file, with the live v2
 * verifier's checks in the live order. The first failure is the result:
 * 1. the stamps parse (CHAIN_MISSING);
 * 2. no field holds the `|` delimiter (BAD_SIGNATURE);
 * 3. the origin's service is allowed (BAD_ORIGIN); with `signers`, it reports their instance too;
 * 4. each stamp is signed by its service's key and links to the one before (BAD_SIGNATURE, BROKEN_LINK);
 *    with `signers`, each is by the expected service and instance, or it is BAD_SIGNATURE;
 * 5. every stamp carries the record's rid (RID_MISMATCH);
 * 6. every stamp is in the session (SESSION_UNKNOWN);
 * 7. in place of the live freshness window, which has no clock to be fresh against offline: the last stamp's
 *    time is the one recorded with it, and the origin's is one of the run's recorded times (TIME_MISMATCH);
 *    then the origin binds the run's recorded prompt (PROMPT_MISMATCH);
 * 8. the last stamp binds `expectedBind` (BINDING_MISMATCH);
 * 9. and commits to the influence (INFLUENCE_MISMATCH);
 * 10. its nonce key has not been spent anywhere in the record set (REPLAY), which a live cache that forgets
 *     after its window cannot show;
 * 11. the route, the chain's services then the receiver, is proven against the root (PATH_NOT_ALLOWED).
 * Checks 1 to 6, 8, 9 and 11 are the live verifier's own code.
 */
export function verifyChainOffline(input: OfflineInput, cfg: OfflineConfig): VerifyResult {
  // 1-6. Parse, delimiter, origin, signatures and links, the record's rid, session.
  const stamps = checkStamps(input.stamps, cfg, input.rid, cfg.signers);
  if (typeof stamps === "string") {
    return reject(stamps);
  }
  const first = stamps[0]!;
  const last = stamps[stamps.length - 1]!;

  // 7. Recorded times, then the prompt.
  const t = input.recordedTs;
  if (t !== undefined && (last.ts !== t.last || (t.run !== undefined && !t.run.has(first.ts)))) {
    return reject("TIME_MISMATCH");
  }
  if (input.prompt === undefined || first.bind !== bindPrompt(input.prompt)) {
    return reject("PROMPT_MISMATCH");
  }

  // 8-9. Binding and influence commitment.
  const commitment = checkCommitments(last, input.expectedBind, input.influence);
  if (commitment !== undefined) {
    return reject(commitment);
  }

  // 10. Replay, across the whole record set.
  if (cfg.seen.has(cfg.nonceKey)) {
    return reject("REPLAY");
  }
  cfg.seen.add(cfg.nonceKey);

  // 11. Route proven against the root.
  return checkRoute(stamps, input.receiver, input.proof, cfg);
}
