// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The checks the live and the offline chain verifiers share, each written once. Internal: index.ts does not
// export this module.

import { decode } from "../encoding/b64url.ts";
import { verify } from "../crypto/crypto.ts";
import { commitInfluence, parseInfluence, type InfluenceEntry } from "../influence/influence.ts";
import { provesPath } from "../policy/merkle.ts";
import type { ReasonCode, VerifyResult } from "../verify/reason.ts";
import { routeOf } from "../policy/routes.ts";
import { parseStampsV3, signingBytesV3, type StampV3 } from "../stamp/stamp.ts";

/**
 * Only OK and PATH_NOT_ALLOWED name a suspect: by then the signatures, links, times, binding and replay
 * checks held, so the last hop's service really sent this request (its inst is that service's own claim).
 * Earlier failures may carry an unsigned name or another service's genuine stamp from a replayed or altered
 * capture. Receiver failures name no suspect either: a chain forwarded unchanged was genuinely signed for
 * someone else, so its last signer did not send it here.
 */
export function reject(reason: ReasonCode): VerifyResult {
  return { ok: false, reason, suspectSvc: "", suspectInst: "" };
}

/** The services that sign a chain that never leaves one process, in order, and the instance they all report. */
export type Signers = { svcs: readonly string[]; inst: string };

/**
 * What a verifier takes besides the config. `receiver` is what the last stamp's rcv must name; `rid` the one
 * every stamp must carry, the origin's by default; `signers` the services and instance a one-process chain must
 * come from.
 */
export type StampShape = { receiver?: string; rid?: string; signers?: Signers };

/** A stamp's signed string fields. */
function signedFields(s: StampV3): string[] {
  return [s.svc, s.inst, s.rid, s.sess, s.rcv, s.bind, s.infl, s.prev];
}

function signatureValid(publicKey: string, s: StampV3): boolean {
  try {
    return verify(publicKey, signingBytesV3(s), decode(s.sig));
  } catch {
    return false;
  }
}

/**
 * Checks 1 to 6: the stamps parse, all v3 (CHAIN_MISSING), no field holds the delimiter, rcv included
 * (BAD_SIGNATURE), the origin is allowed (BAD_ORIGIN), each stamp is signed by its service's key and links to
 * the one before (BAD_SIGNATURE, BROKEN_LINK), then each stamp's rcv names the next stamp's service and the
 * last's names `receiver` (BINDING_MISMATCH), every stamp carries the rid (RID_MISMATCH), and the session
 * (SESSION_UNKNOWN). With `signers`, a stamp from another service or instance than expected is not one the
 * expected key signed: BAD_ORIGIN for the origin, BAD_SIGNATURE for any other. Returns the stamps, or the first
 * failure.
 */
export function checkStamps(
  value: unknown,
  cfg: { keyring: Record<string, string>; allowedOrigins: readonly string[]; sess: string },
  shape: StampShape,
): StampV3[] | ReasonCode {
  const { rid, signers } = shape;
  // 1. Parse.
  let stamps: StampV3[];
  try {
    stamps = parseStampsV3(value);
  } catch {
    return "CHAIN_MISSING";
  }
  const first = stamps[0]!;

  // 2. No delimiter in any field.
  if (stamps.some((s) => signedFields(s).some((f) => f.includes("|")))) {
    return "BAD_SIGNATURE";
  }

  // 3. Origin.
  if (!cfg.allowedOrigins.includes(first.svc) || (signers !== undefined && first.inst !== signers.inst)) {
    return "BAD_ORIGIN";
  }

  // 4. Signatures and links.
  for (let i = 0; i < stamps.length; i++) {
    const s = stamps[i]!;
    const key = Object.hasOwn(cfg.keyring, s.svc) ? cfg.keyring[s.svc] : undefined;
    if (key === undefined || !signatureValid(key, s) || (signers !== undefined && (s.svc !== signers.svcs[i] || s.inst !== signers.inst))) {
      return "BAD_SIGNATURE";
    }
    if (s.prev !== (i === 0 ? "" : stamps[i - 1]!.sig)) {
      return "BROKEN_LINK";
    }
  }
  // Then the receivers: each stamp names the next hop, and the last the chain's receiver.
  if (stamps.some((s, i) => s.rcv !== (i + 1 < stamps.length ? stamps[i + 1]!.svc : shape.receiver))) {
    return "BINDING_MISMATCH";
  }

  // 5. Shared rid.
  const want = rid ?? first.rid;
  if (stamps.some((s) => s.rid !== want)) {
    return "RID_MISMATCH";
  }

  // 6. Session.
  if (stamps.some((s) => s.sess !== cfg.sess)) {
    return "SESSION_UNKNOWN";
  }
  return stamps;
}

/** Checks 8 and 9: the last stamp binds what was expected (BINDING_MISMATCH) and commits to the influence (INFLUENCE_MISMATCH). */
export function checkCommitments(last: StampV3, expectedBind: string, influence: InfluenceEntry[]): ReasonCode | undefined {
  // 8. Binding.
  if (last.bind !== expectedBind) {
    return "BINDING_MISMATCH";
  }

  // 9. Influence commitment.
  let committed: string;
  try {
    committed = commitInfluence(parseInfluence(influence));
  } catch {
    return "INFLUENCE_MISMATCH";
  }
  if (last.infl !== committed) {
    return "INFLUENCE_MISMATCH";
  }
  return undefined;
}

/** Check 11 and the result: the chain's services, then the receiver when given, proven against the root (PATH_NOT_ALLOWED). */
export function checkRoute(stamps: StampV3[], receiver: string | undefined, proof: unknown, cfg: { root: Uint8Array; rootId: string }): VerifyResult {
  const last = stamps[stamps.length - 1]!;
  // 11. Route proven against the root.
  const svcs = stamps.map((s) => s.svc);
  const route = routeOf(receiver !== undefined ? [...svcs, receiver] : svcs);
  if (!provesPath(proof, route, cfg.root, cfg.rootId)) {
    return { ok: false, reason: "PATH_NOT_ALLOWED", suspectSvc: last.svc, suspectInst: last.inst };
  }
  return { ok: true, reason: "OK", suspectSvc: last.svc, suspectInst: last.inst };
}
