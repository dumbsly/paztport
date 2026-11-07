// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The checks the live and the offline chain verifiers share, each written once. Internal: index.ts does not
// export this module.

import { decode } from "../encoding/b64url.ts";
import { verify } from "../crypto/crypto.ts";
import { readToken, type JsonValue } from "../encoding/json.ts";
import { commitInfluence, influenceOf } from "../influence/influence.ts";
import { parseProof, provesPath } from "../policy/merkle.ts";
import { isNotAfter } from "../policy/validity.ts";
import type { ReasonCode, VerifyResult } from "../verify/reason.ts";
import type { PinnedKeyring, PinnedRoot } from "../verify/verify-chain.ts";
import { addressedTo, routeOf } from "../policy/routes.ts";
import { chainOf, signingBytes, type Stamp } from "../stamp/stamp.ts";

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

/**
 * What the reader gives for a token: its value, or undefined for no token (null) and for one that does not read.
 * Each check then refuses undefined as its own: CHAIN_MISSING, INFLUENCE_MISMATCH, or not proven.
 */
export function readOrUndefined(token: string | null): JsonValue | undefined {
  try {
    return token === null ? undefined : readToken(token);
  } catch {
    return undefined;
  }
}

/**
 * The pinned keyrings or roots current at `at`: those whose `notAfter` is at or after it, `Infinity` being no window.
 * With no finite `at` (a non-finite clock live, no recorded time offline) every member counts, and the time check
 * refuses the chain; a member with a malformed window never counts.
 */
export function currentAt<T extends { notAfter: number }>(members: readonly T[], at: number | undefined): T[] {
  const holds = (n: number) => (n === Infinity || isNotAfter(n)) && (at === undefined || !Number.isFinite(at) || at <= n);
  return Array.isArray(members) ? members.filter((m) => m != null && holds(m.notAfter)) : [];
}

/**
 * The keys the keyrings give `svc`, by own name only, each distinct key once. A member, or a member's `keys`, that
 * is not an object gives none, as `currentAt` counts no member that is not one.
 */
function keysFor(keyrings: readonly PinnedKeyring[], svc: string): string[] {
  const keys = new Set<string>();
  for (const member of keyrings) {
    const ring: Readonly<Record<string, string>> | undefined = member?.keys;
    if (typeof ring !== "object" || ring === null) continue;
    const key = Object.hasOwn(ring, svc) ? ring[svc] : undefined;
    if (typeof key === "string") keys.add(key);
  }
  return [...keys];
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
function signedFields(s: Stamp): string[] {
  return [s.svc, s.inst, s.rid, s.sess, s.rcv, s.bind, s.infl, s.prev];
}

function signatureValid(publicKey: string, s: Stamp): boolean {
  try {
    return verify(publicKey, signingBytes(s), decode(s.sig));
  } catch {
    return false;
  }
}

/**
 * Checks 1 to 6: the chain was read and its stamps are all v3 by the stamp's schema (CHAIN_MISSING), no field holds the
 * delimiter, rcv included (BAD_SIGNATURE), the origin is allowed (BAD_ORIGIN), each stamp is signed under one of the
 * keys `cfg.keyrings` give its service, each distinct key tried once, and links to the one before (BAD_SIGNATURE,
 * BROKEN_LINK), then each stamp's rcv addresses the next stamp's service and the last's names `receiver`
 * (BINDING_MISMATCH), every stamp carries the rid (RID_MISMATCH), and the session (SESSION_UNKNOWN). With `signers`, a
 * stamp from another service or instance than expected is not one the expected key signed: BAD_ORIGIN for the origin,
 * BAD_SIGNATURE for any other. Returns the stamps, or the first failure.
 */
export function checkStamps(
  value: JsonValue | undefined,
  cfg: { keyrings: readonly PinnedKeyring[]; allowedOrigins: readonly string[]; sess: string },
  shape: StampShape,
): Stamp[] | ReasonCode {
  const { rid, signers } = shape;
  // 1. The chain, by its schema.
  if (value === undefined) {
    return "CHAIN_MISSING";
  }
  let stamps: Stamp[];
  try {
    stamps = chainOf(value);
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
    const signed = keysFor(cfg.keyrings, s.svc).some((key) => signatureValid(key, s));
    if (!signed || (signers !== undefined && (s.svc !== signers.svcs[i] || s.inst !== signers.inst))) {
      return "BAD_SIGNATURE";
    }
    if (s.prev !== (i === 0 ? "" : stamps[i - 1]!.sig)) {
      return "BROKEN_LINK";
    }
  }
  // Then the receivers: each stamp addresses the next hop's service, naming an operation of it or none, and the
  // last names the chain's receiver exactly.
  const misaddressed = stamps.some((s, i) =>
    i + 1 < stamps.length ? !addressedTo(s.rcv, stamps[i + 1]!.svc) : s.rcv !== shape.receiver,
  );
  if (misaddressed) {
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

/**
 * Checks 8 and 9: the last stamp binds what was expected (BINDING_MISMATCH) and commits to the influence read
 * (INFLUENCE_MISMATCH).
 */
export function checkCommitments(
  last: Stamp,
  expectedBind: string,
  influence: JsonValue | undefined,
): ReasonCode | undefined {
  // 8. Binding.
  if (last.bind !== expectedBind) {
    return "BINDING_MISMATCH";
  }

  // 9. Influence commitment.
  if (influence === undefined) {
    return "INFLUENCE_MISMATCH";
  }
  let committed: string;
  try {
    committed = commitInfluence(influenceOf(influence));
  } catch {
    return "INFLUENCE_MISMATCH";
  }
  if (last.infl !== committed) {
    return "INFLUENCE_MISMATCH";
  }
  return undefined;
}

/**
 * The route a chain took: the first stamp's service, then each stamp's rcv, so a hop that names an operation carries
 * it into the route. The last rcv is the receiver's, and is left off when the receiver is not on the route.
 */
export function routeFromRcv(stamps: readonly Stamp[], receiverInRoute: boolean): string {
  const rcvs = stamps.map((s) => s.rcv);
  return routeOf([stamps[0]!.svc, ...(receiverInRoute ? rcvs : rcvs.slice(0, -1))]);
}

/**
 * Check 11 and the result: the route from the chain's rcvs, ending at the receiver when `receiverInRoute`, proven by
 * the proof read against one of `roots` with the proof's rootId (PATH_NOT_ALLOWED); none, or one its schema refuses,
 * proves nothing.
 */
export function checkRoute(
  stamps: Stamp[],
  receiverInRoute: boolean,
  proof: JsonValue | undefined,
  roots: readonly PinnedRoot[],
): VerifyResult {
  const last = stamps[stamps.length - 1]!;
  // 11. Route proven against a root the proof names.
  const route = routeFromRcv(stamps, receiverInRoute);
  if (!proven(proof, route, roots)) {
    return { ok: false, reason: "PATH_NOT_ALLOWED", suspectSvc: last.svc, suspectInst: last.inst };
  }
  return { ok: true, reason: "OK", suspectSvc: last.svc, suspectInst: last.inst };
}

/**
 * Whether the proof read is, by its schema, a proof of `route` for one of `roots`: provesPath takes only a root with
 * the proof's rootId, so those are the ones tried, a root and its renewals sharing one.
 */
function proven(proof: JsonValue | undefined, route: string, roots: readonly PinnedRoot[]): boolean {
  if (proof === undefined) return false;
  try {
    const p = parseProof(proof);
    return roots.some((r) => provesPath(p, route, r.root, r.rootId));
  } catch {
    return false;
  }
}
