// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The checks the live and the offline chain verifiers share, each written once. Internal: index.ts does not
// export this module.

import { decode } from "../encoding/b64url.ts";
import { verify } from "../crypto/crypto.ts";
import { readToken, type JsonValue } from "../encoding/json.ts";
import { parseProof, provesPath } from "../policy/merkle.ts";
import { isNotAfter } from "../policy/validity.ts";
import type { ExtensionSettings, HandOver, StampItems } from "../verify/extensions.ts";
import type { ReasonCode, VerifyResult } from "../verify/reason.ts";
import type { ChainVerification, PinnedKeyring, PinnedRoot } from "../verify/verify-chain.ts";
import { addressedTo, routeOf } from "../policy/routes.ts";
import { blocksOf, commitBlock, EMPTY_BLOCK, itemsUnder, type Block } from "../stamp/block.ts";
import { chainOf, signingBytes, type Stamp } from "../stamp/stamp.ts";

/**
 * Only OK and PATH_NOT_ALLOWED name a suspect: by then the signatures, links, receivers, times, binding, blocks and
 * replay checks held, so the last hop's service really sent this request (its inst is that service's own claim).
 * Earlier failures may carry an unsigned name or another service's genuine stamp from a replayed or altered
 * capture. Receiver failures name no suspect either: a chain forwarded unchanged was genuinely signed for
 * someone else, so its last signer did not send it here. A refusal hands nothing over.
 */
export function reject(reason: ReasonCode): ChainVerification {
  return { ok: false, reason, suspectSvc: "", suspectInst: "", handOver: null };
}

/**
 * What the reader gives for a token: its value, or undefined for no token (null) and for one that does not read.
 * Each check then refuses undefined as its own: CHAIN_MISSING, or not proven.
 */
export function readOrUndefined(token: string | null): JsonValue | undefined {
  try {
    return token === null ? undefined : readToken(token);
  } catch {
    return undefined;
  }
}

/**
 * What the reader gives for a blocks token: null for no token (null), which is one empty block per stamp; undefined
 * for one that does not read, and for one that reads as JSON `null`, which is no array of blocks; else its value.
 * Check 9a refuses undefined.
 */
export function readBlocksToken(token: string | null): JsonValue | undefined | null {
  if (token === null) return null;
  const value = readOrUndefined(token);
  return value === null ? undefined : value;
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

function signatureValid(publicKey: string, s: Stamp): boolean {
  try {
    return verify(publicKey, signingBytes(s), decode(s.sig));
  } catch {
    return false;
  }
}

/**
 * Checks 1 to 6 of the live order (`verifyChain` lists them), against `cfg.keyrings`, each distinct key a service has
 * tried once. With `signers`, a stamp from another service or instance than expected is not one the expected key
 * signed: BAD_ORIGIN for the origin, BAD_SIGNATURE for any other. Returns the stamps, or the first failure.
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

  // 2. Origin.
  if (!cfg.allowedOrigins.includes(first.svc) || (signers !== undefined && first.inst !== signers.inst)) {
    return "BAD_ORIGIN";
  }

  // 3. Signatures and links.
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
  // 4. Only after the whole chain's signatures, the receivers: each stamp addresses the next hop's service, naming an
  // operation of it or none, and the last names the chain's receiver exactly.
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

/** Check 8: the last stamp binds what was received. */
export function checkBinding(last: Stamp, expectedBind: string): ReasonCode | undefined {
  return last.bind === expectedBind ? undefined : "BINDING_MISMATCH";
}

/**
 * Checks 9a and 9b of the live order (`verifyChain` lists them), then 9c when `live` and `settings.enforceRequires`.
 * `blocks` is what `readBlocksToken` gives, or a value already read: null is one empty block per stamp. Returns the
 * blocks, one per stamp, or the first failure.
 */
export function checkBlocks(
  stamps: readonly Stamp[],
  blocks: JsonValue | undefined | null,
  settings: ExtensionSettings,
  live: boolean,
): Block[] | ReasonCode {
  // 9a. The blocks read, one per stamp, each matching its stamp's ext.
  let read: Block[];
  try {
    if (blocks === undefined) return "EXTENSION_MISMATCH";
    read = blocks === null ? stamps.map(() => EMPTY_BLOCK) : blocksOf(blocks);
    if (read.length !== stamps.length || read.some((b, i) => commitBlock(b) !== stamps[i]!.ext)) {
      return "EXTENSION_MISMATCH";
    }
  } catch {
    return "EXTENSION_MISMATCH";
  }

  // 9b. Every name is one the verifier carries.
  const allowed = settings.allowed;
  const names = (b: Block) => [...Object.keys(b.items), ...b.requires];
  if (allowed !== undefined && !read.every((b) => names(b).every((n) => allowed.has(n)))) {
    return "EXTENSION_NOT_ALLOWED";
  }

  // 9c. The direct caller's requirements are acted on.
  if (live && settings.enforceRequires && read[read.length - 1]!.requires.some((n) => !settings.actsOn.has(n))) {
    return "EXTENSION_REQUIRED";
  }
  return read;
}

/**
 * What a verifier hands the service on OK (spec verification.md, The live order): for each name in `actsOn`, one entry
 * per stamp in chain order, its svc and the items its block holds under the name, or null when the block does not name
 * it.
 */
export function handOverOf(stamps: readonly Stamp[], blocks: readonly Block[], settings: ExtensionSettings): HandOver {
  const handOver = new Map<string, readonly StampItems[]>();
  for (const name of settings.actsOn) {
    handOver.set(name, stamps.map((s, i) => ({ svc: s.svc, items: itemsUnder(blocks[i]!, name) })));
  }
  return handOver;
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
 * Check 12 and the result: the route from the chain's rcvs, ending at the receiver when `receiverInRoute`, proven by
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
  // 12. Route proven against a root the proof names.
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
