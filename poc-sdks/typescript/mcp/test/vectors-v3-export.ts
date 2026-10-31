// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Builds spec/vectors/v3.json, the v3 conformance vectors, as a pure function of fixed seeds; run with
// `--write` from poc-sdks/typescript to write the file. Every case is checked against the library first, and
// the export throws on any mismatch, so it can never record a wrong answer.

import { createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import {
  CALL_MAX_AGE_MS, NONCE_TTL_MS, NonceCache, RUN_MAX_AGE_MS, SALT_BYTES, bindLocalTool, buildTree, bindPrompt, bindResponse, bindResult,
  commitInfluence, concat, decode, encode, keyPairMatches, keyringSigningBytes, leafHash, localReceiver, nodeHash,
  normalizeInfluence, provesPath, publicWriteRefused, routeOf, sha256, sign, signKeyring, signKeyringOldForm, signStampV2, signStampV3, signingBytesV3,
  utf8, verifyChainOffline, verifyChainV3, verifyKeyring, issueReplyCert, replyCertSigningBytes, verifyReplyCert,
  checkSessionReply, deriveSessionId, isCurrent, isNotAfter, renewRoot, rootSigningBytes, sessionStatus, signRoot, signRootOldForm, signSessionReply, verifyRoot,
  callInSession, newRecordSet, parseLocalRules, recordedSession, rulesHash, stampLocalStep, localStepBind, verifyRecordedLocalStep,
} from "@paztport/core";
import type {
  InfluenceEntry, InfluenceFact, LegacySessionRequest, LocalRules, LocalVerdict, MerkleProof, Peer, RecordedStamp, ReplyCert, Resolved, SessionReply, SessionRequest,
  SignedKeyring, SignedRoot, StampV3,
} from "@paztport/core";
import { bindMcpCall, mcpReceiver } from "../src/index.ts";

const V3_JSON = new URL("../../../spec/vectors/v3.json", import.meta.url);
const V2_JSON = new URL("../../../spec/vectors/v2.json", import.meta.url);

const KEY_NAMES = ["session", "pi", "mcp-entry", "github-tools", "gateway", "orders", "client-policy", "server-policy"] as const;
type KeyName = (typeof KEY_NAMES)[number];
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";
/** The keyring and root cases' fixed notAfter: 2027-01-01, as the Java tests use. */
const POLICY_NOT_AFTER = 1_798_761_600_000;
/** The keyring and root cases whose notAfter the file writes as `1798761600000.0` (see vectorsV3Text). */
const BY_VALUE = { keyring: "notAfter written 1798761600000.0", root: "notAfter written 1798761600000.0" } as const;
const DEPTH = 8;
/** The verify case whose last stamp's ts is −2^63, which the file writes exactly (see vectorsV3Text). */
const TS_MIN_CASE = "stamp ts of -2^63";
const TS_MIN_TEXT = "-9223372036854775808";

const ABOUT =
  "Paztport v3 conformance vectors. Every case carries all of its inputs; keys and policies are named and defined in this file. " +
  `Each key's private key is the PKCS#8 DER ${PKCS8_ED25519_PREFIX} || seed, where seed = SHA-256(utf8("paztport-v3-vector-key:" + name)), ` +
  "and its public key is the SPKI DER export; both are base64url. " +
  `Each Merkle leaf salt is the first ${SALT_BYTES} bytes of SHA-256(utf8("paztport-v3-vector-salt:" + route)), and the policy's routes fill the ` +
  'first leaves in order; padding leaf i is SHA-256(utf8("paztport-v3-vector-pad:" + rootId + ":" + i)). ' +
  "This placement and rootId derivation are for the vectors only; real builds use random slots and a random rootId. " +
  "Ed25519 is deterministic, so the file is reproduced byte for byte. " +
  "A verify case runs the live verifier `uses` times against one nonce cache of nonceTtlMs and expects the last result; " +
  "its policyNotAfter is the earliest notAfter of the keyring and root the verifier pins, which `now` must not pass. " +
  "An offline case runs the offline verifier once: `recordedTs.last` is the recorded time of the last stamp, `rid` the record's rid, " +
  "`prompt` the run's recorded prompt, and callMaxAgeMs and runMaxAgeMs the age limits; there is no peer, clock or nonce TTL, and `seen` " +
  "is the set of nonce keys already spent in the record set. A policy's proof is looked up by `proofRoute` (null: no proof). " +
  "A sessionStatus case is the server's status for `request` at `now`, against its own `serverRoot` and `serverKeyring` (whose notAfter is its window), " +
  "its policy key `serverPolicyKey` and the client policy keys `pinned`. " +
  "Cases may be added; a recorded answer changes only with a protocol change.";

/** The deterministic Ed25519 key pair for a name, as base64url SPKI and PKCS#8 DER. */
function vectorKey(name: string): { pub: string; priv: string } {
  const der = concat(Buffer.from(PKCS8_ED25519_PREFIX, "hex"), sha256(utf8("paztport-v3-vector-key:" + name)));
  const pub = createPublicKey(createPrivateKey({ key: Buffer.from(der), format: "der", type: "pkcs8" })).export({ format: "der", type: "spki" });
  const pair = { pub: encode(pub), priv: encode(der) };
  if (!keyPairMatches(pair.priv, pair.pub)) {
    throw new Error(`key ${name} does not round-trip`);
  }
  return pair;
}

function salt(route: string): Uint8Array {
  return sha256(utf8("paztport-v3-vector-salt:" + route)).slice(0, SALT_BYTES);
}

type Policy = { routes: string[]; depth: number; rootId: string; root: string; proofs: Record<string, MerkleProof> };

/** "v" + first 12 hex of SHA-256(routes joined by newline): the vectors' fixed rootId, not how real builds label a tree. */
function deriveRootId(routes: string[]): string {
  return "v" + Buffer.from(sha256(utf8(routes.join("\n")))).toString("hex").slice(0, 12);
}

/** A policy tree with fixed salts and padding (the library's tree pads at random), each proof checked by the library. */
function policy(routes: string[]): Policy {
  const rootId = deriveRootId(routes);
  const level0 = routes.map((r) => leafHash(salt(r), r));
  for (let i = routes.length; i < 2 ** DEPTH; i++) {
    level0.push(sha256(utf8(`paztport-v3-vector-pad:${rootId}:${i}`)));
  }
  const levels = [level0];
  while (levels[levels.length - 1]!.length > 1) {
    const below = levels[levels.length - 1]!;
    levels.push(below.flatMap((_, i) => (i % 2 === 0 ? [nodeHash(below[i]!, below[i + 1]!)] : [])));
  }
  const root = levels[levels.length - 1]![0]!;
  const library = buildTree(routes.map((path) => ({ salt: salt(path), path })), DEPTH, rootId);
  const proofs: Record<string, MerkleProof> = {};
  routes.forEach((route, leaf) => {
    const siblings: string[] = [];
    let dirs = "";
    let index = leaf;
    for (let level = 0; level < DEPTH; level++) {
      const left = index % 2 === 0;
      siblings.push(encode(levels[level]![left ? index + 1 : index - 1]!));
      dirs += left ? "L" : "R";
      index = Math.floor(index / 2);
    }
    proofs[route] = { leafSalt: encode(salt(route)), siblings, dirs, rootId };
    if (!provesPath(proofs[route], route, root, rootId)) {
      throw new Error(`proof for ${route} does not verify`);
    }
    // Laid out as the library lays out a tree: the same leaf, salt and directions.
    const { leafSalt, dirs: libraryDirs } = library.proofFor(route);
    check(`proof layout for ${route}`, { leafSalt, dirs: libraryDirs }, { leafSalt: proofs[route].leafSalt, dirs });
  });
  return { routes, depth: DEPTH, rootId, root: encode(root), proofs };
}

function check(what: string, got: unknown, want: unknown): void {
  if (!isDeepStrictEqual(got, want)) {
    throw new Error(`${what}: the library gives ${JSON.stringify(got)}, the vector says ${JSON.stringify(want)}`);
  }
}

type Expected = { reason: string; suspectSvc: string; suspectInst: string };

/** What a verify case shares with an offline one. */
type CaseInputs = {
  name: string;
  chain: RecordedStamp[];
  expectedBind: string;
  influence: InfluenceEntry[];
  policy: "client" | "server" | "mesh";
  proofRoute: string | null;
  receiver: string;
  receiverInRoute: boolean;
  keyring: Record<string, KeyName>;
  allowedOrigins: string[];
  sess: string;
  nonceKey: string;
};

export function buildVectorsV3(): Record<string, unknown> {
  const keys = Object.fromEntries(KEY_NAMES.map((n) => [n, vectorKey(n)])) as Record<KeyName, { pub: string; priv: string }>;
  const v3 = (fields: Omit<StampV3, "v" | "sig">, key: KeyName) => signStampV3(fields, keys[key].priv);

  const TOOL = "create_pull_request";
  const CALL_RCV = mcpReceiver("github", TOOL);
  const OTHER_RCV = mcpReceiver("github", "add_issue_comment");
  const LOCAL_RCV = localReceiver("read");
  const policies = {
    client: policy([routeOf(["session", "pi", CALL_RCV]), routeOf(["session", "pi", OTHER_RCV]), routeOf(["session", "pi", LOCAL_RCV])]),
    server: policy([routeOf(["mcp-entry", "github-tools"])]),
    mesh: policy([routeOf(["gateway", "orders", "payment"])]),
  };
  const [CALL_ROUTE, OTHER_ROUTE, LOCAL_ROUTE] = policies.client.routes as [string, string, string];

  // signingBytesV3: the second pins UTF-8 with a non-ASCII inst.
  const sbStamps: Omit<StampV3, "sig">[] = [
    { v: 3, svc: "pi", inst: "pi-1", rid: "rid-1", ts: 1767225600000, sess: "sess-1", rcv: CALL_RCV, bind: "bind-1", infl: "infl-1", prev: "prev-1" },
    { v: 3, svc: "pi", inst: "pi-é", rid: "rid-1", ts: 1767225600000, sess: "", rcv: LOCAL_RCV, bind: "bind-2", infl: "", prev: "prev-2" },
  ];
  const signingBytesCases = sbStamps.map((stamp) => ({ stamp, hex: Buffer.from(signingBytesV3(stamp)).toString("hex") }));
  check("signingBytesV3 UTF-8", signingBytesCases[1]!.hex.includes(Buffer.from("|pi-é|", "utf8").toString("hex")), true);

  // The client run: one prompt, an mcp call and a local step.
  const NOW = 1_767_225_600_000;
  const SESS = "sess-1";
  const RID = "rid-1";
  const PROMPT = "open a PR for issue #42";
  const CALL_ID = "call-1";
  const ARGS = { title: "Fix #42", body: "Closes #42", draft: false };
  const INFLUENCE: InfluenceEntry[] = [
    { cls: "third-party", src: "web:example.com", h: "h2" },
    { cls: "private", src: "github:acme/app#42", h: "h1", cid: "cid-1", owner: "alice" },
  ];
  const callBind = bindMcpCall(TOOL, CALL_ID, ARGS);
  const originFields = { svc: "session", inst: "pi-1", rid: RID, ts: NOW - 2000, sess: SESS, rcv: "pi", bind: bindPrompt(PROMPT), infl: "", prev: "" };
  const origin = v3(originFields, "session");
  const hopFields = (prev: string) => ({ svc: "pi", inst: "pi-1", rid: RID, ts: NOW - 1000, sess: SESS, rcv: CALL_RCV, bind: callBind, infl: commitInfluence(INFLUENCE), prev });
  const hop = v3(hopFields(origin.sig), "pi");
  const call = [origin, hop];

  // The server's response to that call, back to pi.
  const LABELS = [{ cls: "private" as const, cid: "cid-1", owner: "alice" }];
  const respBind = bindResponse(bindResult({ content: [{ type: "text", text: "opened #43" }], isError: false }), CALL_ID, LABELS);
  const entry = v3({ svc: "mcp-entry", inst: "entry-1", rid: RID, ts: NOW - 800, sess: SESS, rcv: "github-tools", bind: callBind, infl: "", prev: "" }, "mcp-entry");
  const toolsFields = { svc: "github-tools", inst: "gh-1", rid: RID, ts: NOW - 500, sess: SESS, rcv: "pi", bind: respBind, infl: "", prev: entry.sig };
  const tools = v3(toolsFields, "github-tools");

  // A local step: its own chain, with no session.
  const localBind = bindLocalTool("read", { path: "notes.md" }, { callId: "tc-1", verdict: "OK" });
  const localOrigin = v3({ ...originFields, sess: "" }, "session");
  const local = [localOrigin, v3({ svc: "pi", inst: "pi-1", rid: RID, ts: NOW - 1000, sess: "", rcv: LOCAL_RCV, bind: localBind, infl: "", prev: localOrigin.sig }, "pi")];

  // Two plain HTTP hops in a mesh.
  const HTTP_BIND = "bind-orders-to-payment";
  const gateway = v3({ svc: "gateway", inst: "gw-1", rid: "rid-2", ts: NOW - 1500, sess: "sess-2", rcv: "orders", bind: "bind-gateway-to-orders", infl: "", prev: "" }, "gateway");
  const http = [gateway, v3({ svc: "orders", inst: "ord-1", rid: "rid-2", ts: NOW - 500, sess: "sess-2", rcv: "payment", bind: HTTP_BIND, infl: "", prev: gateway.sig }, "orders")];

  // Broken variants of the call.
  const strayOrigin = v3({ ...originFields, rcv: "search" }, "session");
  const strayCall = [strayOrigin, v3(hopFields(strayOrigin.sig), "pi")];
  const forgedCall = [origin, v3(hopFields(origin.sig), "session")];
  const strayForgedCall = [strayOrigin, v3(hopFields(strayOrigin.sig), "session")];
  // An origin older than the run's lifetime when the call was made.
  const staleOrigin = v3({ ...originFields, ts: NOW - 1000 - RUN_MAX_AGE_MS - 1 }, "session");
  const staleCall = [staleOrigin, v3(hopFields(staleOrigin.sig), "pi")];
  // Malformed rcv fields, built by hand: signStampV3 refuses the delimiter, and the parse and delimiter checks come before signatures.
  const { rcv: _rcv, ...hopWithoutRcv } = hop;
  const malformed = (last: unknown) => [origin, last] as unknown as RecordedStamp[];
  // The same call recorded before stamps named their receiver (v2, influence with no owners), and mixed.
  const v2Influence: InfluenceEntry[] = [{ cls: "third-party", src: "web:example.com", h: "h2" }];
  const v2Origin = signStampV2({ svc: "session", inst: "pi-1", rid: RID, ts: NOW - 2000, sess: SESS, bind: bindPrompt(PROMPT), infl: "", prev: "" }, keys.session.priv);
  const v2Call: RecordedStamp[] = [
    v2Origin,
    signStampV2({ svc: "pi", inst: "pi-1", rid: RID, ts: NOW - 1000, sess: SESS, bind: callBind, infl: commitInfluence(v2Influence), prev: v2Origin.sig }, keys.pi.priv),
  ];
  const mixedCall: RecordedStamp[] = [v2Origin, v3(hopFields(v2Origin.sig), "pi")];
  // A v2 chain whose stamps carry an rcv: v2 does not sign it, so it is ignored, even one naming the wrong hop.
  const strayRcvV2Call = v2Call.map((s) => ({ ...s, rcv: "search" })) as unknown as RecordedStamp[];

  const clientCall: Omit<CaseInputs, "name"> = {
    chain: call, expectedBind: callBind, influence: INFLUENCE, policy: "client", proofRoute: CALL_ROUTE, receiver: CALL_RCV,
    receiverInRoute: true, keyring: { session: "session", pi: "pi" }, allowedOrigins: ["session"], sess: SESS, nonceKey: `${RID}|${CALL_ID}|req`,
  };
  const resolveKeyring = (k: Record<string, KeyName>) => Object.fromEntries(Object.entries(k).map(([svc, name]) => [svc, keys[name].pub]));
  const rootOf = (name: CaseInputs["policy"]) => decode(policies[name].root);
  const proofOf = (c: CaseInputs) => (c.proofRoute === null ? null : policies[c.policy].proofs[c.proofRoute]);

  /** A verify case's pinned policy window unless it sets its own: 2100-01-01, far past `now`. */
  const PINNED_NOT_AFTER = 4_102_444_800_000;
  type Live = CaseInputs & { peer: Peer | null; uses: number; policyNotAfter?: number };
  const live = (c: Live, expected: Expected) => {
    const nonces = new NonceCache(NONCE_TTL_MS);
    const policyNotAfter = c.policyNotAfter ?? PINNED_NOT_AFTER;
    const cfg = {
      keyring: resolveKeyring(c.keyring), root: rootOf(c.policy), rootId: policies[c.policy].rootId, allowedOrigins: c.allowedOrigins,
      sess: c.sess, nonces, nonceKey: c.nonceKey, now: NOW, callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS, policyNotAfter,
    };
    const input = {
      stamps: c.chain, expectedBind: c.expectedBind, influence: c.influence, proof: proofOf(c), receiver: c.receiver,
      receiverInRoute: c.receiverInRoute, ...(c.peer === null ? {} : { peer: c.peer }),
    };
    let result = verifyChainV3(input, cfg);
    for (let i = 1; i < c.uses; i++) result = verifyChainV3(input, cfg);
    check(`verify ${c.name}`, { reason: result.reason, suspectSvc: result.suspectSvc, suspectInst: result.suspectInst }, expected);
    const { name, chain, expectedBind, influence, policy: p, proofRoute, receiver, receiverInRoute, peer, keyring, allowedOrigins, sess, nonceKey, uses } = c;
    return {
      name, chain, expectedBind, influence, policy: p, proofRoute, receiver, receiverInRoute, peer, keyring, allowedOrigins, sess, nonceKey,
      now: NOW, callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS, nonceTtlMs: NONCE_TTL_MS, policyNotAfter, uses, expected,
    };
  };
  const ok = (svc: string, inst: string): Expected => ({ reason: "OK", suspectSvc: svc, suspectInst: inst });
  const no = (reason: string, svc = "", inst = ""): Expected => ({ reason, suspectSvc: svc, suspectInst: inst });
  const callCase = (name: string, extra: Partial<Live> = {}): Live => ({ name, ...clientCall, peer: null, uses: 1, ...extra });
  const responseCase: Live = {
    name: "response ok", chain: [entry, tools], expectedBind: respBind, influence: [], policy: "server", proofRoute: "mcp-entry/github-tools",
    receiver: "pi", receiverInRoute: false, peer: null, keyring: { "mcp-entry": "mcp-entry", "github-tools": "github-tools" },
    allowedOrigins: ["mcp-entry"], sess: SESS, nonceKey: `${RID}|${CALL_ID}|resp`, uses: 1,
  };
  const verify = [
    live(callCase("mcp call ok"), ok("pi", "pi-1")),
    live(
      {
        name: "http hops ok", chain: http, expectedBind: HTTP_BIND, influence: [], policy: "mesh", proofRoute: "gateway/orders/payment",
        receiver: "payment", receiverInRoute: true, peer: null, keyring: { gateway: "gateway", orders: "orders" }, allowedOrigins: ["gateway"],
        sess: "sess-2", nonceKey: "rid-2|orders|req", uses: 1,
      },
      ok("orders", "ord-1"),
    ),
    live(responseCase, ok("github-tools", "gh-1")),
    live(
      callCase("local step ok", { chain: local, expectedBind: localBind, influence: [], proofRoute: LOCAL_ROUTE, receiver: LOCAL_RCV, sess: "", nonceKey: `${RID}|tc-1|local` }),
      ok("pi", "pi-1"),
    ),
    live(callCase("receiver chain broken", { chain: strayCall }), no("BINDING_MISMATCH")),
    live(callCase("wrong receiver", { receiver: OTHER_RCV }), no("BINDING_MISMATCH")),
    live(callCase("v2 stamps live", { chain: v2Call, influence: v2Influence }), no("CHAIN_MISSING")),
    live(callCase("peer ok", { peer: { svc: "pi", inst: "10.0.0.7" } }), ok("pi", "10.0.0.7")),
    live(callCase("peer mismatch", { peer: { svc: "search", inst: "10.0.0.9" } }), no("PEER_MISMATCH", "search", "10.0.0.9")),
    live(callCase("peer blamed on bad signature", { chain: forgedCall, peer: { svc: "search", inst: "10.0.0.9" } }), no("BAD_SIGNATURE", "search", "10.0.0.9")),
    live(callCase("no peer, bad signature", { chain: forgedCall }), no("BAD_SIGNATURE")),
    live(callCase("no peer, path not allowed", { proofRoute: OTHER_ROUTE }), no("PATH_NOT_ALLOWED", "pi", "pi-1")),
    live(callCase("replay", { uses: 2 }), no("REPLAY")),
    live(callCase("influence owner altered", { influence: INFLUENCE.map((e) => (e.owner === undefined ? e : { ...e, owner: "bob" })) }), no("INFLUENCE_MISMATCH")),
    // The check order: signatures before receivers, the route before the peer.
    live(callCase("bad signature beats bad receiver", { chain: strayForgedCall }), no("BAD_SIGNATURE")),
    live(callCase("route fails before peer", { proofRoute: OTHER_ROUTE, peer: { svc: "search", inst: "10.0.0.9" } }), no("PATH_NOT_ALLOWED", "search", "10.0.0.9")),
    live({ ...responseCase, name: "response to wrong receiver", receiver: "other" }, no("BINDING_MISMATCH")),
    // Malformed rcv fields.
    live(callCase("v3 stamp with no rcv", { chain: malformed(hopWithoutRcv) }), no("CHAIN_MISSING")),
    live(callCase("rcv holding the delimiter", { chain: malformed({ ...hop, rcv: "a|b" }) }), no("BAD_SIGNATURE")),
    live(callCase("non-string rcv", { chain: malformed({ ...hop, rcv: 7 }) }), no("CHAIN_MISSING")),
    // A ts out of the safe-integer range, at the low end a 64-bit reader could take for a long.
    live(callCase(TS_MIN_CASE, { chain: malformed({ ...hop, ts: -(2 ** 63) }) }), no("CHAIN_MISSING")),
    // The verifier's own pinned policy: checked before the stamps, and naming no one, not even a peer.
    live(callCase("at policy notAfter", { policyNotAfter: NOW }), ok("pi", "pi-1")),
    live(callCase("policy expired", { policyNotAfter: NOW - 1 }), no("POLICY_EXPIRED")),
    live(callCase("policy expired beats bad signature, names no peer", { policyNotAfter: NOW - 1, chain: forgedCall, peer: { svc: "search", inst: "10.0.0.9" } }), no("POLICY_EXPIRED")),
    live(callCase("policy expired beats a malformed chain", { policyNotAfter: NOW - 1, chain: [] }), no("POLICY_EXPIRED")),
    live(callCase("policy notAfter out of range", { policyNotAfter: 2 ** 53 }), no("POLICY_EXPIRED")),
  ];

  /** An offline case; the recorded time defaults to the last stamp's, the prompt to the run's, and `seen` to none. */
  type Offline = CaseInputs & { recordedTs?: { last: number }; prompt?: string; seen?: string[] };
  const offlineCase = (c: Offline, expected: Expected & { legacy: boolean }) => {
    const recordedTs = c.recordedTs ?? { last: c.chain[c.chain.length - 1]!.ts };
    const prompt = c.prompt ?? PROMPT;
    const seen = c.seen ?? [];
    const result = verifyChainOffline(
      {
        stamps: c.chain, expectedBind: c.expectedBind, influence: c.influence, proof: proofOf(c), receiver: c.receiver, receiverInRoute: c.receiverInRoute,
        rid: RID, recordedTs, prompt,
      },
      {
        keyring: resolveKeyring(c.keyring), root: rootOf(c.policy), rootId: policies[c.policy].rootId, allowedOrigins: c.allowedOrigins, sess: c.sess,
        nonceKey: c.nonceKey, seen: new Set(seen), callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS,
      },
    );
    check(`offline ${c.name}`, { reason: result.reason, suspectSvc: result.suspectSvc, suspectInst: result.suspectInst, legacy: result.legacy }, expected);
    const { name, chain, expectedBind, influence, policy: p, proofRoute, receiver, receiverInRoute, keyring, allowedOrigins, sess, nonceKey } = c;
    return {
      name, chain, expectedBind, influence, policy: p, proofRoute, receiver, receiverInRoute, keyring, allowedOrigins, sess, nonceKey,
      seen, callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS, rid: RID, recordedTs, prompt, expected,
    };
  };
  const offline = [
    offlineCase({ name: "legacy v2 recorded call", ...clientCall, chain: v2Call, influence: v2Influence }, { ...ok("pi", "pi-1"), legacy: true }),
    offlineCase({ name: "v3 recorded call", ...clientCall }, { ...ok("pi", "pi-1"), legacy: false }),
    offlineCase({ name: "mixed versions", ...clientCall, chain: mixedCall }, { ...no("CHAIN_MISSING"), legacy: false }),
    offlineCase({ name: "legacy v2 call with a stray rcv", ...clientCall, chain: strayRcvV2Call, influence: v2Influence }, { ...ok("pi", "pi-1"), legacy: true }),
    offlineCase({ name: "receiver chain broken", ...clientCall, chain: strayCall }, { ...no("BINDING_MISMATCH"), legacy: false }),
    offlineCase({ name: "recorded time differs", ...clientCall, recordedTs: { last: hop.ts + 1 } }, { ...no("TIME_MISMATCH"), legacy: false }),
    offlineCase({ name: "expired", ...clientCall, chain: staleCall }, { ...no("EXPIRED"), legacy: false }),
    offlineCase({ name: "prompt differs", ...clientCall, prompt: "open a PR for issue #43" }, { ...no("PROMPT_MISMATCH"), legacy: false }),
    offlineCase({ name: "replay in the record set", ...clientCall, seen: [clientCall.nonceKey] }, { ...no("REPLAY"), legacy: false }),
  ];

  const signatures = [
    { fields: originFields, key: "session" },
    { fields: hopFields(origin.sig), key: "pi" },
    { fields: toolsFields, key: "github-tools" },
  ].map((c) => {
    const sig = encode(sign(keys[c.key as KeyName].priv, signingBytesV3({ v: 3, ...c.fields })));
    check(`signature by ${c.key}`, sig, [origin, hop, tools].find((s) => s.svc === c.fields.svc)!.sig);
    return { ...c, sig };
  });

  // Influence: normalised forms written by hand; the "no owners" commitment is v2's.
  const v2 = JSON.parse(readFileSync(V2_JSON, "utf8"));
  const notes = (cid?: string, owner?: string): InfluenceEntry => ({
    cls: "private", src: "file:notes.md", h: "h1", ...(cid === undefined ? {} : { cid }), ...(owner === undefined ? {} : { owner }),
  });
  const influenceCases = [
    { name: "no owners", entries: v2.commitInfluence.entries as InfluenceEntry[], normalized: [
      { cls: "private", src: "file:notes.md", h: "h1", cid: "cid-1" },
      { cls: "third-party", src: "web:example.com", h: "h2" },
      { cls: "public", src: "web:docs.example.org", h: "h3" },
    ] },
    { name: "owner after cid, absent first", entries: [notes("cid-2"), notes("cid-1", "bob"), notes("cid-1", "alice"), notes("cid-1")], normalized: [
      notes("cid-1"), notes("cid-1", "alice"), notes("cid-1", "bob"), notes("cid-2"),
    ] },
    { name: "same entry with and without an owner is kept twice", entries: [notes(undefined, "alice"), notes(), notes(undefined, "alice")], normalized: [
      notes(), notes(undefined, "alice"),
    ] },
  ].map((c) => {
    check(`influence ${c.name}`, normalizeInfluence(c.entries), c.normalized);
    return { ...c, commitment: commitInfluence(c.entries) };
  });
  check("no owners commitment", influenceCases[0]!.commitment, v2.commitInfluence.expected);

  // The standing rule's truth table, by hand.
  const TP = { cls: "third-party" } as const;
  const LU = { cls: "local-untrusted" } as const;
  const PUB = { cls: "public" } as const;
  const P = (owner?: string): InfluenceFact => (owner === undefined ? { cls: "private" } : { cls: "private", owner });
  const rule = ([
    ["own private data, untrusted content", [TP, P("alice")], "alice", false],
    ["someone else's private data", [TP, P("bob")], "alice", true],
    ["private data with no owner", [TP, P()], "alice", true],
    ["unknown destination owner", [TP, P("alice")], null, true],
    ["local-untrusted counts as untrusted", [LU, P("bob")], "alice", true],
    ["no untrusted content", [P("bob")], "alice", false],
    ["no private data", [TP], "alice", false],
    ["one foreign entry is enough", [TP, P("alice"), P("bob")], "alice", true],
    ["public is not private", [TP, PUB], "alice", false],
    ["an empty owner is unknown on both sides", [TP, P("")], "", true],
    ["nothing at all", [], "alice", false],
    ["an empty private owner is unknown", [TP, P("")], "alice", true],
    ["an empty destination owner is unknown", [TP, P("alice")], "", true],
  ] as [string, InfluenceFact[], string | null, boolean][]).map(([name, influence, destinationOwner, refused]) => {
    check(`rule ${name}`, publicWriteRefused(influence, destinationOwner ?? undefined), refused);
    return { name, influence, destinationOwner, refused };
  });

  // The client keyring in the old form, signed by its policy key, and a copy with pi's key swapped.
  const keyringCase = (name: string, services: Record<string, KeyName>, sig: string | undefined, verifies: boolean) => {
    const resolved = resolveKeyring(services);
    const signed = sig === undefined ? signKeyringOldForm(resolved, keys["client-policy"].pub, keys["client-policy"].priv) : { policy: keys["client-policy"].pub, services: resolved, sig };
    check(`keyring ${name}`, verifyKeyring(signed, keys["client-policy"].pub), verifies);
    return { name, policyKey: "client-policy", services, signingBytes: encode(keyringSigningBytes(signed.policy, signed.services)), sig: signed.sig, signed, verifies };
  };
  const signedKeyring = keyringCase("signed", { session: "session", pi: "pi" }, undefined, true);
  const keyring: Record<string, unknown>[] = [signedKeyring, keyringCase("tampered", { session: "session", pi: "gateway" }, signedKeyring.sig, false)];

  // The two forms of what the policy key signs offline. The new form carries notAfter, and its signed bytes
  // include it; the old form has none, still verifies for recorded evidence, and is never current. A case's
  // form is decided by whether `signed` has a notAfter member. signingBytes is null when that notAfter is not
  // an integer in [0, 2^53 - 1], which nothing signs; `current` gives isCurrent's answer at each `at`.
  //
  // The cross-prefix cases (a root signature offered as a keyring signature, and the other way round) are not the
  // domain-separation guarantee: the two signed bodies differ, so those signatures would fail even without the
  // prefixes. What pins the prefixes is each case's literal `signingBytes`, which both replays rebuild by hand.
  //
  // Two cases tie the readers together on how a notAfter is read: one of 2^53, which each must refuse, and one
  // written 1798761600000.0 in the file (see BY_VALUE), which each must read by value as the integer the signature
  // is over.
  const DAY_MS = 86_400_000;
  const hasWindow = (o: object): o is { notAfter: unknown } => Object.hasOwn(o, "notAfter");
  const currentAt = (o: object, ats: number[]) => ats.map((at) => ({ at, current: isCurrent(o, at) }));
  const ringServices = { session: "session", pi: "pi" } as const;
  const ringPolicy = keys["client-policy"].pub;
  const newRing = (notAfter: number) => signKeyring(resolveKeyring(ringServices), ringPolicy, keys["client-policy"].priv, notAfter);
  const oldRing = signKeyringOldForm(resolveKeyring(ringServices), ringPolicy, keys["client-policy"].priv);
  const rootPolicy = policies.client;
  const newRoot = (notAfter: number, signer: KeyName = "client-policy") => signRoot(decode(rootPolicy.root), rootPolicy.rootId, keys[signer].priv, notAfter);
  const oldRoot = signRootOldForm(decode(rootPolicy.root), rootPolicy.rootId, keys["client-policy"].priv);
  const keyringFormCase = (name: string, signed: SignedKeyring, verifies: boolean, ats?: number[]) => {
    check(`keyring ${name}`, verifyKeyring(signed, ringPolicy), verifies);
    const w = hasWindow(signed);
    const bytes = !w ? keyringSigningBytes(signed.policy, signed.services) : isNotAfter(signed.notAfter) ? keyringSigningBytes(signed.policy, signed.services, signed.notAfter) : null;
    const priv = keys["client-policy"].priv;
    if (verifies) check(`keyring ${name} re-signed`, (w ? signKeyring(signed.services, signed.policy, priv, signed.notAfter as number) : signKeyringOldForm(signed.services, signed.policy, priv)).sig, signed.sig);
    const current = ats === undefined ? {} : { current: currentAt(signed, ats) };
    return { name, policyKey: "client-policy", services: ringServices, signingBytes: bytes === null ? null : encode(bytes), sig: signed.sig, signed, verifies, ...current };
  };
  const { notAfter: _ringWindow, ...ringWindowDropped } = newRing(POLICY_NOT_AFTER);
  keyring.push(
    keyringFormCase("new form", newRing(POLICY_NOT_AFTER), true, [POLICY_NOT_AFTER, POLICY_NOT_AFTER + 1]),
    keyringFormCase("new form, largest notAfter", newRing(Number.MAX_SAFE_INTEGER), true, [Number.MAX_SAFE_INTEGER]),
    keyringFormCase("new form, tampered notAfter", { ...newRing(POLICY_NOT_AFTER), notAfter: POLICY_NOT_AFTER + 1 }, false),
    keyringFormCase("new form, notAfter dropped", ringWindowDropped, false),
    keyringFormCase("old form, notAfter added", { ...oldRing, notAfter: POLICY_NOT_AFTER }, false),
    keyringFormCase("notAfter not an integer", { ...newRing(POLICY_NOT_AFTER), notAfter: 1.5 }, false),
    keyringFormCase("root signature as a keyring signature", { ...newRing(POLICY_NOT_AFTER), sig: newRoot(POLICY_NOT_AFTER).sig }, false),
    keyringFormCase("old form, offline only", oldRing, true, [0, POLICY_NOT_AFTER]),
    keyringFormCase("notAfter 2^53", { ...newRing(POLICY_NOT_AFTER), notAfter: 2 ** 53 }, false),
    keyringFormCase(BY_VALUE.keyring, newRing(POLICY_NOT_AFTER), true, [POLICY_NOT_AFTER, POLICY_NOT_AFTER + 1]),
  );

  // The client policy's signed root in both forms, under the client-policy pin; `policy` names the tree.
  const rootCase = (name: string, signed: SignedRoot, verifies: boolean, ats?: number[]) => {
    check(`root ${name}`, verifyRoot(signed, keys["client-policy"].pub), verifies);
    const w = hasWindow(signed);
    const bytes = !w ? rootSigningBytes(signed.rootId, signed.root) : isNotAfter(signed.notAfter) ? rootSigningBytes(signed.rootId, signed.root, signed.notAfter) : null;
    const priv = keys["client-policy"].priv;
    if (verifies) check(`root ${name} re-signed`, (w ? signRoot(decode(signed.root), signed.rootId, priv, signed.notAfter as number) : signRootOldForm(decode(signed.root), signed.rootId, priv)).sig, signed.sig);
    const current = ats === undefined ? {} : { current: currentAt(signed, ats) };
    return { name, policyKey: "client-policy", policy: "client", signingBytes: bytes === null ? null : encode(bytes), signed, verifies, ...current };
  };
  const renewed = renewRoot(oldRoot, POLICY_NOT_AFTER + DAY_MS, keys["client-policy"].priv);
  check("root renewed keeps the tree", [renewed.rootId, renewed.root], [oldRoot.rootId, oldRoot.root]);
  check("root renewed is the tree signed afresh", renewed, newRoot(POLICY_NOT_AFTER + DAY_MS));
  const { notAfter: _rootWindow, ...rootWindowDropped } = newRoot(POLICY_NOT_AFTER);
  const signedRoots = [
    rootCase("new form", newRoot(POLICY_NOT_AFTER), true, [POLICY_NOT_AFTER, POLICY_NOT_AFTER + 1]),
    rootCase("new form, largest notAfter", newRoot(Number.MAX_SAFE_INTEGER), true, [Number.MAX_SAFE_INTEGER]),
    rootCase("renewed", renewed, true, [POLICY_NOT_AFTER + DAY_MS, POLICY_NOT_AFTER + DAY_MS + 1]),
    rootCase("new form, tampered notAfter", { ...newRoot(POLICY_NOT_AFTER), notAfter: POLICY_NOT_AFTER + 1 }, false),
    rootCase("new form, notAfter dropped", rootWindowDropped, false),
    rootCase("old form, notAfter added", { ...oldRoot, notAfter: POLICY_NOT_AFTER }, false),
    rootCase("notAfter not an integer", { ...newRoot(POLICY_NOT_AFTER), notAfter: 1.5 }, false),
    rootCase("signed by another policy key", newRoot(POLICY_NOT_AFTER, "server-policy"), false),
    rootCase("keyring signature as a root signature", { ...newRoot(POLICY_NOT_AFTER), sig: newRing(POLICY_NOT_AFTER).sig }, false),
    rootCase("old form, offline only", oldRoot, true, [0, POLICY_NOT_AFTER]),
    rootCase("notAfter 2^53", { ...newRoot(POLICY_NOT_AFTER), notAfter: 2 ** 53 }, false),
    rootCase(BY_VALUE.root, newRoot(POLICY_NOT_AFTER), true, [POLICY_NOT_AFTER, POLICY_NOT_AFTER + 1]),
  ];

  // The server's reply certificate for mcp-entry, and forms of it that must not verify under the server pin.
  const CERT_NOT_AFTER = 1_798_761_600_000;
  const issueCert = (policy: KeyName, notAfter: number, signer: KeyName): ReplyCert =>
    issueReplyCert(keys[policy].pub, "mcp-entry", keys["mcp-entry"].pub, notAfter, keys[signer].priv);
  const certCase = (name: string, signer: KeyName, cert: ReplyCert, verifies: boolean) => {
    check(`reply certificate ${name}`, verifyReplyCert(cert, keys["server-policy"].pub), verifies);
    return { name, signer, pin: "server-policy", cert, signingBytes: encode(replyCertSigningBytes(cert.policy, cert.svc, cert.key, cert.notAfter)), verifies };
  };
  const signedCert = issueCert("server-policy", CERT_NOT_AFTER, "server-policy");
  const otherPolicyCert = issueCert("client-policy", CERT_NOT_AFTER, "client-policy");
  check("reply certificate under its own policy key", verifyReplyCert(otherPolicyCert, keys["client-policy"].pub), true);
  const replyCert = [
    certCase("signed", "server-policy", signedCert, true),
    certCase("tampered notAfter", "server-policy", { ...signedCert, notAfter: CERT_NOT_AFTER + 1 }, false),
    certCase("signed by another policy key", "client-policy", issueCert("server-policy", CERT_NOT_AFTER, "client-policy"), false),
    certCase("names another policy key", "client-policy", otherPolicyCert, false),
    certCase("an extra field is ignored", "server-policy", { ...signedCert, note: "not signed" } as ReplyCert, true),
    certCase("largest notAfter", "server-policy", issueCert("server-policy", Number.MAX_SAFE_INTEGER, "server-policy"), true),
  ];

  // Session replies under the server pin: the entry-key ("new") form, signed by mcp-entry's key under its
  // certificate and the signed server keyring, the policy-key ("old") form, and forms that must fail. Both sides'
  // roots and keyrings are in the new form, valid until LIVE_NOT_AFTER, far past every case's `now`; the request
  // carries the client keyring's window as clientKeyringNotAfter, and an entry-key reply the server's as
  // serverKeyringNotAfter.
  const LIVE_NOT_AFTER = 4_102_444_800_000;
  const nonce16 = (label: string) => encode(sha256(utf8("paztport-v3-vector-nonce:" + label)).slice(0, 16));
  const clientRoot = signRoot(decode(policies.client.root), policies.client.rootId, keys["client-policy"].priv, LIVE_NOT_AFTER);
  const clientRing = signKeyring(resolveKeyring(ringServices), ringPolicy, keys["client-policy"].priv, LIVE_NOT_AFTER);
  const request: SessionRequest = {
    clientRoot, clientPolicyKey: ringPolicy, clientKeyring: clientRing.services,
    clientKeyringSig: clientRing.sig, clientKeyringNotAfter: LIVE_NOT_AFTER, nonce: nonce16("client"),
  };
  const SERVER_NONCE = nonce16("server");
  const serverRoot = signRoot(decode(policies.server.root), policies.server.rootId, keys["server-policy"].priv, LIVE_NOT_AFTER);
  const serverRing = signKeyring(
    resolveKeyring({ "mcp-entry": "mcp-entry", "github-tools": "github-tools" }), keys["server-policy"].pub, keys["server-policy"].priv, LIVE_NOT_AFTER,
  );
  const serverRingServices = resolveKeyring({ "mcp-entry": "mcp-entry", "github-tools": "github-tools" });
  const serverRootUntil = (notAfter: number) => signRoot(decode(policies.server.root), policies.server.rootId, keys["server-policy"].priv, notAfter);
  const serverRingUntil = (notAfter: number) => signKeyring(serverRingServices, keys["server-policy"].pub, keys["server-policy"].priv, notAfter);
  const oldServerRoot = signRootOldForm(decode(policies.server.root), policies.server.rootId, keys["server-policy"].priv);
  const oldServerRing = signKeyringOldForm(serverRingServices, keys["server-policy"].pub, keys["server-policy"].priv);
  const certFor = (svc: string, key: KeyName, signer: KeyName = "server-policy") =>
    issueReplyCert(keys["server-policy"].pub, svc, keys[key].pub, CERT_NOT_AFTER, keys[signer].priv);
  const entryCert = certFor("mcp-entry", "mcp-entry");
  const sessFor = (root: { sig: string } | null) => deriveSessionId(clientRoot.sig, root?.sig ?? null, request.nonce, SERVER_NONCE, request);
  /** A reply in the entry-key form by default; `drop` leaves fields out, and `signer` signs it. */
  const reply = (signer: KeyName, o: Record<string, unknown> = {}, drop: string[] = []): Record<string, unknown> => {
    const root = (o.serverRoot ?? serverRoot) as { sig: string };
    const body: Record<string, unknown> = {
      serverRoot: root, serverPolicyKey: keys["server-policy"].pub, serverKeyring: serverRing.services, serverKeyringSig: serverRing.sig,
      serverKeyringNotAfter: LIVE_NOT_AFTER, serverReplyCert: entryCert, nonce: SERVER_NONCE, sess: sessFor(root), status: "attested", disabled: [], ...o,
    };
    for (const f of drop) delete body[f];
    return signSessionReply(body as unknown as Omit<SessionReply, "sig">, keys[signer].priv) as unknown as Record<string, unknown>;
  };
  // The keyring's signature and its window travel together: neither is in the policy-key form.
  const NO_RING_SIG = ["serverKeyringSig", "serverKeyringNotAfter"];
  const OLD = [...NO_RING_SIG, "serverReplyCert"];
  const sessionReplyCase = (name: string, raw: Record<string, unknown>, expected: string, o: { pin?: KeyName; serverEntry?: string; now?: number } = {}) => {
    const pin = o.pin ?? "server-policy";
    const serverEntry = o.serverEntry ?? "mcp-entry";
    const now = o.now ?? NOW;
    check(`session reply ${name}`, checkSessionReply(raw, request, keys[pin].pub, serverEntry, now), expected);
    return { name, request, reply: raw, pin, serverEntry, now, expected };
  };
  const attackerRing = { ...serverRing.services, "mcp-entry": keys.orders.pub };
  const sessionReply = [
    sessionReplyCase("new form attested", reply("mcp-entry"), "ATTESTED"),
    sessionReplyCase("new form unsafe", reply("mcp-entry", { status: "unsafe", disabled: [TOOL] }), "UNSAFE"),
    sessionReplyCase("old form attested", reply("server-policy", {}, OLD), "ATTESTED"),
    sessionReplyCase("at notAfter", reply("mcp-entry"), "ATTESTED", { now: CERT_NOT_AFTER }),
    sessionReplyCase("one ms after notAfter", reply("mcp-entry"), "BAD_SIGNATURE", { now: CERT_NOT_AFTER + 1 }),
    sessionReplyCase("certificate for another service", reply("github-tools", { serverReplyCert: certFor("github-tools", "github-tools") }), "BAD_SIGNATURE"),
    sessionReplyCase("certificate key not the keyring's entry key", reply("orders", { serverReplyCert: certFor("mcp-entry", "orders") }), "BAD_SIGNATURE"),
    sessionReplyCase("certificate signed by another policy key", reply("mcp-entry", { serverReplyCert: certFor("mcp-entry", "mcp-entry", "client-policy") }), "BAD_SIGNATURE"),
    sessionReplyCase("signed by another service", reply("github-tools"), "BAD_SIGNATURE"),
    sessionReplyCase("keyring altered after signing", reply("mcp-entry", { serverKeyring: { ...serverRing.services, "github-tools": keys.orders.pub } }), "BAD_SIGNATURE"),
    sessionReplyCase(
      "keyring signed by another policy key",
      reply("mcp-entry", { serverKeyringSig: encode(sign(keys["client-policy"].priv, keyringSigningBytes(keys["server-policy"].pub, serverRing.services, LIVE_NOT_AFTER))) }),
      "BAD_SIGNATURE",
    ),
    sessionReplyCase(
      "entry absent from keyring",
      (() => {
        const ring = signKeyring(resolveKeyring({ "github-tools": "github-tools" }), keys["server-policy"].pub, keys["server-policy"].priv, LIVE_NOT_AFTER);
        return reply("mcp-entry", { serverKeyring: ring.services, serverKeyringSig: ring.sig });
      })(),
      "BAD_SIGNATURE",
    ),
    sessionReplyCase("keyring signature without certificate", reply("mcp-entry", {}, ["serverReplyCert"]), "BAD_SIGNATURE"),
    sessionReplyCase("certificate without keyring signature", reply("mcp-entry", {}, NO_RING_SIG), "BAD_SIGNATURE"),
    // The form is decided by which fields are present, never by which key verifies.
    sessionReplyCase("keyring signature without certificate, signed by the policy key", reply("server-policy", {}, ["serverReplyCert"]), "BAD_SIGNATURE"),
    sessionReplyCase("certificate without keyring signature, signed by the policy key", reply("server-policy", {}, NO_RING_SIG), "BAD_SIGNATURE"),
    sessionReplyCase("neither field, signed by the keyring's entry key", reply("orders", { serverKeyring: attackerRing }, OLD), "BAD_SIGNATURE"),
    sessionReplyCase(
      "server root signed by the entry key",
      reply("mcp-entry", { serverRoot: signRoot(decode(policies.server.root), policies.server.rootId, keys["mcp-entry"].priv, LIVE_NOT_AFTER) }),
      "BAD_SIGNATURE",
    ),
    sessionReplyCase("serverKeyringSig empty", reply("mcp-entry", { serverKeyringSig: "" }), "BAD_SIGNATURE"),
    sessionReplyCase("serverKeyringSig null", reply("mcp-entry", { serverKeyringSig: null }), "MALFORMED_REPLY"),
    sessionReplyCase("serverReplyCert null", reply("mcp-entry", { serverReplyCert: null }), "MALFORMED_REPLY"),
    sessionReplyCase("notAfter not an integer", reply("mcp-entry", { serverReplyCert: { ...entryCert, notAfter: 1.5 } }), "MALFORMED_REPLY"),
    sessionReplyCase(
      "entry named in the reply is ignored",
      reply("github-tools", { serverEntry: "github-tools", serverReplyCert: certFor("github-tools", "github-tools") }),
      "BAD_SIGNATURE",
    ),
    sessionReplyCase("pin mismatch", reply("mcp-entry"), "PIN_MISMATCH", { pin: "client-policy" }),
    // The server keyring's window is covered by the policy key's keyring signature, not by the entry key's.
    sessionReplyCase("serverKeyringNotAfter moved", reply("mcp-entry", { serverKeyringNotAfter: LIVE_NOT_AFTER + 1 }), "BAD_SIGNATURE"),
    sessionReplyCase("serverKeyringNotAfter dropped", reply("mcp-entry", {}, ["serverKeyringNotAfter"]), "BAD_SIGNATURE"),
    sessionReplyCase("serverKeyringNotAfter not an integer", reply("mcp-entry", { serverKeyringNotAfter: "x" }), "MALFORMED_REPLY"),
    sessionReplyCase("serverKeyringNotAfter null", reply("mcp-entry", { serverKeyringNotAfter: null }), "MALFORMED_REPLY"),
    sessionReplyCase("server root notAfter moved", reply("mcp-entry", { serverRoot: { ...serverRoot, notAfter: LIVE_NOT_AFTER + 1 } }), "BAD_SIGNATURE"),
    sessionReplyCase("server root notAfter not an integer", reply("mcp-entry", { serverRoot: { ...serverRoot, notAfter: 1.5 } }), "MALFORMED_REPLY"),
    // The client judges the server's root, in either form and either status, and in the entry-key form its keyring:
    // each must be in the new form and current at `now`.
    sessionReplyCase("server root at notAfter", reply("mcp-entry", { serverRoot: serverRootUntil(NOW) }), "ATTESTED"),
    sessionReplyCase("server root expired", reply("mcp-entry", { serverRoot: serverRootUntil(NOW - 1) }), "BAD_SIGNATURE"),
    sessionReplyCase("server root expired, policy-key form", reply("server-policy", { serverRoot: serverRootUntil(NOW - 1) }, OLD), "BAD_SIGNATURE"),
    sessionReplyCase("server root expired, unsafe", reply("mcp-entry", { serverRoot: serverRootUntil(NOW - 1), status: "unsafe", disabled: [TOOL] }), "BAD_SIGNATURE"),
    sessionReplyCase("server root old form", reply("mcp-entry", { serverRoot: oldServerRoot }), "BAD_SIGNATURE"),
    sessionReplyCase("server root old form, policy-key form", reply("server-policy", { serverRoot: oldServerRoot }, OLD), "BAD_SIGNATURE"),
    // Current by its moved window and re-signed by the entry key, so only the root's own signature refuses it.
    sessionReplyCase(
      "expired server root's notAfter moved past now, re-signed by the entry key",
      reply("mcp-entry", { serverRoot: { ...serverRootUntil(NOW - 1), notAfter: LIVE_NOT_AFTER } }),
      "BAD_SIGNATURE",
    ),
    sessionReplyCase("server keyring at notAfter", reply("mcp-entry", { serverKeyringSig: serverRingUntil(NOW).sig, serverKeyringNotAfter: NOW }), "ATTESTED"),
    sessionReplyCase("server keyring expired", reply("mcp-entry", { serverKeyringSig: serverRingUntil(NOW - 1).sig, serverKeyringNotAfter: NOW - 1 }), "BAD_SIGNATURE"),
    sessionReplyCase("server keyring old form", reply("mcp-entry", { serverKeyringSig: oldServerRing.sig }, ["serverKeyringNotAfter"]), "BAD_SIGNATURE"),
    // A keyring window with no keyring signature: the policy-key form's keyring is signed only through the reply.
    sessionReplyCase("serverKeyringNotAfter in the policy-key form", reply("server-policy", {}, ["serverKeyringSig", "serverReplyCert"]), "BAD_SIGNATURE"),
  ];

  // The server's status for a request, against its own root and keyring and the client keys it pinned, at `now`:
  // attested only when every root and keyring on both sides is in the new form and current. The client's material
  // is judged only once its signature verifies, so a moved window fails as a signature.
  const clientRootUntil = (notAfter: number) => signRoot(decode(policies.client.root), policies.client.rootId, keys["client-policy"].priv, notAfter);
  const withClientRing = (ring: SignedKeyring): SessionRequest => {
    const { clientKeyringNotAfter: _window, ...rest } = request;
    return { ...rest, clientKeyringSig: ring.sig, ...(ring.notAfter === undefined ? {} : { clientKeyringNotAfter: ring.notAfter }) };
  };
  const statusCase = (
    name: string,
    o: { request?: SessionRequest; serverRoot?: SignedRoot; serverKeyring?: SignedKeyring; pinned?: KeyName[]; now?: number },
    expected: "attested" | "unsafe",
  ) => {
    const req = o.request ?? request;
    const root = o.serverRoot ?? serverRoot;
    const ring = o.serverKeyring ?? serverRing;
    const pinned = o.pinned ?? ["client-policy"];
    const now = o.now ?? NOW;
    const got = sessionStatus(req, root, Object.hasOwn(ring, "notAfter") ? ring.notAfter : undefined, keys["server-policy"].pub, pinned.map((n) => keys[n].pub), now);
    check(`session status ${name}`, got, expected);
    return { name, request: req, serverRoot: root, serverKeyring: ring, serverPolicyKey: "server-policy", pinned, now, expected };
  };
  const sessionStatusCases = [
    statusCase("attested", {}, "attested"),
    statusCase("client key not pinned", { pinned: ["server-policy"] }, "unsafe"),
    statusCase("client root at notAfter", { request: { ...request, clientRoot: clientRootUntil(NOW) } }, "attested"),
    statusCase("client root expired", { request: { ...request, clientRoot: clientRootUntil(NOW - 1) } }, "unsafe"),
    statusCase("client root old form", { request: { ...request, clientRoot: signRootOldForm(decode(policies.client.root), policies.client.rootId, keys["client-policy"].priv) } }, "unsafe"),
    statusCase("expired client root's notAfter moved past now", { request: { ...request, clientRoot: { ...clientRootUntil(NOW - 1), notAfter: LIVE_NOT_AFTER } } }, "unsafe"),
    statusCase("client keyring at notAfter", { request: withClientRing(newRing(NOW)) }, "attested"),
    statusCase("client keyring expired", { request: withClientRing(newRing(NOW - 1)) }, "unsafe"),
    statusCase("client keyring old form", { request: withClientRing(oldRing) }, "unsafe"),
    statusCase("expired client keyring's clientKeyringNotAfter moved past now", { request: { ...withClientRing(newRing(NOW - 1)), clientKeyringNotAfter: LIVE_NOT_AFTER } }, "unsafe"),
    statusCase("server root and keyring at notAfter", { serverRoot: serverRootUntil(NOW), serverKeyring: serverRingUntil(NOW) }, "attested"),
    statusCase("server root expired", { serverRoot: serverRootUntil(NOW - 1) }, "unsafe"),
    statusCase("server root old form", { serverRoot: oldServerRoot }, "unsafe"),
    statusCase("server keyring expired", { serverKeyring: serverRingUntil(NOW - 1) }, "unsafe"),
    statusCase("server keyring old form", { serverKeyring: oldServerRing }, "unsafe"),
  ];


  // Recorded handshakes (sessions-and-influence.md §Recorded handshakes): the session a recorded request and reply
  // opened, judged offline at each `at`, at all (at the earliest of its limits), the policyNotAfter a response in it
  // is checked with, and whether it is legacy. The reply's session id is bound to the request it answers.
  type AnyRequest = SessionRequest | LegacySessionRequest;
  const replyTo = (req: AnyRequest, signer: KeyName, o: Record<string, unknown> = {}, drop: string[] = []): SessionReply => {
    const root = (Object.hasOwn(o, "serverRoot") ? o.serverRoot : serverRoot) as { sig: string };
    const body: Record<string, unknown> = {
      serverRoot: root, serverPolicyKey: keys["server-policy"].pub, serverKeyring: serverRing.services, serverKeyringSig: serverRing.sig,
      serverKeyringNotAfter: LIVE_NOT_AFTER, serverReplyCert: entryCert, nonce: SERVER_NONCE,
      sess: deriveSessionId(req.clientRoot?.sig ?? null, root.sig, req.nonce, SERVER_NONCE, req), status: "attested", disabled: [], ...o,
    };
    for (const f of drop) delete body[f];
    return signSessionReply(body as unknown as Omit<SessionReply, "sig">, keys[signer].priv);
  };
  const { clientKeyringSig: _legacySig, clientKeyringNotAfter: _legacyWindow, ...legacyRequest } = withClientRing(oldRing) as SessionRequest;
  const oldRequest: SessionRequest = { ...withClientRing(oldRing), clientRoot: signRootOldForm(decode(policies.client.root), policies.client.rootId, keys["client-policy"].priv) };
  const handshakeCase = (name: string, request: AnyRequest, reply: SessionReply, at: number[], o: { pin?: KeyName; serverEntry?: string } = {}) => {
    const pin = o.pin ?? "server-policy";
    const serverEntry = o.serverEntry ?? "mcp-entry";
    const s = recordedSession({ request, reply, pin: keys[pin].pub, serverEntry });
    const expected = { attested: s.attested, attestedAt: at.map((t) => s.attestedAt(t)), responseNotAfter: s.responseNotAfter, legacy: s.legacy };
    return { name, request, reply, pin, serverEntry, at, expected };
  };
  const clientRootAt = (t: number): SessionRequest => ({ ...request, clientRoot: clientRootUntil(t) });
  const recordedHandshake = [
    handshakeCase("entry-key form, limited by the certificate", request, replyTo(request, "mcp-entry"), [CERT_NOT_AFTER, CERT_NOT_AFTER + 1]),
    handshakeCase("policy-key form, limited by the roots and keyrings", request, replyTo(request, "server-policy", {}, OLD), [LIVE_NOT_AFTER, LIVE_NOT_AFTER + 1]),
    handshakeCase("client root's notAfter", clientRootAt(NOW), replyTo(clientRootAt(NOW), "mcp-entry"), [NOW, NOW + 1]),
    handshakeCase("client keyring's notAfter", withClientRing(newRing(NOW)), replyTo(withClientRing(newRing(NOW)), "mcp-entry"), [NOW, NOW + 1]),
    handshakeCase("server root's notAfter", request, replyTo(request, "mcp-entry", { serverRoot: serverRootUntil(NOW) }), [NOW, NOW + 1]),
    handshakeCase(
      "server keyring's notAfter",
      request,
      replyTo(request, "mcp-entry", { serverKeyringSig: serverRingUntil(NOW).sig, serverKeyringNotAfter: NOW }),
      [NOW, NOW + 1],
    ),
    handshakeCase(
      "attested at all at the earliest limit",
      clientRootAt(NOW + 3),
      replyTo(clientRootAt(NOW + 3), "mcp-entry", { serverKeyringSig: serverRingUntil(NOW + 2).sig, serverKeyringNotAfter: NOW + 2 }),
      [NOW + 2, NOW + 3],
    ),
    handshakeCase("old form throughout, policy-key form", oldRequest, replyTo(oldRequest, "server-policy", { serverRoot: oldServerRoot }, OLD), [0, Number.MAX_SAFE_INTEGER]),
    handshakeCase("server root old form, entry-key form", request, replyTo(request, "mcp-entry", { serverRoot: oldServerRoot }), [CERT_NOT_AFTER, CERT_NOT_AFTER + 1]),
    handshakeCase(
      "server keyring old form, entry-key form",
      request,
      replyTo(request, "mcp-entry", { serverKeyringSig: oldServerRing.sig }, ["serverKeyringNotAfter"]),
      [CERT_NOT_AFTER, CERT_NOT_AFTER + 1],
    ),
    handshakeCase("legacy request", legacyRequest, replyTo(legacyRequest, "server-policy", {}, OLD), [NOW]),
    handshakeCase("legacy request with a keyring window", { ...legacyRequest, clientKeyringNotAfter: LIVE_NOT_AFTER }, replyTo({ ...legacyRequest, clientKeyringNotAfter: LIVE_NOT_AFTER }, "server-policy", {}, OLD), [NOW]),
    handshakeCase("unsafe", request, replyTo(request, "mcp-entry", { status: "unsafe", disabled: [TOOL] }), [NOW]),
    handshakeCase("a signed reply the client's shape check refuses", request, replyTo(request, "mcp-entry", {}, ["disabled"]), [NOW]),
    handshakeCase("another pin", request, replyTo(request, "mcp-entry"), [NOW], { pin: "client-policy" }),
    handshakeCase("the configured entry, not the reply's", request, replyTo(request, "github-tools", { serverReplyCert: certFor("github-tools", "github-tools") }), [NOW], { serverEntry: "mcp-entry" }),
    handshakeCase("configured for another entry", request, replyTo(request, "mcp-entry"), [NOW], { serverEntry: "github-tools" }),
    handshakeCase("client keyring window moved", { ...withClientRing(newRing(NOW)), clientKeyringNotAfter: LIVE_NOT_AFTER }, replyTo({ ...withClientRing(newRing(NOW)), clientKeyringNotAfter: LIVE_NOT_AFTER }, "mcp-entry"), [NOW]),
    handshakeCase("client root signed by another key", { ...request, clientRoot: newRoot(LIVE_NOT_AFTER, "server-policy") }, replyTo({ ...request, clientRoot: newRoot(LIVE_NOT_AFTER, "server-policy") }, "mcp-entry"), [NOW]),
  ];
  check("recorded handshake answers", recordedHandshake.map((c) => [c.name, c.expected.attested, c.expected.attestedAt, c.expected.legacy]), [
    ["entry-key form, limited by the certificate", true, [true, false], false],
    ["policy-key form, limited by the roots and keyrings", true, [true, false], false],
    ["client root's notAfter", true, [true, false], false],
    ["client keyring's notAfter", true, [true, false], false],
    ["server root's notAfter", true, [true, false], false],
    ["server keyring's notAfter", true, [true, false], false],
    ["attested at all at the earliest limit", true, [true, false], false],
    ["old form throughout, policy-key form", true, [true, true], false],
    ["server root old form, entry-key form", true, [true, false], false],
    ["server keyring old form, entry-key form", true, [true, false], false],
    ["legacy request", true, [true], true],
    ["legacy request with a keyring window", false, [false], false],
    ["unsafe", false, [false], false],
    ["a signed reply the client's shape check refuses", false, [false], false],
    ["another pin", false, [false], false],
    ["the configured entry, not the reply's", false, [false], false],
    ["configured for another entry", false, [false], false],
    ["client keyring window moved", false, [false], false],
    ["client root signed by another key", false, [false], false],
  ]);
  // The server signed it, so only the shape check refuses it: live it is MALFORMED_REPLY, and offline never attested.
  const shapeRefused = recordedHandshake.find((c) => c.name === "a signed reply the client's shape check refuses")!;
  check("the shape-refused reply live", checkSessionReply(shapeRefused.reply, request, keys["server-policy"].pub, "mcp-entry", NOW), "MALFORMED_REPLY");
  check("the shape-refused reply's response limit", shapeRefused.expected.responseNotAfter, LIVE_NOT_AFTER);
  check(
    "recorded handshake response limits",
    recordedHandshake.slice(0, 10).map((c) => c.expected.responseNotAfter),
    [LIVE_NOT_AFTER, LIVE_NOT_AFTER, LIVE_NOT_AFTER, LIVE_NOT_AFTER, NOW, NOW, NOW + 2, Number.MAX_SAFE_INTEGER, LIVE_NOT_AFTER, LIVE_NOT_AFTER],
  );

  // Recorded calls (verification.md §Offline verification): each call is checked by the offline verifier in the
  // session of the handshake it names, against the client keyring and root of that handshake's request and its reply's
  // session id, then limited to the session (OUTSIDE_SESSION). The calls are one record set, in order: one set of spent
  // nonce keys for them all, whatever handshakes the set holds.
  type RecordedCallInput = Omit<CaseInputs, "name" | "keyring" | "sess" | "allowedOrigins"> & {
    handshake: number;
    rid: string;
    recordedTs: { last: number };
    prompt: string;
  };
  const callIn = (reply: SessionReply, ts: number, callId: string, o: { forged?: boolean; v2?: boolean } = {}): RecordedCallInput => {
    const bind = bindMcpCall(TOOL, callId, ARGS);
    const sess = reply.sess;
    let chain: RecordedStamp[];
    if (o.v2 === true) {
      const first = signStampV2({ svc: "session", inst: "pi-1", rid: RID, ts: ts - 1000, sess, bind: bindPrompt(PROMPT), infl: "", prev: "" }, keys.session.priv);
      chain = [first, signStampV2({ svc: "pi", inst: "pi-1", rid: RID, ts, sess, bind, infl: commitInfluence(v2Influence), prev: first.sig }, keys.pi.priv)];
    } else {
      const first = v3({ ...originFields, ts: ts - 1000, sess }, "session");
      chain = [first, v3({ ...hopFields(first.sig), ts, sess, bind }, o.forged === true ? "session" : "pi")];
    }
    return {
      handshake: 0, chain, expectedBind: bind, influence: o.v2 === true ? v2Influence : INFLUENCE, policy: "client", proofRoute: CALL_ROUTE, receiver: CALL_RCV, receiverInRoute: true,
      nonceKey: `${RID}|${callId}|req`, rid: RID, recordedTs: { last: ts }, prompt: PROMPT,
    };
  };
  const recordedCallCase = (name: string, handshakes: { request: AnyRequest; reply: SessionReply }[], calls: RecordedCallInput[]) => {
    const recorded = handshakes.map((h) => ({ request: h.request, reply: h.reply, pin: "server-policy" as KeyName, serverEntry: "mcp-entry" }));
    const sessions = recorded.map((h) => recordedSession({ ...h, pin: keys[h.pin].pub }));
    const records = newRecordSet();
    const expected = calls.map((c) => {
      const h = recorded[c.handshake]!;
      const clientRoot = h.request.clientRoot!;
      const v = verifyChainOffline(
        { stamps: c.chain, expectedBind: c.expectedBind, influence: c.influence, proof: c.proofRoute === null ? null : policies[c.policy].proofs[c.proofRoute]!, receiver: c.receiver, receiverInRoute: c.receiverInRoute, rid: c.rid, recordedTs: c.recordedTs, prompt: c.prompt },
        {
          keyring: h.request.clientKeyring, root: decode(clientRoot.root), rootId: clientRoot.rootId, allowedOrigins: ["session"], sess: h.reply.sess,
          nonceKey: c.nonceKey, seen: records.spent, callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS,
        },
      );
      const reason = callInSession(sessions[c.handshake]!, v.reason, c.recordedTs.last);
      if (reason === undefined) throw new Error(`recorded call ${name}: its session is not attested`);
      return { reason, legacy: reason === "OK" && v.legacy };
    });
    return { name, handshakes: recorded, allowedOrigins: ["session"], callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS, calls, expected };
  };
  const entryKeyReply = replyTo(request, "mcp-entry");
  const shortRoot = clientRootAt(NOW);
  const shortRootReply = replyTo(shortRoot, "mcp-entry");
  const legacyReply = replyTo(legacyRequest, "server-policy", {}, OLD);
  const inSession = { request, reply: entryKeyReply };
  const recordedCall = [
    recordedCallCase("at the certificate's notAfter", [inSession], [callIn(entryKeyReply, CERT_NOT_AFTER, "call-1")]),
    recordedCallCase("past the certificate's notAfter", [inSession], [callIn(entryKeyReply, CERT_NOT_AFTER + 1, "call-1")]),
    recordedCallCase("past the client root's notAfter", [{ request: shortRoot, reply: shortRootReply }], [callIn(shortRootReply, NOW, "call-1"), callIn(shortRootReply, NOW + 1, "call-2")]),
    recordedCallCase("a failing call keeps its result past the limit", [{ request: shortRoot, reply: shortRootReply }], [callIn(shortRootReply, NOW + 1, "call-1", { forged: true })]),
    recordedCallCase("replay in the record set", [inSession], [callIn(entryKeyReply, NOW, "call-1"), callIn(entryKeyReply, NOW + 60_000, "call-1")]),
    recordedCallCase("a repeated handshake resets no spent key", [inSession, inSession], [callIn(entryKeyReply, NOW, "call-1"), { ...callIn(entryKeyReply, NOW, "call-1"), handshake: 1 }]),
    recordedCallCase("legacy v2 call in a legacy session", [{ request: legacyRequest, reply: legacyReply }], [callIn(legacyReply, NOW, "call-1", { v2: true })]),
  ];
  check("recorded call answers", recordedCall.map((c) => [c.name, c.expected]), [
    ["at the certificate's notAfter", [{ reason: "OK", legacy: false }]],
    ["past the certificate's notAfter", [{ reason: "OUTSIDE_SESSION", legacy: false }]],
    ["past the client root's notAfter", [{ reason: "OK", legacy: false }, { reason: "OUTSIDE_SESSION", legacy: false }]],
    ["a failing call keeps its result past the limit", [{ reason: "BAD_SIGNATURE", legacy: false }]],
    ["replay in the record set", [{ reason: "OK", legacy: false }, { reason: "REPLAY", legacy: false }]],
    ["a repeated handshake resets no spent key", [{ reason: "OK", legacy: false }, { reason: "REPLAY", legacy: false }]],
    ["legacy v2 call in a legacy session", [{ reason: "OK", legacy: true }]],
  ]);

  // Recorded local steps (MCP profile): the client's own steps, checked against its keyring and root and its signed
  // local rules, then POLICY_EXPIRED, PROOF_MISMATCH, RULES_MISMATCH and VERDICT_MISMATCH.
  const LOCAL_RULES: LocalRules = parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read"] }], programs: [] });
  const OTHER_RULES: LocalRules = parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read"] }, { path: "out", access: ["write"], destination: "public" }], programs: [] });
  const READ_NOTES: Resolved = { paths: [{ need: "read", at: "notes.md" }], programs: [], parse: "ok", readOnly: true };
  const READ_OUTSIDE: Resolved = { paths: [{ need: "read", at: "outside" }], programs: [], parse: "ok", readOnly: true };
  const NOTHING: Resolved = { paths: [], programs: [], parse: "ok", readOnly: false };
  const LOCAL_SIGNERS = { svcs: ["session", "pi"], inst: "pi-1" };
  const STEP_TS = NOW - 1000;
  type LocalDecision = { tool: string; callId: string; input: Record<string, unknown>; resolved: Resolved; verdict: LocalVerdict; routeAllowed: boolean; rulesHash: string | null };
  type LocalClient = { keyring: Record<string, KeyName>; policy: "client"; rootNotAfter?: number; keyringNotAfter?: number; rules: LocalRules | null };
  const localStepCase = (
    name: string,
    d: Partial<LocalDecision> = {},
    o: { client?: Partial<LocalClient>; proofRoute?: string | null; seen?: string[]; v2?: boolean } = {},
  ) => {
    const decision: LocalDecision = { tool: "read", callId: "tc-1", input: { path: "notes.md" }, resolved: READ_NOTES, verdict: "OK", routeAllowed: true, rulesHash: rulesHash(LOCAL_RULES), ...d };
    const client: LocalClient = { keyring: { session: "session", pi: "pi" }, policy: "client", rules: LOCAL_RULES, ...o.client };
    let chain: RecordedStamp[];
    if (o.v2 === true) {
      const first = signStampV2({ svc: "session", inst: "pi-1", rid: RID, ts: NOW - 2000, sess: "", bind: bindPrompt(PROMPT), infl: "", prev: "" }, keys.session.priv);
      const bind = localStepBind({ toolName: decision.tool, toolCallId: decision.callId, input: decision.input, resolved: decision.resolved, verdict: decision.verdict, listed: decision.routeAllowed, rulesHash: decision.rulesHash });
      chain = [first, signStampV2({ svc: "pi", inst: "pi-1", rid: RID, ts: STEP_TS, sess: "", bind, infl: commitInfluence(INFLUENCE), prev: first.sig }, keys.pi.priv)];
    } else {
      const first = localOrigin;
      chain = [
        first,
        stampLocalStep(
          {
            svc: "pi", inst: "pi-1", rid: RID, ts: STEP_TS, prev: first.sig, toolName: decision.tool, toolCallId: decision.callId, input: decision.input,
            resolved: decision.resolved, verdict: decision.verdict, listed: decision.routeAllowed, rulesHash: decision.rulesHash, influence: INFLUENCE,
          },
          keys.pi.priv,
        ),
      ];
    }
    const proofRoute = Object.hasOwn(o, "proofRoute") ? o.proofRoute! : decision.routeAllowed ? routeOf(["session", "pi", localReceiver(decision.tool)]) : null;
    const step = { ...decision, rid: RID, now: STEP_TS, chain, proofRoute, influence: INFLUENCE };
    const run = { prompt: PROMPT, ts: [localOrigin.ts] };
    const seen = o.seen ?? [];
    const result = verifyRecordedLocalStep(
      { ...step, proof: proofRoute === null ? null : policies.client.proofs[proofRoute]! },
      {
        client: {
          keyring: resolveKeyring(client.keyring), root: rootOf(client.policy), rootId: policies[client.policy].rootId,
          ...(client.rootNotAfter === undefined ? {} : { rootNotAfter: client.rootNotAfter }),
          ...(client.keyringNotAfter === undefined ? {} : { keyringNotAfter: client.keyringNotAfter }),
          rules: client.rules,
        },
        signers: LOCAL_SIGNERS,
        run: { prompt: run.prompt, ts: new Set(run.ts) },
        seen: new Set(seen),
      },
    );
    return { name, client, signers: LOCAL_SIGNERS, step, run, seen, expected: { reason: result.reason, verdict: result.verdict ?? null, legacy: result.legacy } };
  };
  const recordedLocalStep = [
    localStepCase("allowed"),
    localStepCase("refused by the rules", { input: { path: "/etc/passwd" }, resolved: READ_OUTSIDE, verdict: "SCOPE_DENIED" }),
    localStepCase("unlisted tool", { tool: "bash", input: { command: "ls" }, resolved: NOTHING, verdict: "PATH_NOT_ALLOWED", routeAllowed: false }),
    localStepCase("no rules", { resolved: NOTHING, verdict: "SCOPE_DENIED", rulesHash: null }, { client: { rules: null } }),
    localStepCase("at the client root's notAfter", {}, { client: { rootNotAfter: STEP_TS } }),
    localStepCase("client root expired", {}, { client: { rootNotAfter: STEP_TS - 1 } }),
    localStepCase("client keyring expired", {}, { client: { keyringNotAfter: STEP_TS - 1 } }),
    localStepCase("client root expired, bad signature first", {}, { client: { rootNotAfter: STEP_TS - 1, keyring: { session: "session", pi: "gateway" } } }),
    localStepCase("listed but not proven", {}, { proofRoute: CALL_ROUTE }),
    localStepCase("proven but recorded as not listed", { resolved: NOTHING, verdict: "PATH_NOT_ALLOWED", routeAllowed: false }, { proofRoute: LOCAL_ROUTE }),
    localStepCase("expired before the proof", { resolved: NOTHING, verdict: "PATH_NOT_ALLOWED", routeAllowed: false }, { proofRoute: LOCAL_ROUTE, client: { rootNotAfter: STEP_TS - 1 } }),
    localStepCase("rules hash not the client's", { rulesHash: rulesHash(OTHER_RULES) }),
    localStepCase("verdict not the rules'", { input: { path: "/etc/passwd" }, resolved: READ_OUTSIDE, verdict: "OK" }),
    localStepCase("verdict not the rules', unlisted tool resolving something", { tool: "bash", input: { command: "cat notes.md" }, resolved: READ_NOTES, verdict: "PATH_NOT_ALLOWED", routeAllowed: false }),
    localStepCase("rules mismatch before verdict mismatch", { rulesHash: null, verdict: "SCOPE_DENIED" }),
    localStepCase("replay in the record set", {}, { seen: [`${RID}|tc-1|local`] }),
    localStepCase("legacy v2 step", {}, { v2: true }),
  ];
  check("recorded local step answers", recordedLocalStep.map((c) => [c.name, c.expected.reason, c.expected.verdict, c.expected.legacy]), [
    ["allowed", "OK", "OK", false],
    ["refused by the rules", "OK", "SCOPE_DENIED", false],
    ["unlisted tool", "OK", "PATH_NOT_ALLOWED", false],
    ["no rules", "OK", "SCOPE_DENIED", false],
    ["at the client root's notAfter", "OK", "OK", false],
    ["client root expired", "POLICY_EXPIRED", null, false],
    ["client keyring expired", "POLICY_EXPIRED", null, false],
    ["client root expired, bad signature first", "BAD_SIGNATURE", null, false],
    ["listed but not proven", "PROOF_MISMATCH", null, false],
    ["proven but recorded as not listed", "PROOF_MISMATCH", null, false],
    ["expired before the proof", "POLICY_EXPIRED", null, false],
    ["rules hash not the client's", "RULES_MISMATCH", null, false],
    ["verdict not the rules'", "VERDICT_MISMATCH", null, false],
    ["verdict not the rules', unlisted tool resolving something", "VERDICT_MISMATCH", null, false],
    ["rules mismatch before verdict mismatch", "RULES_MISMATCH", null, false],
    ["replay in the record set", "REPLAY", null, false],
    ["legacy v2 step", "OK", "OK", true],
  ]);

  return {
    about: ABOUT,
    keys,
    policies,
    signingBytesV3: signingBytesCases,
    signatures,
    influence: influenceCases,
    rule,
    keyring,
    root: signedRoots,
    verify,
    offline,
    recordedHandshake,
    recordedCall,
    recordedLocalStep,
    replyCert,
    sessionReply,
    sessionStatus: sessionStatusCases,
  };
}

/**
 * v3.json's text: the built vectors as JSON, except that the BY_VALUE cases' notAfter is written
 * `1798761600000.0`, which JSON.stringify would print as plain digits, so each reader's by-value reading is tested.
 */
export function vectorsV3Text(): string {
  const vectors = buildVectorsV3();
  let text = JSON.stringify(vectors, null, 2) + "\n";
  for (const [section, name] of Object.entries(BY_VALUE)) {
    const at = text.indexOf(`"name": ${JSON.stringify(name)}`, text.indexOf(`\n  "${section}": [`));
    // the signed object's last member, so the digits end the line
    const from = `"notAfter": ${POLICY_NOT_AFTER}\n`;
    const window = text.indexOf(from, at);
    const next = text.indexOf('"name": ', at + 1);
    if (at < 0 || window < 0 || (next >= 0 && next < window)) throw new Error(`no notAfter in the ${section} case ${name}`);
    text = text.slice(0, window) + `"notAfter": ${POLICY_NOT_AFTER}.0\n` + text.slice(window + from.length);
  }
  // JSON.stringify prints −2^63 as -9223372036854776000; the file spells it exactly, so a 64-bit reader meets the long
  // it could take it for
  const at = text.indexOf(`"name": ${JSON.stringify(TS_MIN_CASE)}`);
  const printed = `"ts": ${JSON.stringify(-(2 ** 63))},`;
  const ts = text.indexOf(printed, at);
  const next = text.indexOf('"name": ', at + 1);
  if (at < 0 || ts < 0 || (next >= 0 && next < ts)) throw new Error(`no ts in the verify case ${TS_MIN_CASE}`);
  text = text.slice(0, ts) + `"ts": ${TS_MIN_TEXT},` + text.slice(ts + printed.length);
  check("v3.json text", JSON.parse(text), vectors);
  return text;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url) && process.argv.includes("--write")) {
  writeFileSync(V3_JSON, vectorsV3Text());
}
