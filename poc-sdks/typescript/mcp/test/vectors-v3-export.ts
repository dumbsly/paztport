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
  normalizeInfluence, provesPath, publicWriteRefused, routeOf, sha256, sign, signKeyring, signStampV2, signStampV3, signingBytesV3,
  utf8, verifyChainOffline, verifyChainV3, verifyKeyring, issueReplyCert, replyCertSigningBytes, verifyReplyCert,
  deriveSessionId, isCurrent, renewRoot, rootSigningBytes, signRoot, signSessionReply, verifyRoot,
} from "@paztport/core";
import type {
  InfluenceEntry, InfluenceFact, MerkleProof, Peer, RecordedStamp, ReplyCert, SessionReply, SessionRequest, SignedKeyring, SignedRoot, StampV3,
} from "@paztport/core";
import { bindMcpCall, classifySessionReply, mcpReceiver } from "../src/index.ts";

const V3_JSON = new URL("../../../spec/vectors/v3.json", import.meta.url);
const V2_JSON = new URL("../../../spec/vectors/v2.json", import.meta.url);

const KEY_NAMES = ["session", "pi", "mcp-entry", "github-tools", "gateway", "orders", "client-policy", "server-policy"] as const;
type KeyName = (typeof KEY_NAMES)[number];
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";
const DEPTH = 8;

const ABOUT =
  "Paztport v3 conformance vectors. Every case carries all of its inputs; keys and policies are named and defined in this file. " +
  `Each key's private key is the PKCS#8 DER ${PKCS8_ED25519_PREFIX} || seed, where seed = SHA-256(utf8("paztport-v3-vector-key:" + name)), ` +
  "and its public key is the SPKI DER export; both are base64url. " +
  `Each Merkle leaf salt is the first ${SALT_BYTES} bytes of SHA-256(utf8("paztport-v3-vector-salt:" + route)), and the policy's routes fill the ` +
  'first leaves in order; padding leaf i is SHA-256(utf8("paztport-v3-vector-pad:" + rootId + ":" + i)). ' +
  "This placement and rootId derivation are for the vectors only; real builds use random slots and a random rootId. " +
  "Ed25519 is deterministic, so the file is reproduced byte for byte. " +
  "A verify case runs the live verifier `uses` times against one nonce cache of nonceTtlMs and expects the last result. " +
  "An offline case runs the offline verifier once: `recordedTs.last` is the recorded time of the last stamp, `rid` the record's rid, " +
  "`prompt` the run's recorded prompt, and callMaxAgeMs and runMaxAgeMs the age limits; there is no peer, clock or nonce TTL, and `seen` " +
  "is the set of nonce keys already spent in the record set. A policy's proof is looked up by `proofRoute` (null: no proof). " +
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

  type Live = CaseInputs & { peer: Peer | null; uses: number };
  const live = (c: Live, expected: Expected) => {
    const nonces = new NonceCache(NONCE_TTL_MS);
    const cfg = {
      keyring: resolveKeyring(c.keyring), root: rootOf(c.policy), rootId: policies[c.policy].rootId, allowedOrigins: c.allowedOrigins,
      sess: c.sess, nonces, nonceKey: c.nonceKey, now: NOW, callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS,
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
      now: NOW, callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS, nonceTtlMs: NONCE_TTL_MS, uses, expected,
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

  // The client keyring, signed by its policy key, and a copy with pi's key swapped.
  const keyringCase = (name: string, services: Record<string, KeyName>, sig: string | undefined, verifies: boolean) => {
    const resolved = resolveKeyring(services);
    const signed = sig === undefined ? signKeyring(resolved, keys["client-policy"].pub, keys["client-policy"].priv) : { policy: keys["client-policy"].pub, services: resolved, sig };
    check(`keyring ${name}`, verifyKeyring(signed, keys["client-policy"].pub), verifies);
    return { name, policyKey: "client-policy", services, signingBytes: encode(keyringSigningBytes(signed.policy, signed.services)), sig: signed.sig, signed, verifies };
  };
  const signedKeyring = keyringCase("signed", { session: "session", pi: "pi" }, undefined, true);
  const keyring: Record<string, unknown>[] = [signedKeyring, keyringCase("tampered", { session: "session", pi: "gateway" }, signedKeyring.sig, false)];

  // The two forms of what the policy key signs offline. The new form carries notAfter, and its signed bytes
  // include it; the old form has none, still verifies for recorded evidence, and is never current. A case's
  // form is decided by whether `signed` has a notAfter member. signingBytes is null when that notAfter is not
  // an integer in [0, 2^53 - 1], which nothing signs; `current` gives isCurrent's answer at each `at`.
  const POLICY_NOT_AFTER = 1_798_761_600_000;
  const DAY_MS = 86_400_000;
  const hasWindow = (o: object): o is { notAfter: unknown } => Object.hasOwn(o, "notAfter");
  const windowOk = (n: unknown): n is number => Number.isSafeInteger(n) && (n as number) >= 0;
  const currentAt = (o: object, ats: number[]) => ats.map((at) => ({ at, current: isCurrent(o, at) }));
  const ringServices = { session: "session", pi: "pi" } as const;
  const ringPolicy = keys["client-policy"].pub;
  const newRing = (notAfter: number) => signKeyring(resolveKeyring(ringServices), ringPolicy, keys["client-policy"].priv, notAfter);
  const oldRing = signKeyring(resolveKeyring(ringServices), ringPolicy, keys["client-policy"].priv);
  const rootPolicy = policies.client;
  const newRoot = (notAfter: number, signer: KeyName = "client-policy") => signRoot(decode(rootPolicy.root), rootPolicy.rootId, keys[signer].priv, notAfter);
  const oldRoot = signRoot(decode(rootPolicy.root), rootPolicy.rootId, keys["client-policy"].priv);
  const keyringFormCase = (name: string, signed: SignedKeyring, verifies: boolean, ats?: number[]) => {
    check(`keyring ${name}`, verifyKeyring(signed, ringPolicy), verifies);
    const w = hasWindow(signed);
    const bytes = !w ? keyringSigningBytes(signed.policy, signed.services) : windowOk(signed.notAfter) ? keyringSigningBytes(signed.policy, signed.services, signed.notAfter) : null;
    if (verifies) check(`keyring ${name} re-signed`, signKeyring(signed.services, signed.policy, keys["client-policy"].priv, w ? signed.notAfter : undefined).sig, signed.sig);
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
  );

  // The client policy's signed root in both forms, under the client-policy pin; `policy` names the tree.
  const rootCase = (name: string, signed: SignedRoot, verifies: boolean, ats?: number[]) => {
    check(`root ${name}`, verifyRoot(signed, keys["client-policy"].pub), verifies);
    const w = hasWindow(signed);
    const bytes = !w ? rootSigningBytes(signed.rootId, signed.root) : windowOk(signed.notAfter) ? rootSigningBytes(signed.rootId, signed.root, signed.notAfter) : null;
    if (verifies) check(`root ${name} re-signed`, signRoot(decode(signed.root), signed.rootId, keys["client-policy"].priv, w ? signed.notAfter : undefined).sig, signed.sig);
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
  // certificate and the signed server keyring, the policy-key ("old") form, and forms that must fail.
  const nonce16 = (label: string) => encode(sha256(utf8("paztport-v3-vector-nonce:" + label)).slice(0, 16));
  const clientRoot = signRoot(decode(policies.client.root), policies.client.rootId, keys["client-policy"].priv);
  const request: SessionRequest = {
    clientRoot, clientPolicyKey: keys["client-policy"].pub, clientKeyring: signedKeyring.signed.services,
    clientKeyringSig: signedKeyring.sig, nonce: nonce16("client"),
  };
  const SERVER_NONCE = nonce16("server");
  const serverRoot = signRoot(decode(policies.server.root), policies.server.rootId, keys["server-policy"].priv);
  const serverRing = signKeyring(resolveKeyring({ "mcp-entry": "mcp-entry", "github-tools": "github-tools" }), keys["server-policy"].pub, keys["server-policy"].priv);
  const certFor = (svc: string, key: KeyName, signer: KeyName = "server-policy") =>
    issueReplyCert(keys["server-policy"].pub, svc, keys[key].pub, CERT_NOT_AFTER, keys[signer].priv);
  const entryCert = certFor("mcp-entry", "mcp-entry");
  const sessFor = (root: { sig: string } | null) => deriveSessionId(clientRoot.sig, root?.sig ?? null, request.nonce, SERVER_NONCE, request);
  /** A reply in the entry-key form by default; `drop` leaves fields out, and `signer` signs it. */
  const reply = (signer: KeyName, o: Record<string, unknown> = {}, drop: string[] = []): Record<string, unknown> => {
    const root = (o.serverRoot ?? serverRoot) as { sig: string };
    const body: Record<string, unknown> = {
      serverRoot: root, serverPolicyKey: keys["server-policy"].pub, serverKeyring: serverRing.services, serverKeyringSig: serverRing.sig,
      serverReplyCert: entryCert, nonce: SERVER_NONCE, sess: sessFor(root), status: "attested", disabled: [], ...o,
    };
    for (const f of drop) delete body[f];
    return signSessionReply(body as unknown as Omit<SessionReply, "sig">, keys[signer].priv) as unknown as Record<string, unknown>;
  };
  const OLD = ["serverKeyringSig", "serverReplyCert"];
  const sessionReplyCase = (name: string, raw: Record<string, unknown>, expected: string, o: { pin?: KeyName; serverEntry?: string; now?: number } = {}) => {
    const pin = o.pin ?? "server-policy";
    const serverEntry = o.serverEntry ?? "mcp-entry";
    const now = o.now ?? NOW;
    const outcome = classifySessionReply(raw, request, keys[pin].pub, serverEntry, now);
    check(`session reply ${name}`, outcome.status === "attested" ? "ATTESTED" : outcome.reason, expected);
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
      reply("mcp-entry", { serverKeyringSig: encode(sign(keys["client-policy"].priv, keyringSigningBytes(keys["server-policy"].pub, serverRing.services))) }),
      "BAD_SIGNATURE",
    ),
    sessionReplyCase(
      "entry absent from keyring",
      (() => {
        const ring = signKeyring(resolveKeyring({ "github-tools": "github-tools" }), keys["server-policy"].pub, keys["server-policy"].priv);
        return reply("mcp-entry", { serverKeyring: ring.services, serverKeyringSig: ring.sig });
      })(),
      "BAD_SIGNATURE",
    ),
    sessionReplyCase("keyring signature without certificate", reply("mcp-entry", {}, ["serverReplyCert"]), "BAD_SIGNATURE"),
    sessionReplyCase("certificate without keyring signature", reply("mcp-entry", {}, ["serverKeyringSig"]), "BAD_SIGNATURE"),
    // The form is decided by which fields are present, never by which key verifies.
    sessionReplyCase("keyring signature without certificate, signed by the policy key", reply("server-policy", {}, ["serverReplyCert"]), "BAD_SIGNATURE"),
    sessionReplyCase("certificate without keyring signature, signed by the policy key", reply("server-policy", {}, ["serverKeyringSig"]), "BAD_SIGNATURE"),
    sessionReplyCase("neither field, signed by the keyring's entry key", reply("orders", { serverKeyring: attackerRing }, OLD), "BAD_SIGNATURE"),
    sessionReplyCase("server root signed by the entry key", reply("mcp-entry", { serverRoot: signRoot(decode(policies.server.root), policies.server.rootId, keys["mcp-entry"].priv) }), "BAD_SIGNATURE"),
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
  ];

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
    replyCert,
    sessionReply,
  };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url) && process.argv.includes("--write")) {
  writeFileSync(V3_JSON, JSON.stringify(buildVectorsV3(), null, 2) + "\n");
}
