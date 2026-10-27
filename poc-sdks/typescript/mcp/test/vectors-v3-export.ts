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
  commitInfluence, concat, decode, deriveRootId, encode, keyPairMatches, keyringSigningBytes, leafHash, localReceiver, nodeHash,
  normalizeInfluence, provesPath, publicWriteRefused, routeOf, sha256, sign, signKeyring, signStampV2, signStampV3, signingBytesV3,
  utf8, verifyChainOffline, verifyChainV3, verifyKeyring,
} from "@paztport/core";
import type { InfluenceEntry, InfluenceFact, MerkleProof, Peer, RecordedStamp, StampV3 } from "@paztport/core";
import { bindMcpCall, mcpReceiver } from "../src/index.ts";

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

  // Influence: normalized forms written by hand; the "no owners" commitment is v2's.
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
  const keyring = [signedKeyring, keyringCase("tampered", { session: "session", pi: "gateway" }, signedKeyring.sig, false)];

  return {
    about: ABOUT,
    keys,
    policies,
    signingBytesV3: signingBytesCases,
    signatures,
    influence: influenceCases,
    rule,
    keyring,
    verify,
    offline,
  };
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url) && process.argv.includes("--write")) {
  writeFileSync(V3_JSON, JSON.stringify(buildVectorsV3(), null, 2) + "\n");
}
