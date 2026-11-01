// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Builds spec/vectors/v3.json, the v3 conformance vectors, as a pure function of fixed seeds; run with
// `--write` from poc-sdks/typescript to write the file. Every case is checked against the library first, and
// the export throws on any mismatch, so it can never record a wrong answer.

import { createPrivateKey, createPublicKey } from "node:crypto";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import {
  CALL_MAX_AGE_MS, NONCE_TTL_MS, NonceCache, RUN_MAX_AGE_MS, SALT_BYTES, bindLocalTool, buildTree, bindPrompt, bindResponse, bindResult,
  canonicalize, commitInfluence, concat, decode, encode, keyPairMatches, keyringSigningBytes, leafHash, localReceiver, nodeHash,
  printFile, readKeyringFile, readReplyCertFile, readRootFile,
  normalizeInfluence, provesPath, publicWriteRefused, routeOf, sha256, sign, signKeyring, signStampV3, signingBytesV3,
  writeToken,
  utf8, verifyChainOffline, verifyChainV3, verifyKeyring, signReplyCert, replyCertSigningBytes, verifyReplyCert,
  checkSessionReply, readProof, readSessionRequest, deriveSessionId, encodeProof, isCurrent, isNotAfter,
  signRenewedRoot, rootSigningBytes, sessionStatus, signRoot, verifyRoot,
  callInSession, newRecordSet, parseLocalRules, recordedSession, rulesHash, stampLocalStep, localStepBind, verifyRecordedLocalStep,
  verifyResponse,
} from "@paztport/core";
import type {
  InfluenceEntry, InfluenceFact, JsonValue, LocalRules, LocalVerdict, MerkleProof, Peer, ReplyCert, Resolved,
  SessionReply, SessionRequest,
  SignedKeyring, SignedRoot, StampV3,
} from "@paztport/core";
import { bindMcpCall, mcpReceiver } from "../src/index.ts";

const V3_JSON = new URL("../../../spec/vectors/v3.json", import.meta.url);

const KEY_NAMES = ["session", "pi", "mcp-entry", "github-tools", "gateway", "orders", "client-policy", "server-policy"] as const;
type KeyName = (typeof KEY_NAMES)[number];
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";
/** The keyring and root cases' fixed notAfter: 2027-01-01, as the Java tests use. */
const POLICY_NOT_AFTER = 1_798_761_600_000;
/** The keyring and root case whose `file` writes its notAfter `1798761600000.0`, the integer its signature is over. */
const FRACTION_CASE = "notAfter written 1798761600000.0";
const DEPTH = 8;
/** The verify case whose last stamp's ts is −2^63, which the file writes exactly (see vectorsV3Text). */
const TS_MIN_CASE = "stamp ts of -2^63";
const TS_MIN_TEXT = "-9223372036854775808";
/** The responseAttestation case whose token spells the attestation's members in wire order, which JCS cannot write. */
const WIRE_ORDER_CASE = "an attestation in wire member order";

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
  "A sessionRequest case is a request as received, its bytes in `requestToken`, read by the server: " +
  "`expected` is OK for a well-formed request and MALFORMED for one it refuses " +
  "(JSON-RPC -32602, HTTP 400 INVALID_PARAMS). " +
  "The sections after sessionRequest pin the primitives the cases above rely on, each with its inputs: fixedInputs are `length` consecutive bytes from `start`, base64url, " +
  "which deriveSessionId's cases name; the prompt, result, response and tools/call bindings; the influence commitment; " +
  "and merkle, a tree of its own (depth 8, rootId merkle-vector) whose leaf hashes, node, root, proofs and proof headers (the base64url of each proof's JCS bytes) are recorded as the library computes them, and whose padding hashes are recorded as given, not derived. " +
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

type Policy = {
  routes: string[];
  depth: number;
  rootId: string;
  root: string;
  proofs: Record<string, MerkleProof>;
  /** Each proof's token, as a case that names its route receives it. */
  proofTokens: Record<string, string>;
};

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
  const proofTokens = Object.fromEntries(routes.map((route) => [route, writeToken(proofs[route]!)]));
  return { routes, depth: DEPTH, rootId, root: encode(root), proofs, proofTokens };
}

function check(what: string, got: unknown, want: unknown): void {
  if (!isDeepStrictEqual(got, want)) {
    throw new Error(`${what}: the library gives ${JSON.stringify(got)}, the vector says ${JSON.stringify(want)}`);
  }
}

/** The token a case carries for a value it says was received: the base64url of the value's JCS bytes. */
const tokenOf = (value: unknown): string => encode(utf8(canonicalize(value)));

/**
 * A verify or offline case's chain token: tokenOf the chain, except in TS_MIN_CASE, whose bytes spell its ts exactly,
 * as the readable chain does, where JCS would write −2^63 as -9223372036854776000.
 */
function chainTokenOf(name: string, chain: unknown): string {
  if (name !== TS_MIN_CASE) return tokenOf(chain);
  const jcs = `"ts":${String(-(2 ** 63))}`;
  const text = canonicalize(chain);
  if (text.split(jcs).length !== 2) throw new Error(`no ts in the chain of ${TS_MIN_CASE}`);
  return encode(utf8(text.replace(jcs, `"ts":${TS_MIN_TEXT}`)));
}

type Attestation = { chain: unknown; proof: unknown; labels: unknown; resultHash: string };

/** The token of an attestation whose members are in wire order (chain, proof, labels, resultHash), not JCS order. */
function wireOrderAttestationToken(att: Attestation): string {
  return encode(
    utf8(
      `{"chain":${canonicalize(att.chain)},"proof":${canonicalize(att.proof)},"labels":${canonicalize(att.labels)},` +
        `"resultHash":${canonicalize(att.resultHash)}}`,
    ),
  );
}

/**
 * A case's file text: printFile of its value, except where the value's notAfter is not a protocol integer (1.5, 2^53),
 * which printFile refuses, or the case is FRACTION_CASE. Then it is the value's file with notAfter printed as 0, and
 * that number's own text put in its place.
 */
function fileOf(name: unknown, value: object): string {
  const n = (value as { notAfter?: unknown }).notAfter;
  const own = name === FRACTION_CASE ? `${String(n)}.0` : n !== undefined && !isNotAfter(n) ? String(n) : undefined;
  if (own === undefined) return printFile(value as JsonValue);
  const zero = printFile({ ...value, notAfter: 0 } as JsonValue);
  if (zero.split('"notAfter": 0').length !== 2) throw new Error(`no notAfter in the file of ${String(name)}`);
  return zero.replace('"notAfter": 0', `"notAfter": ${own}`);
}

/** What `read` gives, or undefined for a file its reader refuses. */
function readOr<T>(read: () => T): T | undefined {
  try {
    return read();
  } catch {
    return undefined;
  }
}

/**
 * Every token in the vectors is tokenOf its readable sibling, `<m>Token` of `<m>` and `proofTokens` of `proofs`,
 * except the chain token TS_MIN_CASE crafts, which holds the ts exactly, and the attestation token WIRE_ORDER_CASE
 * crafts, which writes the members in wire order. Every file is fileOf its readable sibling: a keyring's or root's
 * `signed`, a certificate's `cert`, and a session status case's `serverRoot` and `serverKeyring`.
 */
function checkTokens(value: unknown, path = ""): void {
  if (Array.isArray(value)) {
    value.forEach((item, i) => checkTokens(item, `${path}[${i}]`));
    return;
  }
  if (typeof value !== "object" || value === null) return;
  const o = value as Record<string, unknown>;
  for (const [k, v] of Object.entries(o)) {
    const at = `${path}.${k}`;
    if (k.endsWith("Token") && Object.hasOwn(o, k.slice(0, -5))) {
      if (o.name === WIRE_ORDER_CASE && k === "attestationToken") {
        check(`${at} is the wire-order token of its value`, v, wireOrderAttestationToken(o.attestation as Attestation));
      } else if (o.name === TS_MIN_CASE && k === "chainToken") {
        const text = Buffer.from(decode(v as string)).toString("utf8");
        check(`${at} spells its ts exactly`, text.includes(`"ts":${TS_MIN_TEXT},`), true);
      } else {
        check(`${at} is the token of its value`, v, tokenOf(o[k.slice(0, -5)]));
      }
    } else if (k === "decisionToken") {
      const { callId, resolved, verdict, routeAllowed, rulesHash } = o;
      check(`${at} is the token of its decision`, v, tokenOf({ callId, resolved, verdict, routeAllowed, rulesHash }));
    } else if (k === "file") {
      check(`${at} is the file of its value`, v, fileOf(o.name, (o.signed ?? o.cert) as object));
    } else if (k === "serverRootFile" || k === "serverKeyringFile") {
      check(`${at} is the file of its value`, v, fileOf(o.name, o[k.slice(0, -4)] as object));
    } else if (k === "proofTokens") {
      for (const [route, t] of Object.entries(v as Record<string, string>)) {
        check(`${at}.${route} is the token of its proof`, t, tokenOf((o.proofs as Record<string, unknown>)[route]));
      }
    }
    checkTokens(v, at);
  }
}

const fixedBytes = (start: number, length: number) => Uint8Array.from({ length }, (_, i) => start + i);

/** The inputs of the sections that bind no keys: the session id, the prompt, result, response and `tools/call` bindings, and the influence commitment. */
const FIXED_INPUTS = {
  clientRootSig: { start: 1, length: 64 },
  serverRootSig: { start: 65, length: 64 },
  clientNonce: { start: 160, length: 16 },
  serverNonce: { start: 176, length: 16 },
};
const SESSION_ID_KEYS = { clientPolicyKey: "client-policy-key", clientKeyring: { session: "harness-key", pi: "harness-key" } };
const SESSION_ID_CASES = [
  { name: "both roots", clientRootSig: "clientRootSig", serverRootSig: "serverRootSig" },
  { name: "client root null", clientRootSig: null, serverRootSig: "serverRootSig" },
  { name: "server root null", clientRootSig: "clientRootSig", serverRootSig: null },
] as const;
const PROMPT = "open a PR for issue #42";
const RESPONSE = {
  resultHash: "result-hash", callId: "call-1", labels: [{ cls: "third-party", cid: "cid-1" }, { cls: "private", cid: "cid-2" }],
};
const RESULT = { content: [{ type: "text", text: "hi" }], isError: false, _meta: { x: 1 } };
const MCP_CALL = { tool: "create_pull_request", callId: "call-1", args: { title: "t", body: "b", draft: false, n: [1, 2.5] } };
const COMMIT_INFLUENCE = {
  entries: [
    { cls: "third-party", src: "web:example.com", h: "h2" },
    { cls: "private", src: "file:notes.md", h: "h1", cid: "cid-1" },
    { cls: "public", src: "web:docs.example.org", h: "h3" },
  ],
};

/**
 * The Merkle section's tree: depth 8, three leaves in slots 0 to 2 and opaque padding elsewhere. Slot 3's padding hash and
 * the padding subtree hashes above level 1 (one per level 2 to 7) are recorded as they are, since the padding is not derived.
 */
const MERKLE = {
  rootId: "merkle-vector",
  depth: 8,
  leaves: [
    { salt: "-72t5JB2o5-0_DBVICoNQg", path: "gateway/orders/payment" },
    { salt: "ujLZXNGXFps4j4nU0wX2Yw", path: "gateway/orders" },
    { salt: "izKXq4MjEbVHm7fWohfcuA", path: "gateway/search" },
  ],
  padSlot3: "WNvdj6tvsMs2Jb8wPRXSqllJVXM5Zze7N1X_flvMOaY",
  paddingAbove: [
    "X06nacS-ouvnBG6KnPfT2pJc-Mj2t_abv_cMQyLyv-M", "olRUm8Cy7HiRHy8L4sV--BhtR4rqYEDgEzikzD3oHVs", "Pd_M0oMDh2waooX3WuTZvRXzCn65rFu3mBMDV50-3gk",
    "sSQiqDmBAYLdZsjjdFGBcAfrr7GTBIdyf-JYjzifhhA", "iJH4gNbjMmaFIrADBEO2WHDKNFM7YXeaR6Kp-X_NLMw", "Jwd3p1rdO_wwDGnhA7RAz-9hncnnPwDTs39m1magsK0",
  ],
};

/** The sections every implementation of the session and binding primitives replays, each output computed by the library. */
function sharedPrimitives() {
  const fixedInputs = Object.fromEntries(
    Object.entries(FIXED_INPUTS).map(([name, f]) => [name, { ...f, encoded: encode(fixedBytes(f.start, f.length)) }]),
  );
  const input = (name: string | null) => (name === null ? null : (fixedInputs[name] as { encoded: string }).encoded);
  const deriveSessionIdSection = {
    keys: SESSION_ID_KEYS,
    cases: SESSION_ID_CASES.map((c) => ({
      ...c,
      expected: deriveSessionId(input(c.clientRootSig), input(c.serverRootSig), fixedInputs.clientNonce.encoded, fixedInputs.serverNonce.encoded, SESSION_ID_KEYS),
    })),
  };
  const bindResponseSection = { ...RESPONSE, expected: bindResponse(RESPONSE.resultHash, RESPONSE.callId, RESPONSE.labels as Parameters<typeof bindResponse>[2]) };
  const bindPromptSection = { prompt: PROMPT, expected: bindPrompt(PROMPT) };
  const bindResultSection = { result: RESULT, expected: bindResult(RESULT) };
  const bindMcpCallSection = { ...MCP_CALL, expected: bindMcpCall(MCP_CALL.tool, MCP_CALL.callId, MCP_CALL.args) };
  const commitInfluenceSection = { ...COMMIT_INFLUENCE, expected: commitInfluence(COMMIT_INFLUENCE.entries as InfluenceEntry[]) };

  const leafHashes = MERKLE.leaves.map((l) => leafHash(decode(l.salt), l.path));
  const level0 = [...leafHashes, decode(MERKLE.padSlot3)];
  const level1 = [nodeHash(level0[0]!, level0[1]!), nodeHash(level0[2]!, level0[3]!)];
  let root = nodeHash(level1[0]!, level1[1]!);
  for (const pad of MERKLE.paddingAbove) root = nodeHash(root, decode(pad));
  const siblingsOf = (slot: number): string[] => [
    encode(level0[slot ^ 1]!), encode(level1[(slot >> 1) ^ 1]!), ...MERKLE.paddingAbove,
  ];
  const dirsOf = (slot: number) => Array.from({ length: MERKLE.depth }, (_, level) => ((slot >> level) & 1 ? "R" : "L")).join("");
  const proofs: Record<string, MerkleProof> = {};
  const proofHeaders: Record<string, string> = {};
  MERKLE.leaves.forEach((l, slot) => {
    proofs[l.path] = { leafSalt: l.salt, siblings: siblingsOf(slot), dirs: dirsOf(slot), rootId: MERKLE.rootId };
    if (!provesPath(proofs[l.path], l.path, root, MERKLE.rootId)) {
      throw new Error(`merkle proof for ${l.path} does not verify`);
    }
    proofHeaders[l.path] = encodeProof(proofs[l.path]!);
    check(`merkle proof header for ${l.path}`, readProof(proofHeaders[l.path]!), proofs[l.path]);
  });
  const merkle = {
    leaves: MERKLE.leaves.map((l, i) => ({ ...l, hash: encode(leafHashes[i]!) })),
    nodes: [{ left: encode(level0[0]!), right: encode(level0[1]!), hash: encode(level1[0]!) }],
    root: encode(root),
    proofs,
    proofHeaders,
  };
  return {
    fixedInputs,
    deriveSessionId: deriveSessionIdSection,
    bindPrompt: bindPromptSection,
    bindResult: bindResultSection,
    bindResponse: bindResponseSection,
    bindMcpCall: bindMcpCallSection,
    commitInfluence: commitInfluenceSection,
    merkle,
  };
}

type Expected = { reason: string; suspectSvc: string; suspectInst: string };

/** What a verify case shares with an offline one. */
type CaseInputs = {
  name: string;
  chain: StampV3[];
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
  const malformed = (last: unknown) => [origin, last] as unknown as StampV3[];
  // A stamp that is not v3 beside a v3 one.
  const notV3Call = [origin, { ...hop, v: 2 }] as unknown as StampV3[];

  const clientCall: Omit<CaseInputs, "name"> = {
    chain: call, expectedBind: callBind, influence: INFLUENCE, policy: "client", proofRoute: CALL_ROUTE, receiver: CALL_RCV,
    receiverInRoute: true, keyring: { session: "session", pi: "pi" }, allowedOrigins: ["session"], sess: SESS, nonceKey: `${RID}|${CALL_ID}|req`,
  };
  const resolveKeyring = (k: Record<string, KeyName>) => Object.fromEntries(Object.entries(k).map(([svc, name]) => [svc, keys[name].pub]));
  const rootOf = (name: CaseInputs["policy"]) => decode(policies[name].root);
  const proofTokenOf = (c: { policy: CaseInputs["policy"]; proofRoute: string | null }) =>
    c.proofRoute === null ? null : policies[c.policy].proofTokens[c.proofRoute]!;

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
    const chainToken = chainTokenOf(c.name, c.chain);
    const influenceToken = tokenOf(c.influence);
    const input = {
      chain: chainToken, expectedBind: c.expectedBind, influence: influenceToken, proof: proofTokenOf(c),
      receiver: c.receiver, receiverInRoute: c.receiverInRoute, ...(c.peer === null ? {} : { peer: c.peer }),
    };
    let result = verifyChainV3(input, cfg);
    for (let i = 1; i < c.uses; i++) result = verifyChainV3(input, cfg);
    check(`verify ${c.name}`, { reason: result.reason, suspectSvc: result.suspectSvc, suspectInst: result.suspectInst }, expected);
    const { name, chain, expectedBind, influence, policy: p, proofRoute, receiver, receiverInRoute, peer, keyring, allowedOrigins, sess, nonceKey, uses } = c;
    return {
      name, chain, chainToken, expectedBind, influence, influenceToken, policy: p, proofRoute, receiver,
      receiverInRoute, peer, keyring, allowedOrigins, sess, nonceKey, now: NOW, callMaxAgeMs: CALL_MAX_AGE_MS,
      runMaxAgeMs: RUN_MAX_AGE_MS, nonceTtlMs: NONCE_TTL_MS, policyNotAfter, uses, expected,
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
    // A stamp that is not v3 beside a v3 one.
    live(callCase("a stamp whose v is not 3", { chain: notV3Call }), no("CHAIN_MISSING")),
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
  const offlineCase = (c: Offline, expected: Expected) => {
    const recordedTs = c.recordedTs ?? { last: c.chain[c.chain.length - 1]!.ts };
    const prompt = c.prompt ?? PROMPT;
    const seen = c.seen ?? [];
    const chainToken = chainTokenOf(c.name, c.chain);
    const influenceToken = tokenOf(c.influence);
    const result = verifyChainOffline(
      {
        chain: chainToken, expectedBind: c.expectedBind, influence: influenceToken, proof: proofTokenOf(c),
        receiver: c.receiver, receiverInRoute: c.receiverInRoute, rid: RID, recordedTs, prompt,
      },
      {
        keyring: resolveKeyring(c.keyring), root: rootOf(c.policy), rootId: policies[c.policy].rootId, allowedOrigins: c.allowedOrigins, sess: c.sess,
        nonceKey: c.nonceKey, seen: new Set(seen), callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS,
      },
    );
    check(`offline ${c.name}`, { reason: result.reason, suspectSvc: result.suspectSvc, suspectInst: result.suspectInst }, expected);
    const { name, chain, expectedBind, influence, policy: p, proofRoute, receiver, receiverInRoute, keyring, allowedOrigins, sess, nonceKey } = c;
    return {
      name, chain, chainToken, expectedBind, influence, influenceToken, policy: p, proofRoute, receiver,
      receiverInRoute, keyring, allowedOrigins, sess, nonceKey, seen, callMaxAgeMs: CALL_MAX_AGE_MS,
      runMaxAgeMs: RUN_MAX_AGE_MS, rid: RID, recordedTs, prompt, expected,
    };
  };
  const offline = [
    offlineCase({ name: "v3 recorded call", ...clientCall }, ok("pi", "pi-1")),
    offlineCase({ name: "a stamp whose v is not 3", ...clientCall, chain: notV3Call }, no("CHAIN_MISSING")),
    offlineCase({ name: "receiver chain broken", ...clientCall, chain: strayCall }, no("BINDING_MISMATCH")),
    offlineCase({ name: "recorded time differs", ...clientCall, recordedTs: { last: hop.ts + 1 } }, no("TIME_MISMATCH")),
    offlineCase({ name: "expired", ...clientCall, chain: staleCall }, no("EXPIRED")),
    offlineCase({ name: "prompt differs", ...clientCall, prompt: "open a PR for issue #43" }, no("PROMPT_MISMATCH")),
    offlineCase({ name: "replay in the record set", ...clientCall, seen: [clientCall.nonceKey] }, no("REPLAY")),
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

  // Influence: normalised forms written by hand; the "no owners" commitment is the shared one.
  const primitives = sharedPrimitives();
  const notes = (cid?: string, owner?: string): InfluenceEntry => ({
    cls: "private", src: "file:notes.md", h: "h1", ...(cid === undefined ? {} : { cid }), ...(owner === undefined ? {} : { owner }),
  });
  const influenceCases = [
    { name: "no owners", entries: COMMIT_INFLUENCE.entries as InfluenceEntry[], normalized: [
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
  check("no owners commitment", influenceCases[0]!.commitment, primitives.commitInfluence.expected);

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

  // What the policy key signs offline, a keyring and a root, each carrying notAfter, which its signed bytes include.
  // signingBytes is null when `signed` has no notAfter, or one that is not an integer in [0, 2^53 - 1]: nothing
  // signs either, and a reader refuses both, so their signature is never consulted; `current` gives isCurrent's
  // answer at each `at`. The case without notAfter is signed over the bytes the other fields alone would give, so a
  // reader that took the missing window for none would find it verifies.
  //
  // The cross-prefix cases (a root signature offered as a keyring signature, and the other way round) are not the
  // domain-separation guarantee: the two signed bodies differ, so those signatures would fail even without the
  // prefixes. What pins the prefixes is each case's literal `signingBytes`, which both replays rebuild by hand.
  //
  // Each case carries its `file`, which a replay reads, and its answers are the file's: a file that does not read
  // never verifies, has no signed bytes and is never current. Two cases tie the readers together on how a notAfter
  // is read: one of 2^53, and one whose file writes it 1798761600000.0 (FRACTION_CASE), the integer its signature is
  // over; each reader refuses both.
  const DAY_MS = 86_400_000;
  const currentAt = (o: object, ats: number[]) => ats.map((at) => ({ at, current: isCurrent(o, at) }));
  const ringServices = { session: "session", pi: "pi" } as const;
  const ringPolicy = keys["client-policy"].pub;
  const newRing = (notAfter: number) => signKeyring(resolveKeyring(ringServices), ringPolicy, keys["client-policy"].priv, notAfter);
  const rootPolicy = policies.client;
  const newRoot = (notAfter: number, signer: KeyName = "client-policy") => signRoot(decode(rootPolicy.root), rootPolicy.rootId, keys[signer].priv, notAfter);
  // Signed by the client policy key over each object's other fields alone, the bytes a keyring or root with no window would have.
  const unwindowedRing = { policy: ringPolicy, services: resolveKeyring(ringServices), sig: encode(sign(keys["client-policy"].priv, utf8("paztport-keyring\n" + canonicalize({ policy: ringPolicy, services: resolveKeyring(ringServices) })))) };
  const unwindowedRoot = { rootId: rootPolicy.rootId, root: rootPolicy.root, sig: encode(sign(keys["client-policy"].priv, utf8(`${rootPolicy.rootId}|${rootPolicy.root}`))) };
  const keyringFormCase = (name: string, signed: SignedKeyring, verifies: boolean, ats?: number[], services: Record<string, KeyName> = ringServices) => {
    const file = fileOf(name, signed);
    const read = readOr(() => readKeyringFile(utf8(file)));
    if (read !== undefined) check(`keyring ${name} file`, { ...read, services: { ...read.services } }, signed);
    check(`keyring ${name}`, read !== undefined && verifyKeyring(read, ringPolicy), verifies);
    const bytes = read === undefined ? null : keyringSigningBytes(read.policy, read.services, read.notAfter);
    if (verifies) check(`keyring ${name} re-signed`, signKeyring(signed.services, signed.policy, keys["client-policy"].priv, signed.notAfter).sig, signed.sig);
    const current = ats === undefined ? {} : { current: currentAt(read ?? {}, ats) };
    const signingBytes = bytes === null ? null : encode(bytes);
    const sig = signed.sig;
    return { name, policyKey: "client-policy", services, signingBytes, sig, signed, file, verifies, ...current };
  };
  const tamperedServices = { session: "session", pi: "gateway" } as const;
  const keyring = [
    keyringFormCase("signed", newRing(POLICY_NOT_AFTER), true, [POLICY_NOT_AFTER, POLICY_NOT_AFTER + 1]),
    keyringFormCase("tampered service key", { ...newRing(POLICY_NOT_AFTER), services: resolveKeyring(tamperedServices) }, false, undefined, tamperedServices),
    keyringFormCase("largest notAfter", newRing(Number.MAX_SAFE_INTEGER), true, [Number.MAX_SAFE_INTEGER]),
    keyringFormCase("tampered notAfter", { ...newRing(POLICY_NOT_AFTER), notAfter: POLICY_NOT_AFTER + 1 }, false),
    keyringFormCase("no notAfter", unwindowedRing as unknown as SignedKeyring, false, [0, POLICY_NOT_AFTER]),
    keyringFormCase("notAfter added to a signature made without one", { ...unwindowedRing, notAfter: POLICY_NOT_AFTER }, false),
    keyringFormCase("notAfter not an integer", { ...newRing(POLICY_NOT_AFTER), notAfter: 1.5 }, false),
    keyringFormCase("root signature as a keyring signature", { ...newRing(POLICY_NOT_AFTER), sig: newRoot(POLICY_NOT_AFTER).sig }, false),
    keyringFormCase("notAfter 2^53", { ...newRing(POLICY_NOT_AFTER), notAfter: 2 ** 53 }, false),
    keyringFormCase(FRACTION_CASE, newRing(POLICY_NOT_AFTER), false, [POLICY_NOT_AFTER, POLICY_NOT_AFTER + 1]),
  ];

  // The client policy's signed root, under the client-policy pin; `policy` names the tree.
  const rootCase = (name: string, signed: SignedRoot, verifies: boolean, ats?: number[]) => {
    const file = fileOf(name, signed);
    const read = readOr(() => readRootFile(utf8(file)));
    if (read !== undefined) check(`root ${name} file`, read, signed);
    check(`root ${name}`, read !== undefined && verifyRoot(read, keys["client-policy"].pub), verifies);
    const bytes = read === undefined ? null : rootSigningBytes(read.rootId, read.root, read.notAfter);
    if (verifies) check(`root ${name} re-signed`, signRoot(decode(signed.root), signed.rootId, keys["client-policy"].priv, signed.notAfter).sig, signed.sig);
    const current = ats === undefined ? {} : { current: currentAt(read ?? {}, ats) };
    const signingBytes = bytes === null ? null : encode(bytes);
    return { name, policyKey: "client-policy", policy: "client", signingBytes, signed, file, verifies, ...current };
  };
  const renewed = signRenewedRoot(newRoot(POLICY_NOT_AFTER), POLICY_NOT_AFTER + DAY_MS, keys["client-policy"].priv);
  check("root renewed keeps the tree", [renewed.rootId, renewed.root], [rootPolicy.rootId, rootPolicy.root]);
  check("root renewed is the tree signed afresh", renewed, newRoot(POLICY_NOT_AFTER + DAY_MS));
  const signedRoots = [
    rootCase("signed", newRoot(POLICY_NOT_AFTER), true, [POLICY_NOT_AFTER, POLICY_NOT_AFTER + 1]),
    rootCase("largest notAfter", newRoot(Number.MAX_SAFE_INTEGER), true, [Number.MAX_SAFE_INTEGER]),
    rootCase("renewed", renewed, true, [POLICY_NOT_AFTER + DAY_MS, POLICY_NOT_AFTER + DAY_MS + 1]),
    rootCase("tampered notAfter", { ...newRoot(POLICY_NOT_AFTER), notAfter: POLICY_NOT_AFTER + 1 }, false),
    rootCase("no notAfter", unwindowedRoot as unknown as SignedRoot, false, [0, POLICY_NOT_AFTER]),
    rootCase("notAfter added to a signature made without one", { ...unwindowedRoot, notAfter: POLICY_NOT_AFTER }, false),
    rootCase("notAfter not an integer", { ...newRoot(POLICY_NOT_AFTER), notAfter: 1.5 }, false),
    rootCase("signed by another policy key", newRoot(POLICY_NOT_AFTER, "server-policy"), false),
    rootCase("keyring signature as a root signature", { ...newRoot(POLICY_NOT_AFTER), sig: newRing(POLICY_NOT_AFTER).sig }, false),
    rootCase("notAfter 2^53", { ...newRoot(POLICY_NOT_AFTER), notAfter: 2 ** 53 }, false),
    rootCase(FRACTION_CASE, newRoot(POLICY_NOT_AFTER), false, [POLICY_NOT_AFTER, POLICY_NOT_AFTER + 1]),
  ];

  // The server's reply certificate for mcp-entry, and forms of it that must not verify under the server pin.
  const CERT_NOT_AFTER = 1_798_761_600_000;
  const issueCert = (policy: KeyName, notAfter: number, signer: KeyName): ReplyCert =>
    signReplyCert(keys[policy].pub, "mcp-entry", keys["mcp-entry"].pub, notAfter, keys[signer].priv);
  const certCase = (name: string, signer: KeyName, cert: ReplyCert, verifies: boolean) => {
    const file = fileOf(name, cert);
    const read = readOr(() => readReplyCertFile(utf8(file)));
    if (read !== undefined) check(`reply certificate ${name} file`, read, cert);
    const verified = read !== undefined && verifyReplyCert(read, keys["server-policy"].pub);
    check(`reply certificate ${name}`, verified, verifies);
    const bytes = read && encode(replyCertSigningBytes(read.policy, read.svc, read.key, read.notAfter));
    const signingBytes = bytes ?? null;
    return { name, signer, pin: "server-policy", cert, file, signingBytes, verifies };
  };
  const signedCert = issueCert("server-policy", CERT_NOT_AFTER, "server-policy");
  const otherPolicyCert = issueCert("client-policy", CERT_NOT_AFTER, "client-policy");
  check("reply certificate under its own policy key", verifyReplyCert(otherPolicyCert, keys["client-policy"].pub), true);
  const replyCert = [
    certCase("signed", "server-policy", signedCert, true),
    certCase("tampered notAfter", "server-policy", { ...signedCert, notAfter: CERT_NOT_AFTER + 1 }, false),
    certCase("signed by another policy key", "client-policy", issueCert("server-policy", CERT_NOT_AFTER, "client-policy"), false),
    certCase("names another policy key", "client-policy", otherPolicyCert, false),
    certCase("an extra field", "server-policy", { ...signedCert, note: "not signed" } as ReplyCert, false),
    certCase("largest notAfter", "server-policy", issueCert("server-policy", Number.MAX_SAFE_INTEGER, "server-policy"), true),
  ];

  // Session replies under the server pin: the entry-key form, signed by mcp-entry's key under its certificate and
  // the signed server keyring, the policy-key form, and replies that must fail. Both sides' roots and keyrings are
  // valid until LIVE_NOT_AFTER, far past every case's `now`; the request
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
  /** A reply signed over whatever it holds: the crafted cases carry values the SDK's signer refuses to write. */
  const signAnyReply = (body: Record<string, unknown>, priv: string): SessionReply =>
    ({ ...body, sig: encode(sign(priv, utf8("paztport-session-reply\n" + canonicalize(body)))) }) as unknown as SessionReply;
  const certFor = (svc: string, key: KeyName, signer: KeyName = "server-policy") =>
    signReplyCert(keys["server-policy"].pub, svc, keys[key].pub, CERT_NOT_AFTER, keys[signer].priv);
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
    return signAnyReply(body, keys[signer].priv) as unknown as Record<string, unknown>;
  };
  // The keyring's signature and its window travel together: neither is in the policy-key form.
  const NO_RING_SIG = ["serverKeyringSig", "serverKeyringNotAfter"];
  const POLICY_KEY_FORM = [...NO_RING_SIG, "serverReplyCert"];
  const sessionReplyCase = (name: string, raw: Record<string, unknown>, expected: string, o: { pin?: KeyName; serverEntry?: string; now?: number } = {}) => {
    const pin = o.pin ?? "server-policy";
    const serverEntry = o.serverEntry ?? "mcp-entry";
    const now = o.now ?? NOW;
    const requestToken = tokenOf(request);
    const replyToken = tokenOf(raw);
    const got = checkSessionReply(replyToken, readSessionRequest(requestToken), keys[pin].pub, serverEntry, now);
    check(`session reply ${name}`, got, expected);
    return { name, request, requestToken, reply: raw, replyToken, pin, serverEntry, now, expected };
  };
  const attackerRing = { ...serverRing.services, "mcp-entry": keys.orders.pub };
  const { notAfter: _serverRootWindow, ...serverRootWindowDropped } = serverRoot;
  const sessionReply = [
    sessionReplyCase("entry-key form attested", reply("mcp-entry"), "ATTESTED"),
    sessionReplyCase("entry-key form unsafe", reply("mcp-entry", { status: "unsafe", disabled: [TOOL] }), "UNSAFE"),
    sessionReplyCase("policy-key form attested", reply("server-policy", {}, POLICY_KEY_FORM), "ATTESTED"),
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
    sessionReplyCase("neither field, signed by the keyring's entry key", reply("orders", { serverKeyring: attackerRing }, POLICY_KEY_FORM), "BAD_SIGNATURE"),
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
      "a member the reply does not have",
      reply("github-tools", { serverEntry: "github-tools", serverReplyCert: certFor("github-tools", "github-tools") }),
      "MALFORMED_REPLY",
    ),
    sessionReplyCase("pin mismatch", reply("mcp-entry"), "PIN_MISMATCH", { pin: "client-policy" }),
    // The server keyring's window is covered by the policy key's keyring signature, not by the entry key's.
    sessionReplyCase("serverKeyringNotAfter moved", reply("mcp-entry", { serverKeyringNotAfter: LIVE_NOT_AFTER + 1 }), "BAD_SIGNATURE"),
    sessionReplyCase("serverKeyringNotAfter dropped", reply("mcp-entry", {}, ["serverKeyringNotAfter"]), "MALFORMED_REPLY"),
    sessionReplyCase("serverKeyringNotAfter not an integer", reply("mcp-entry", { serverKeyringNotAfter: "x" }), "MALFORMED_REPLY"),
    sessionReplyCase("serverKeyringNotAfter null", reply("mcp-entry", { serverKeyringNotAfter: null }), "MALFORMED_REPLY"),
    sessionReplyCase("server root notAfter moved", reply("mcp-entry", { serverRoot: { ...serverRoot, notAfter: LIVE_NOT_AFTER + 1 } }), "BAD_SIGNATURE"),
    sessionReplyCase("server root notAfter not an integer", reply("mcp-entry", { serverRoot: { ...serverRoot, notAfter: 1.5 } }), "MALFORMED_REPLY"),
    sessionReplyCase("server root notAfter dropped", reply("mcp-entry", { serverRoot: serverRootWindowDropped }), "MALFORMED_REPLY"),
    // The client judges the server's root, in either form and either status, and in the entry-key form its keyring:
    // each must be current at `now`.
    sessionReplyCase("server root at notAfter", reply("mcp-entry", { serverRoot: serverRootUntil(NOW) }), "ATTESTED"),
    sessionReplyCase("server root expired", reply("mcp-entry", { serverRoot: serverRootUntil(NOW - 1) }), "BAD_SIGNATURE"),
    sessionReplyCase("server root expired, policy-key form", reply("server-policy", { serverRoot: serverRootUntil(NOW - 1) }, POLICY_KEY_FORM), "BAD_SIGNATURE"),
    sessionReplyCase("server root expired, unsafe", reply("mcp-entry", { serverRoot: serverRootUntil(NOW - 1), status: "unsafe", disabled: [TOOL] }), "BAD_SIGNATURE"),
    // Current by its moved window and re-signed by the entry key, so only the root's own signature refuses it.
    sessionReplyCase(
      "expired server root's notAfter moved past now, re-signed by the entry key",
      reply("mcp-entry", { serverRoot: { ...serverRootUntil(NOW - 1), notAfter: LIVE_NOT_AFTER } }),
      "BAD_SIGNATURE",
    ),
    sessionReplyCase("server keyring at notAfter", reply("mcp-entry", { serverKeyringSig: serverRingUntil(NOW).sig, serverKeyringNotAfter: NOW }), "ATTESTED"),
    sessionReplyCase("server keyring expired", reply("mcp-entry", { serverKeyringSig: serverRingUntil(NOW - 1).sig, serverKeyringNotAfter: NOW - 1 }), "BAD_SIGNATURE"),
    // A keyring window with no keyring signature: the policy-key form's keyring is signed only through the reply.
    sessionReplyCase("serverKeyringNotAfter in the policy-key form", reply("server-policy", {}, ["serverKeyringSig", "serverReplyCert"]), "BAD_SIGNATURE"),
  ];

  // The server's status for a request, against its own root and keyring and the client keys it pinned, at `now`:
  // attested only when every root and keyring on both sides is current. The client's material
  // is judged only once its signature verifies, so a moved window fails as a signature.
  const clientRootUntil = (notAfter: number) => signRoot(decode(policies.client.root), policies.client.rootId, keys["client-policy"].priv, notAfter);
  const withClientRing = (ring: SignedKeyring): SessionRequest => {
    const { clientKeyringNotAfter: _window, ...rest } = request;
    return { ...rest, clientKeyringSig: ring.sig, clientKeyringNotAfter: ring.notAfter };
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
    const serverRootFile = printFile(root);
    const serverKeyringFile = printFile(ring);
    const ownRoot = readRootFile(utf8(serverRootFile));
    const ownRing = readKeyringFile(utf8(serverKeyringFile));
    const pins = pinned.map((n) => keys[n].pub);
    const requestToken = tokenOf(req);
    const req1 = readSessionRequest(requestToken);
    const got = sessionStatus(req1, ownRoot, ownRing.notAfter, keys["server-policy"].pub, pins, now);
    check(`session status ${name}`, got, expected);
    return {
      name, request: req, requestToken, serverRoot: root, serverRootFile, serverKeyring: ring, serverKeyringFile,
      serverPolicyKey: "server-policy", pinned, now, expected,
    };
  };
  const sessionStatusCases = [
    statusCase("attested", {}, "attested"),
    statusCase("client key not pinned", { pinned: ["server-policy"] }, "unsafe"),
    statusCase("client root at notAfter", { request: { ...request, clientRoot: clientRootUntil(NOW) } }, "attested"),
    statusCase("client root expired", { request: { ...request, clientRoot: clientRootUntil(NOW - 1) } }, "unsafe"),
    statusCase("expired client root's notAfter moved past now", { request: { ...request, clientRoot: { ...clientRootUntil(NOW - 1), notAfter: LIVE_NOT_AFTER } } }, "unsafe"),
    statusCase("client keyring at notAfter", { request: withClientRing(newRing(NOW)) }, "attested"),
    statusCase("client keyring expired", { request: withClientRing(newRing(NOW - 1)) }, "unsafe"),
    statusCase("expired client keyring's clientKeyringNotAfter moved past now", { request: { ...withClientRing(newRing(NOW - 1)), clientKeyringNotAfter: LIVE_NOT_AFTER } }, "unsafe"),
    statusCase("server root and keyring at notAfter", { serverRoot: serverRootUntil(NOW), serverKeyring: serverRingUntil(NOW) }, "attested"),
    statusCase("server root expired", { serverRoot: serverRootUntil(NOW - 1) }, "unsafe"),
    statusCase("server keyring expired", { serverKeyring: serverRingUntil(NOW - 1) }, "unsafe"),
  ];

  // The server's reading of a request body: a request without a usable `clientKeyringSig`, or whose keyring or root
  // has no notAfter, is malformed (JSON-RPC -32602, HTTP 400 INVALID_PARAMS), never an unsafe session.
  const wireRequest = JSON.parse(JSON.stringify(request)) as Record<string, unknown>;
  const { clientKeyringSig: _unsigned, ...withoutSig } = wireRequest;
  const { clientKeyringNotAfter: _ringWindow, ...withoutRingWindow } = wireRequest;
  const { notAfter: _rootWindow, ...unwindowedClientRoot } = wireRequest.clientRoot as Record<string, unknown>;
  const sessionRequestCase = (name: string, body: Record<string, unknown>, expected: "OK" | "MALFORMED") => {
    const requestToken = tokenOf(body);
    let got: "OK" | "MALFORMED" = "OK";
    try {
      readSessionRequest(requestToken);
    } catch {
      got = "MALFORMED";
    }
    check(`session request ${name}`, got, expected);
    return { name, request: body, requestToken, expected };
  };
  const sessionRequestCases = [
    sessionRequestCase("well formed", wireRequest, "OK"),
    sessionRequestCase("no keyring signature", withoutSig, "MALFORMED"),
    sessionRequestCase("keyring signature null", { ...withoutSig, clientKeyringSig: null }, "MALFORMED"),
    sessionRequestCase("keyring signature empty", { ...withoutSig, clientKeyringSig: "" }, "MALFORMED"),
    sessionRequestCase("keyring signature a number", { ...withoutSig, clientKeyringSig: 7 }, "MALFORMED"),
    sessionRequestCase("no keyring notAfter", withoutRingWindow, "MALFORMED"),
    sessionRequestCase("client root without notAfter", { ...wireRequest, clientRoot: unwindowedClientRoot }, "MALFORMED"),
  ];


  // Recorded handshakes (sessions-and-influence.md §Recorded handshakes): the session a recorded request and reply
  // opened, judged offline at each `at`, at all (at the earliest of its limits), the policyNotAfter a response in it
  // is checked with. The reply's session id is bound to the request it answers.
  const replyTo = (req: SessionRequest, signer: KeyName, o: Record<string, unknown> = {}, drop: string[] = []): SessionReply => {
    const root = (Object.hasOwn(o, "serverRoot") ? o.serverRoot : serverRoot) as { sig: string };
    const body: Record<string, unknown> = {
      serverRoot: root, serverPolicyKey: keys["server-policy"].pub, serverKeyring: serverRing.services, serverKeyringSig: serverRing.sig,
      serverKeyringNotAfter: LIVE_NOT_AFTER, serverReplyCert: entryCert, nonce: SERVER_NONCE,
      sess: deriveSessionId(req.clientRoot?.sig ?? null, root.sig, req.nonce, SERVER_NONCE, req), status: "attested", disabled: [], ...o,
    };
    for (const f of drop) delete body[f];
    return signAnyReply(body, keys[signer].priv);
  };
  const handshakeCase = (name: string, request: SessionRequest, reply: SessionReply, at: number[], o: { pin?: KeyName; serverEntry?: string } = {}) => {
    const pin = o.pin ?? "server-policy";
    const serverEntry = o.serverEntry ?? "mcp-entry";
    const requestToken = tokenOf(request);
    const replyToken = tokenOf(reply);
    const s = recordedSession({ request: requestToken, reply: replyToken, pin: keys[pin].pub, serverEntry });
    const expected = { attested: s.attested, attestedAt: at.map((t) => s.attestedAt(t)), responseNotAfter: s.responseNotAfter };
    return { name, request, requestToken, reply, replyToken, pin, serverEntry, at, expected };
  };
  const clientRootAt = (t: number): SessionRequest => ({ ...request, clientRoot: clientRootUntil(t) });
  // Client material a reader refuses as malformed, recorded all the same: the session it opened is never attested.
  const unsignedRequest = withoutSig as unknown as SessionRequest;
  const unwindowedRingRequest = withoutRingWindow as unknown as SessionRequest;
  const unwindowedRootRequest = { ...wireRequest, clientRoot: unwindowedClientRoot } as unknown as SessionRequest;
  const recordedHandshake = [
    handshakeCase("entry-key form, limited by the certificate", request, replyTo(request, "mcp-entry"), [CERT_NOT_AFTER, CERT_NOT_AFTER + 1]),
    handshakeCase("policy-key form, limited by the roots and keyrings", request, replyTo(request, "server-policy", {}, POLICY_KEY_FORM), [LIVE_NOT_AFTER, LIVE_NOT_AFTER + 1]),
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
    handshakeCase("unsafe", request, replyTo(request, "mcp-entry", { status: "unsafe", disabled: [TOOL] }), [NOW]),
    handshakeCase("a signed reply the client's shape check refuses", request, replyTo(request, "mcp-entry", {}, ["disabled"]), [NOW]),
    handshakeCase("another pin", request, replyTo(request, "mcp-entry"), [NOW], { pin: "client-policy" }),
    handshakeCase("the configured entry, not the reply's", request, replyTo(request, "github-tools", { serverReplyCert: certFor("github-tools", "github-tools") }), [NOW], { serverEntry: "mcp-entry" }),
    handshakeCase("configured for another entry", request, replyTo(request, "mcp-entry"), [NOW], { serverEntry: "github-tools" }),
    handshakeCase("client keyring window moved", { ...withClientRing(newRing(NOW)), clientKeyringNotAfter: LIVE_NOT_AFTER }, replyTo({ ...withClientRing(newRing(NOW)), clientKeyringNotAfter: LIVE_NOT_AFTER }, "mcp-entry"), [NOW]),
    handshakeCase("client root signed by another key", { ...request, clientRoot: newRoot(LIVE_NOT_AFTER, "server-policy") }, replyTo({ ...request, clientRoot: newRoot(LIVE_NOT_AFTER, "server-policy") }, "mcp-entry"), [NOW]),
    handshakeCase("request without a client keyring signature", unsignedRequest, replyTo(unsignedRequest, "mcp-entry"), [NOW]),
    handshakeCase("request without a client keyring notAfter", unwindowedRingRequest, replyTo(unwindowedRingRequest, "mcp-entry"), [NOW]),
    handshakeCase("client root without notAfter", unwindowedRootRequest, replyTo(unwindowedRootRequest, "mcp-entry"), [NOW]),
  ];
  check("recorded handshake answers", recordedHandshake.map((c) => [c.name, c.expected.attested, c.expected.attestedAt]), [
    ["entry-key form, limited by the certificate", true, [true, false]],
    ["policy-key form, limited by the roots and keyrings", true, [true, false]],
    ["client root's notAfter", true, [true, false]],
    ["client keyring's notAfter", true, [true, false]],
    ["server root's notAfter", true, [true, false]],
    ["server keyring's notAfter", true, [true, false]],
    ["attested at all at the earliest limit", true, [true, false]],
    ["unsafe", false, [false]],
    ["a signed reply the client's shape check refuses", false, [false]],
    ["another pin", false, [false]],
    ["the configured entry, not the reply's", false, [false]],
    ["configured for another entry", false, [false]],
    ["client keyring window moved", false, [false]],
    ["client root signed by another key", false, [false]],
    ["request without a client keyring signature", false, [false]],
    ["request without a client keyring notAfter", false, [false]],
    ["client root without notAfter", false, [false]],
  ]);
  // The server signed it, so only the shape check refuses it: live it is MALFORMED_REPLY, and offline never attested.
  const shapeRefused = recordedHandshake.find((c) => c.name === "a signed reply the client's shape check refuses")!;
  const serverPin = keys["server-policy"].pub;
  const shapeRefusedLive = checkSessionReply(shapeRefused.replyToken, request, serverPin, "mcp-entry", NOW);
  check("the shape-refused reply live", shapeRefusedLive, "MALFORMED_REPLY");
  check(
    "the unsigned and unwindowed requests' response limits",
    recordedHandshake.slice(-3).map((c) => c.expected.responseNotAfter),
    [LIVE_NOT_AFTER, LIVE_NOT_AFTER, LIVE_NOT_AFTER],
  );
  check("the shape-refused reply's response limit", shapeRefused.expected.responseNotAfter, LIVE_NOT_AFTER);
  check(
    "recorded handshake response limits",
    recordedHandshake.slice(0, 7).map((c) => c.expected.responseNotAfter),
    [LIVE_NOT_AFTER, LIVE_NOT_AFTER, LIVE_NOT_AFTER, LIVE_NOT_AFTER, NOW, NOW, NOW + 2],
  );

  // Recorded calls (verification.md §Offline verification): each call is checked by the offline verifier in the
  // session of the handshake it names, against the client keyring and root of that handshake's request and its reply's
  // session id, then limited to the session (OUTSIDE_SESSION). The calls are one record set, in order: one set of spent
  // nonce keys for them all, whatever handshakes the set holds.
  type RecordedCallInput = Omit<CaseInputs, "name" | "keyring" | "sess" | "allowedOrigins"> & {
    chainToken: string;
    influenceToken: string;
    handshake: number;
    rid: string;
    recordedTs: { last: number };
    prompt: string;
  };
  const callIn = (reply: SessionReply, ts: number, callId: string, o: { forged?: boolean } = {}): RecordedCallInput => {
    const bind = bindMcpCall(TOOL, callId, ARGS);
    const sess = reply.sess;
    const first = v3({ ...originFields, ts: ts - 1000, sess }, "session");
    const chain = [first, v3({ ...hopFields(first.sig), ts, sess, bind }, o.forged === true ? "session" : "pi")];
    return {
      handshake: 0, chain, chainToken: tokenOf(chain), expectedBind: bind, influence: INFLUENCE,
      influenceToken: tokenOf(INFLUENCE), policy: "client", proofRoute: CALL_ROUTE, receiver: CALL_RCV,
      receiverInRoute: true, nonceKey: `${RID}|${callId}|req`, rid: RID, recordedTs: { last: ts }, prompt: PROMPT,
    };
  };
  const recordedCallCase = (name: string, handshakes: { request: SessionRequest; reply: SessionReply }[], calls: RecordedCallInput[]) => {
    const recorded = handshakes.map((h) => ({
      request: h.request, requestToken: tokenOf(h.request), reply: h.reply, replyToken: tokenOf(h.reply),
      pin: "server-policy" as KeyName, serverEntry: "mcp-entry",
    }));
    const sessions = recorded.map((h) =>
      recordedSession({
        request: h.requestToken, reply: h.replyToken, pin: keys[h.pin].pub, serverEntry: h.serverEntry,
      }),
    );
    const records = newRecordSet();
    const expected = calls.map((c) => {
      const h = recorded[c.handshake]!;
      const request = readSessionRequest(h.requestToken);
      const clientRoot = request.clientRoot!;
      const v = verifyChainOffline(
        {
          chain: c.chainToken, expectedBind: c.expectedBind, influence: c.influenceToken, proof: proofTokenOf(c),
          receiver: c.receiver, receiverInRoute: c.receiverInRoute, rid: c.rid, recordedTs: c.recordedTs,
          prompt: c.prompt,
        },
        {
          keyring: request.clientKeyring, root: decode(clientRoot.root), rootId: clientRoot.rootId,
          allowedOrigins: ["session"], sess: h.reply.sess,
          nonceKey: c.nonceKey, seen: records.spent, callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS,
        },
      );
      const reason = callInSession(sessions[c.handshake]!, v.reason, c.recordedTs.last);
      if (reason === undefined) throw new Error(`recorded call ${name}: its session is not attested`);
      return { reason };
    });
    return { name, handshakes: recorded, allowedOrigins: ["session"], callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS, calls, expected };
  };
  const entryKeyReply = replyTo(request, "mcp-entry");
  const shortRoot = clientRootAt(NOW);
  const shortRootReply = replyTo(shortRoot, "mcp-entry");
  const inSession = { request, reply: entryKeyReply };
  const recordedCall = [
    recordedCallCase("at the certificate's notAfter", [inSession], [callIn(entryKeyReply, CERT_NOT_AFTER, "call-1")]),
    recordedCallCase("past the certificate's notAfter", [inSession], [callIn(entryKeyReply, CERT_NOT_AFTER + 1, "call-1")]),
    recordedCallCase("past the client root's notAfter", [{ request: shortRoot, reply: shortRootReply }], [callIn(shortRootReply, NOW, "call-1"), callIn(shortRootReply, NOW + 1, "call-2")]),
    recordedCallCase("a failing call keeps its result past the limit", [{ request: shortRoot, reply: shortRootReply }], [callIn(shortRootReply, NOW + 1, "call-1", { forged: true })]),
    recordedCallCase("replay in the record set", [inSession], [callIn(entryKeyReply, NOW, "call-1"), callIn(entryKeyReply, NOW + 60_000, "call-1")]),
    recordedCallCase("a repeated handshake resets no spent key", [inSession, inSession], [callIn(entryKeyReply, NOW, "call-1"), { ...callIn(entryKeyReply, NOW, "call-1"), handshake: 1 }]),
  ];
  check("recorded call answers", recordedCall.map((c) => [c.name, c.expected]), [
    ["at the certificate's notAfter", [{ reason: "OK" }]],
    ["past the certificate's notAfter", [{ reason: "OUTSIDE_SESSION" }]],
    ["past the client root's notAfter", [{ reason: "OK" }, { reason: "OUTSIDE_SESSION" }]],
    ["a failing call keeps its result past the limit", [{ reason: "BAD_SIGNATURE" }]],
    ["replay in the record set", [{ reason: "OK" }, { reason: "REPLAY" }]],
    ["a repeated handshake resets no spent key", [{ reason: "OK" }, { reason: "REPLAY" }]],
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
  type LocalClient = { keyring: Record<string, KeyName>; policy: "client"; rootNotAfter: number; keyringNotAfter: number; rules: LocalRules | null };
  const localStepCase = (
    name: string,
    d: Partial<LocalDecision> = {},
    o: { client?: Partial<LocalClient>; proofRoute?: string | null; seen?: string[] } = {},
  ) => {
    const decision: LocalDecision = { tool: "read", callId: "tc-1", input: { path: "notes.md" }, resolved: READ_NOTES, verdict: "OK", routeAllowed: true, rulesHash: rulesHash(LOCAL_RULES), ...d };
    const client: LocalClient = { keyring: { session: "session", pi: "pi" }, policy: "client", rootNotAfter: LIVE_NOT_AFTER, keyringNotAfter: LIVE_NOT_AFTER, rules: LOCAL_RULES, ...o.client };
    const first = localOrigin;
    const chain = [
      first,
      stampLocalStep(
        {
          svc: "pi", inst: "pi-1", rid: RID, ts: STEP_TS, prev: first.sig, toolName: decision.tool, toolCallId: decision.callId, input: decision.input,
          resolved: decision.resolved, verdict: decision.verdict, listed: decision.routeAllowed, rulesHash: decision.rulesHash, influence: INFLUENCE,
        },
        keys.pi.priv,
      ),
    ];
    const proofRoute = Object.hasOwn(o, "proofRoute") ? o.proofRoute! : decision.routeAllowed ? routeOf(["session", "pi", localReceiver(decision.tool)]) : null;
    // what bindLocalTool hashes, and what the step records as one token
    const signed = {
      callId: decision.callId, resolved: decision.resolved, verdict: decision.verdict,
      routeAllowed: decision.routeAllowed, rulesHash: decision.rulesHash,
    };
    const step = {
      ...decision, decisionToken: tokenOf(signed), rid: RID, now: STEP_TS, chain, chainToken: tokenOf(chain),
      proofRoute, influence: INFLUENCE, influenceToken: tokenOf(INFLUENCE),
    };
    const run = { prompt: PROMPT, ts: [localOrigin.ts] };
    const seen = o.seen ?? [];
    const result = verifyRecordedLocalStep(
      {
        tool: decision.tool, callId: decision.callId, input: decision.input, decision: step.decisionToken,
        rid: step.rid, now: step.now, chain: step.chainToken,
        proof: proofTokenOf({ policy: "client", proofRoute }), influence: step.influenceToken,
      },
      {
        client: {
          keyring: resolveKeyring(client.keyring), root: rootOf(client.policy), rootId: policies[client.policy].rootId,
          rootNotAfter: client.rootNotAfter, keyringNotAfter: client.keyringNotAfter, rules: client.rules,
        },
        signers: LOCAL_SIGNERS,
        run: { prompt: run.prompt, ts: new Set(run.ts) },
        seen: new Set(seen),
      },
    );
    return { name, client, signers: LOCAL_SIGNERS, step, run, seen, expected: { reason: result.reason, verdict: result.verdict ?? null } };
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
  ];
  check("recorded local step answers", recordedLocalStep.map((c) => [c.name, c.expected.reason, c.expected.verdict]), [
    ["allowed", "OK", "OK"],
    ["refused by the rules", "OK", "SCOPE_DENIED"],
    ["unlisted tool", "OK", "PATH_NOT_ALLOWED"],
    ["no rules", "OK", "SCOPE_DENIED"],
    ["at the client root's notAfter", "OK", "OK"],
    ["client root expired", "POLICY_EXPIRED", null],
    ["client keyring expired", "POLICY_EXPIRED", null],
    ["client root expired, bad signature first", "BAD_SIGNATURE", null],
    ["listed but not proven", "PROOF_MISMATCH", null],
    ["proven but recorded as not listed", "PROOF_MISMATCH", null],
    ["expired before the proof", "POLICY_EXPIRED", null],
    ["rules hash not the client's", "RULES_MISMATCH", null],
    ["verdict not the rules'", "VERDICT_MISMATCH", null],
    ["verdict not the rules', unlisted tool resolving something", "VERDICT_MISMATCH", null],
    ["rules mismatch before verdict mismatch", "RULES_MISMATCH", null],
    ["replay in the record set", "REPLAY", null],
  ]);

  // The same response through the client's check, as the MCP profile carries it in `_meta`.
  const RESULT_BODY = { content: [{ type: "text", text: "opened #43" }], isError: false };
  const RESPONSE_SERVER = {
    policy: "server" as const,
    keyring: { "mcp-entry": "mcp-entry", "github-tools": "github-tools" } as Record<string, KeyName>,
    allowedOrigins: ["mcp-entry"],
    sess: SESS,
    policyNotAfter: 4_102_444_800_000,
    nonceTtlMs: NONCE_TTL_MS,
  };
  const goodAttestation = {
    chain: [entry, tools],
    proof: policies.server.proofs["mcp-entry/github-tools"]!,
    labels: LABELS as unknown,
    resultHash: bindResult(RESULT_BODY),
  };
  const attestationCase = (name: string, attestation: Record<string, unknown>, expected: string) => {
    const result = RESULT_BODY;
    const attestationToken =
      name === WIRE_ORDER_CASE ? wireOrderAttestationToken(attestation as Attestation) : tokenOf(attestation);
    const callArg = { rid: RID, toolCallId: CALL_ID, receiver: "pi" };
    const got = verifyResponse(attestationToken, result, callArg, {
      keyring: resolveKeyring(RESPONSE_SERVER.keyring), root: rootOf("server"), rootId: policies.server.rootId,
      allowedOrigins: RESPONSE_SERVER.allowedOrigins, sess: RESPONSE_SERVER.sess,
      nonces: new NonceCache(RESPONSE_SERVER.nonceTtlMs), now: NOW, policyNotAfter: RESPONSE_SERVER.policyNotAfter,
    });
    check(`response attestation ${name}`, got.result.reason, expected);
    return {
      name, attestation, attestationToken, result, call: callArg, server: RESPONSE_SERVER, now: NOW,
      expected: { reason: expected },
    };
  };
  const otherResultHash = bindResult({ content: [], isError: false });
  const responseAttestation = [
    attestationCase("attested", goodAttestation, "OK"),
    attestationCase("a member the attestation does not have", { ...goodAttestation, extra: 1 }, "CHAIN_MISSING"),
    attestationCase(
      "a label with a member labels do not have",
      { ...goodAttestation, labels: [{ ...LABELS[0]!, extra: 1 }] },
      "CHAIN_MISSING",
    ),
    attestationCase(WIRE_ORDER_CASE, goodAttestation, "CHAIN_MISSING"),
    attestationCase("a result hash for another result", { ...goodAttestation, resultHash: otherResultHash },
      "BINDING_MISMATCH"),
  ];

  const vectors = {
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
    responseAttestation,
    replyCert,
    sessionReply,
    sessionStatus: sessionStatusCases,
    sessionRequest: sessionRequestCases,
    ...primitives,
  };
  checkTokens(vectors);
  return vectors;
}

/** v3.json's text: the built vectors as JSON. */
export function vectorsV3Text(): string {
  const vectors = buildVectorsV3();
  let text = JSON.stringify(vectors, null, 2) + "\n";
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
