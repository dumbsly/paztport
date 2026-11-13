// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Builds spec/vectors/v4.json, the version 4 conformance vectors, as a pure function of fixed seeds; run with
// `--write` from poc-sdks/typescript to write the file. Every case is checked against the library first, and
// the export throws on any mismatch, so it can never record a wrong answer.

import { createPrivateKey, createPublicKey } from "node:crypto";
import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";
import {
  CALL_MAX_AGE_MS, NONCE_TTL_MS, NonceCache, RUN_MAX_AGE_MS, SALT_BYTES, bindLocalTool, buildTree, bindPrompt, bindResponse, bindResult,
  canonicalize, concat, decode, encode, keyPairMatches, keyringSigningBytes, leafHash, localReceiver, nodeHash,
  printFile, readKeyringFile, readReplyCertFile, readRootFile,
  provesPath, routeOf, sha256, sign, signKeyring, signStamp, signingBytes,
  writeToken,
  utf8, verifyChainOffline, verifyChain, verifyKeyring, signReplyCert, replyCertSigningBytes, verifyReplyCert,
  checkSessionReply, readProof, readSessionRequest, deriveSessionId, encodeProof, isCurrent, isNotAfter,
  pinnedNotAfter, signRenewedRoot, rootSigningBytes, sessionStatus, signRoot, verifyRoot,
  callInSession, newRecordSet, parseLocalRules, recordedSession, rulesHash, stampLocalStep, verifyRecordedLocalStep,
  blockOf, callsAfter, commitBlock, extensionSettings, isAttestedSession, nonceKey, readBlocks, writeWire,
  INFLUENCE, decideVerifiedCall, entryOf, labelOf, publicWriteRefused, readRequestInfluence, readSessionReply,
  recordedCallReason, responseEntries, verifyResponse,
} from "@paztport/core";
import type {
  ChainVerification, InfluenceFact, JsonValue, LocalRules, LocalVerdict, MerkleProof, Peer, ReasonCode, ReplyCert,
  ReplyCheck, Resolved, SessionReply, SessionRequest, SignedKeyring, SignedRoot, Stamp, StampItems,
} from "@paztport/core";
import { InvalidParams, bindMcpCall, mcpReceiver, readSessionParams, sessionReplyToken } from "../src/index.ts";

const VECTORS_JSON = new URL("../../../spec/vectors/v4.json", import.meta.url);

const KEY_NAMES = ["session", "pi", "mcp-entry", "github-tools", "gateway", "orders", "client-policy", "server-policy", "orders-next"] as const;
type KeyName = (typeof KEY_NAMES)[number];
const PKCS8_ED25519_PREFIX = "302e020100300506032b657004220420";
/** The keyring and root cases' fixed notAfter: 2027-01-01, as the Java tests use. */
const POLICY_NOT_AFTER = 1_798_761_600_000;
/** The keyring and root case whose `file` writes its notAfter `1798761600000.0`, the integer its signature is over. */
const FRACTION_CASE = "notAfter written 1798761600000.0";
/** The name of the session request, session reply and keyring cases that name a service by something that is not a route node. */
const NOT_A_NODE_CASE = "a keyring name that is not a route node";
const DEPTH = 8;
/** The verify case whose last stamp's ts is −2^63, which the file writes exactly (see vectorsText). */
const TS_MIN_CASE = "stamp ts of -2^63";
const TS_MIN_TEXT = "-9223372036854775808";
/** The verify case whose blocks token does not read: it carries that token, and `blocks` null (see checkTokens). */
const UNREADABLE_BLOCKS_CASE = "a blocks token that does not read";
/** The verify case whose blocks token is the JCS of null, beside `blocks` null. */
const NULL_BLOCKS_CASE = "a blocks token holding null, every ext empty";
/** The verify case whose blocks read as JSON, but whose second element is no block. */
const EXTRA_MEMBER_CASE = "a block with a member blocks do not have";
/** The verify and responseAttestation cases whose call id holds a noncharacter. */
const NONCHARACTER_CASE = "a call id holding a noncharacter";
/** The responseAttestation case whose token writes the attestation's members out of JCS order (see checkTokens). */
const UNSORTED_ATTESTATION_CASE = "an attestation whose members are not in JCS order";

const ABOUT =
  "Paztport version 4 conformance vectors. Every case carries all of its inputs; keys and policies are named and defined in this file. " +
  `Each key's private key is the PKCS#8 DER ${PKCS8_ED25519_PREFIX} || seed, where seed = SHA-256(utf8("paztport-v3-vector-key:" + name)), ` +
  "and its public key is the SPKI DER export; both are base64url. " +
  `Each Merkle leaf salt is the first ${SALT_BYTES} bytes of SHA-256(utf8("paztport-v3-vector-salt:" + route)), and the policy's routes fill the ` +
  'first leaves in order; padding leaf i is SHA-256(utf8("paztport-v3-vector-pad:" + rootId + ":" + i)), ' +
  'and a handshake nonce labelled l is the first 16 bytes of SHA-256(utf8("paztport-v3-vector-nonce:" + l)). ' +
  "The v3 in these seed strings is historical: they are v3.json's, kept so that the keys, the policies and every section whose rule did not change " +
  "are v3.json's value for value, and a file of other vectors can take its keys and policies from either. " +
  "This placement and rootId derivation are for the vectors only; real builds use random slots and a random rootId. " +
  "Ed25519 is deterministic, so the file is reproduced byte for byte. " +
  "The core sections use a made-up extension, example, name influence only as an opaque second name, " +
  "and need no extension's rules. " +
  "recordedLocalStep, responseAttestation, sessionParams, sessionResult, bindMcpCall and bindResult belong to " +
  "the MCP profile. Of these only recordedLocalStep needs the influence extension's rules, since the client's " +
  "local gate decides by them: a step's blocks carry influence entries, which the verifier reads " +
  "(INFLUENCE_MISMATCH) and under whose classes it derives the gate's verdict again. Every other section that " +
  "needs them is in the top-level member influence. " +
  "blocks.read reads each token as blocks: expected is OK with the blocks read, or REFUSED; blocks.commit gives a block's JCS text and its stamp's ext. " +
  "Each verify and offline case, each call of a recordedCall case, and each recordedLocalStep case's step, " +
  "carries `blocksToken`, the token the verifier reads, null when no token was received, which is one empty " +
  "block per stamp, and `blocks`, the token's readable value. `blocks` is null where there is no token, and in " +
  `the two verify cases whose token does not read as an array: "${NULL_BLOCKS_CASE}", whose token is ` +
  `the JCS of null, and "${UNREADABLE_BLOCKS_CASE}", whose token is not canonical bytes and has no readable value. ` +
  `The verify case "${EXTRA_MEMBER_CASE}" carries its readable value, an array whose second element is no block. ` +
  "On each verify, offline, recordedCall and responseAttestation case, `actsOn` is the extensions the verifier " +
  "acts on, and `allowedExtensions` the names it carries, null for unset, which carries any name. " +
  "A verify or offline case's expected is {reason, suspectSvc, suspectInst, handOver}: handOver is null unless the reason is OK, and then has " +
  "one member per name in actsOn, each an array of {svc, items}, one per stamp in chain order, items null where the stamp's block does not name the extension. " +
  "A verify case runs the live verifier `uses` times against one nonce cache of nonceTtlMs and expects the last result; each use is sent by `peer`, " +
  "or, in a case with `peers` in place of `peer`, by peers[i] for use i (null: no peer). " +
  "Its policyNotAfter is the earlier of the latest notAfter of the keyrings and the latest notAfter of the roots the verifier pins (one of each: the earlier of the two), which `now` must not pass. " +
  "An offline case runs the offline verifier once: `recordedTs.last` is the recorded time of the last stamp, `rid` the record's rid, " +
  "`prompt` the run's recorded prompt, and callMaxAgeMs and runMaxAgeMs the age limits; a null recordedTs is a record with no time, and a null limit is one not configured, which is absent, never 0; there is no peer, clock or nonce TTL, and `seen` " +
  "is the set of nonce keys already spent in the record set. A policy's proof is looked up by `proofRoute` (null: no proof). " +
  "A nonce key, in `nonceKey` and `seen`, is the JCS text of its array of strings, each string written as RFC 8785 writes strings. " +
  `The verify case "${NONCHARACTER_CASE}"'s nonceKey, and the responseAttestation case of that name's ` +
  "call.toolCallId, hold the noncharacter U+FFFF written as itself, as json.json already does, which a strict " +
  "reader refuses, so a replay reads this file's own structure with any JSON reader, and only the tokens with the " +
  "reader under test. " +
  "A sessionReply case is the client's check of `reply` at `now`, against `pin` and `serverEntry`, with the extensions it `requires` ([] when absent); " +
  "offline the same reply opened an attested session exactly when the check gives ATTESTED or EXTENSION_REQUIRED, since step 5 is live only. " +
  "A sessionRequirement case is what a client that requires the extensions `requires` may do after the handshake: `check` is the reply's check " +
  "(null for a JSON-RPC error or a timeout), `listed` the reply's extensions ([] when it did not read) and `continueWithout` its switch; " +
  "expected says whether it makes calls and the `requires` its calls carry. " +
  "A sessionStatus case is the server's status for `request` at `now`, against its own `serverRoot` and `serverKeyring` (whose notAfter is its window), " +
  "its policy key `serverPolicyKey` and the client policy keys `pinned`. " +
  "A sessionRequest case is a request as received, its bytes in `requestToken`, read by the server: " +
  "`expected` is OK for a well-formed request and MALFORMED for one it refuses " +
  "(JSON-RPC -32602, HTTP 400 INVALID_PARAMS). " +
  "A recordedLocalStep case is a recorded local step: its `step` (the call's `tool`, `callId` and `input`; the " +
  "gate's decision, `resolved`, `verdict`, `routeAllowed` and `rulesHash`, recorded together as `decisionToken`; " +
  "`rid`, `now`, the chain, `proofRoute`, and the blocks, the origin's naming influence with [] and the hop's " +
  "holding the session's entries), checked against its `client` (`keyring` by name, `policy`'s root, their " +
  "windows `rootNotAfter` and `keyringNotAfter`, and `rules`), its `signers`, its `run` (prompt and start times) " +
  "and `seen`; expected is the reason, and the verdict the step signed when it verifies, else null. " +
  "A responseAttestation case is a response as the client receives it: `attestationToken` (its readable value " +
  "`attestation`, one block per stamp of the response chain), the `result` it answers, the `call` (`rid`, " +
  "`toolCallId`, `receiver`), the client's `actsOn` and `allowedExtensions`, and the `server` its stamps are " +
  "checked against; the client checks it once at `now`, check 9c included, and expected is the reason. " +
  `The attestationToken of "${UNSORTED_ATTESTATION_CASE}" writes the members chain, proof, ` +
  "blocks, resultHash, out of JCS order; every other is its value's JCS. " +
  "A sessionParams case is paztport/session's params as the server reads them (OK, or INVALID_PARAMS for " +
  "JSON-RPC -32602), and a sessionResult case its result as the client reads it (OK, or MALFORMED_REPLY); the OK " +
  'results carry the reply of the sessionReply case "entry-key form attested". ' +
  "The sections after sessionRequest pin the primitives the cases above rely on, each with its inputs: fixedInputs are `length` consecutive bytes from `start`, base64url, " +
  "which deriveSessionId's cases name; the prompt and response bindings; " +
  "merkle, a tree of its own (depth 8, rootId merkle-vector) whose leaf hashes, node, root, proofs and proof headers (the base64url of each proof's JCS bytes) are recorded as the library computes them, and whose padding hashes are recorded as given, not derived; " +
  "and the MCP profile's tools/call and result bindings, bindMcpCall and bindResult. " +
  "The member influence holds: entries and labels, {name, item, reads}, whether the item reads as an entry on a " +
  "request's block or as a label on a response's; rule, the owner-aware rule's truth table {name, influence, " +
  "destinationOwner, refused}, with a null owner unknown; request, {name, stamps, served, write, destinationOwner, " +
  "expected: {reason, everyStampNames}}, what an attested MCP server that acts on influence decides for a call " +
  "that verified, `stamps` the hand-over's entries for influence, `served` the classes it served in the session " +
  "and `write` whether the call writes to a public destination, where an item that does not read as an entry is " +
  "INFLUENCE_MISMATCH before any rule and everyStampNames is then null; response, {name, reason, stamps, src, " +
  "resultHash, expected: {entries}}, the entries a client that acts on influence adds for a response, `reason` " +
  "the core check's result and `stamps` what the response's blocks hold under influence, one per stamp, read only " +
  "on OK; and recordedCall, in recordedCall's shape, at a verifier that acts on influence and reads the items once " +
  "the offline order gives OK, before a call is held to its session's limits. " +
  "A verify or offline case may pin several keyrings and roots: `keyrings` ([{keyring, notAfter}], in place of `keyring`) and `roots` ([{policy, notAfter}], which pin those policies' roots), " +
  "where `policy` then names only where the case's proof comes from; in an offline case a member without a notAfter has no window. " +
  "A case's one `keyring`, or `policy`'s root when it has no `roots`, is a single member whose window is the case's policyNotAfter in a verify case " +
  "and none in an offline case, and two `roots` naming one policy are its root and a renewal of it. " +
  "The policy mesh-second is a second tree over mesh's routes, whose rootId and salts the vectors derive from the seed `second` as well as the routes " +
  "(rootId = \"v\" + first 12 hex of SHA-256(utf8(routes joined by newline + newline + \"#second\")), " +
  'salt = the first 16 bytes of SHA-256(utf8("paztport-v3-vector-salt:second:" + route))); ' +
  "mesh-relabelled holds mesh's proofs with their rootId set to mesh-second's, over mesh's root. " +
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

/** A route's leaf salt; a policy with a seed (a second tree over the same routes) salts as "<seed>:<route>". */
function salt(route: string, seed = ""): Uint8Array {
  return sha256(utf8("paztport-v3-vector-salt:" + (seed === "" ? "" : seed + ":") + route)).slice(0, SALT_BYTES);
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
function deriveRootId(routes: string[], seed = ""): string {
  return "v" + Buffer.from(sha256(utf8(routes.join("\n") + (seed === "" ? "" : "\n#" + seed)))).toString("hex").slice(0, 12);
}

/** A policy tree with fixed salts and padding (the library's tree pads at random), each proof checked by the library. */
function policy(routes: string[], seed = ""): Policy {
  const rootId = deriveRootId(routes, seed);
  const level0 = routes.map((r) => leafHash(salt(r, seed), r));
  for (let i = routes.length; i < 2 ** DEPTH; i++) {
    level0.push(sha256(utf8(`paztport-v3-vector-pad:${rootId}:${i}`)));
  }
  const levels = [level0];
  while (levels[levels.length - 1]!.length > 1) {
    const below = levels[levels.length - 1]!;
    levels.push(below.flatMap((_, i) => (i % 2 === 0 ? [nodeHash(below[i]!, below[i + 1]!)] : [])));
  }
  const root = levels[levels.length - 1]![0]!;
  const library = buildTree(routes.map((path) => ({ salt: salt(path, seed), path })), DEPTH, rootId);
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
    proofs[route] = { leafSalt: encode(salt(route, seed)), siblings, dirs, rootId };
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

type Attestation = { blocks: unknown; chain: unknown; proof: unknown; resultHash: string };

/**
 * The token of an attestation whose members are written `chain`, `proof`, `blocks`, `resultHash`, each value as JCS
 * writes it: the order version 3's attestation was listed in, with `blocks` in `labels`' place, and not JCS order,
 * which sorts the members.
 */
function unsortedAttestationToken(att: Attestation): string {
  return encode(
    utf8(
      `{"chain":${canonicalize(att.chain)},"proof":${canonicalize(att.proof)},"blocks":${canonicalize(att.blocks)},` +
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
 * except the chain token TS_MIN_CASE crafts, which holds the ts exactly, the blocks token of UNREADABLE_BLOCKS_CASE,
 * which does not read, and the attestation token UNSORTED_ATTESTATION_CASE crafts, whose members are out of JCS order;
 * a blocks token is null, for none received, only beside null blocks. A local step's `decisionToken` is tokenOf its
 * `callId`, `resolved`, `verdict`, `routeAllowed` and `rulesHash` together. Every file is fileOf its readable sibling:
 * a keyring's or root's `signed`, a certificate's `cert`, and a session status case's `serverRoot` and `serverKeyring`.
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
      if (o.name === TS_MIN_CASE && k === "chainToken") {
        const text = Buffer.from(decode(v as string)).toString("utf8");
        check(`${at} spells its ts exactly`, text.includes(`"ts":${TS_MIN_TEXT},`), true);
      } else if (o.name === UNREADABLE_BLOCKS_CASE && k === "blocksToken") {
        const read = readOr(() => readBlocks(v as string));
        check(`${at} does not read, beside null blocks`, [read, o.blocks], [undefined, null]);
      } else if (k === "blocksToken" && v === null) {
        check(`${at} is null, beside null blocks`, o.blocks, null);
      } else if (o.name === UNSORTED_ATTESTATION_CASE && k === "attestationToken") {
        check(`${at} is the unsorted token of its value`, v, unsortedAttestationToken(o.attestation as Attestation));
        check(`${at} is not the JCS of its value`, v === tokenOf(o.attestation), false);
      } else {
        check(`${at} is the token of its value`, v, tokenOf(o[k.slice(0, -5)]));
      }
    } else if (k === "decisionToken") {
      const { callId, resolved, verdict, routeAllowed, rulesHash: hash } = o;
      const decision = { callId, resolved, verdict, routeAllowed, rulesHash: hash };
      check(`${at} is the token of its decision`, v, tokenOf(decision));
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

/** The inputs of the sections that bind no keys: the session id, and the prompt and response bindings. */
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
const RESPONSE = { resultHash: "result-hash", callId: "call-1" };
/** The MCP profile's bindings' inputs: a result with a top-level `_meta`, which its hash leaves out, and a call. */
const RESULT = { content: [{ type: "text", text: "hi" }], isError: false, _meta: { x: 1 } };
const MCP_CALL = {
  tool: "create_pull_request", callId: "call-1", args: { title: "t", body: "b", draft: false, n: [1, 2.5] },
};

/**
 * The MCP profile's result and `tools/call` bindings (wire.md, Bindings), each stated by hand: the hash of
 * "result\n" and the result's JCS without its `_meta`, and of "tools/call\n", the tool, "\n", the call id, "\n" and the
 * arguments' JCS.
 */
function mcpBindings() {
  const { _meta: _left, ...hashed } = RESULT;
  const bindResultSection = { result: RESULT, expected: bindResult(RESULT) };
  check("bindResult", bindResultSection.expected, encode(sha256(utf8("result\n" + canonicalize(hashed)))));
  const bindMcpCallSection = { ...MCP_CALL, expected: bindMcpCall(MCP_CALL.tool, MCP_CALL.callId, MCP_CALL.args) };
  const callText = `tools/call\n${MCP_CALL.tool}\n${MCP_CALL.callId}\n${canonicalize(MCP_CALL.args)}`;
  check("bindMcpCall", bindMcpCallSection.expected, encode(sha256(utf8(callText))));
  return { bindMcpCall: bindMcpCallSection, bindResult: bindResultSection };
}

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
  const bindResponseSection = { ...RESPONSE, expected: bindResponse(RESPONSE.resultHash, RESPONSE.callId) };
  // The response binding has no prefix: it is the hash of the result hash, a newline and the call id.
  const responseBytes = utf8(`${RESPONSE.resultHash}\n${RESPONSE.callId}`);
  check("bindResponse", bindResponseSection.expected, encode(sha256(responseBytes)));
  const bindPromptSection = { prompt: PROMPT, expected: bindPrompt(PROMPT) };

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
    bindResponse: bindResponseSection,
    merkle,
  };
}

/** A block of the vectors: its readable value, as received. */
type BlockJson = { items: Record<string, JsonValue[]>; requires: string[] };

/** The block that attaches nothing, whose stamp commits to "". */
const EMPTY: BlockJson = { items: {}, requires: [] };

/** A block's commitment, its stamp's ext; the library's reader takes it first, so it is a block. */
const extOf = (block: BlockJson): string => commitBlock(blockOf(block as unknown as JsonValue));

/** b64url(SHA-256(JCS(value))) for any value, as a stamp would commit to it were it a block that is not empty. */
const hashOf = (value: JsonValue): string => encode(sha256(writeWire(value)));

/** blocks.read: tokens read as blocks, and blocks.commit: blocks, their JCS text and their stamps' ext. */
function blocksSection() {
  const named = (name: string, items: JsonValue[] = [], requires: string[] = []): BlockJson =>
    ({ items: { [name]: items }, requires });
  // The text of a token holding one block whose one item is `depth` arrays deep: the array of blocks is one level, the
  // block two, its items three and the item's list four, so an item 28 deep is at the depth limit of 32.
  const nested = (depth: number) => `[{"items":{"example":[${"[".repeat(depth)}${"]".repeat(depth)}]},"requires":[]}]`;
  const textToken = (text: string) => encode(utf8(text));
  const readCase = (name: string, token: string, blocks: JsonValue | null) => {
    const read = readOr(() => JSON.parse(JSON.stringify(readBlocks(token))) as JsonValue);
    const expected = blocks === null ? "REFUSED" : "OK";
    check(`blocks read ${name}`, read === undefined ? "REFUSED" : "OK", expected);
    if (blocks !== null) check(`blocks read ${name} gives`, read, blocks);
    return { name, token, expected, blocks };
  };
  const reads = (name: string, blocks: JsonValue) => readCase(name, tokenOf(blocks), blocks);
  const refuses = (name: string, value: JsonValue) => readCase(name, tokenOf(value), null);
  const deepest = JSON.parse(nested(28)) as JsonValue;
  // every character a name may hold, 32 of them
  const NAME_32 = "abcdefghijklmnopqrstuvwxyz-01234";
  const read = [
    reads("no blocks", []),
    reads("one empty block", [EMPTY]),
    reads("the wire.md example", [EMPTY, named("example", [{ note: "..." }], ["example"])]),
    reads("a name only in requires", [{ items: {}, requires: ["example"] }]),
    reads("a name only in items", [named("example", [{ note: "n1" }])]),
    reads("an extension named constructor, with one item", [named("constructor", [{ note: "c1" }])]),
    reads("a name of 32 characters", [named(NAME_32, [], [NAME_32])]),
    reads("items of every JSON type", [
      named("example", [null, true, false, 0, 9007199254740991, "", "é", [], {}, [1, [2]], { a: { b: null } }]),
    ]),
    readCase("an item at the depth limit", textToken(nested(28)), deepest),
    refuses("a block with another member", [{ ...EMPTY, note: "n1" }]),
    refuses("a block with no items", [{ requires: [] }]),
    refuses("a block with no requires", [{ items: {} }]),
    refuses("a name Example in items", [named("Example")]),
    refuses("a name Example in requires", [{ items: {}, requires: ["Example"] }]),
    refuses("a name of 33 characters", [named(NAME_32 + "5")]),
    refuses("an empty name", [named("")]),
    refuses("a value in items that is an object", [{ items: { example: {} }, requires: [] }]),
    refuses("items an array", [{ items: [], requires: [] }]),
    refuses("requires unsorted", [{ items: {}, requires: ["influence", "example"] }]),
    refuses("a name twice in requires", [{ items: {}, requires: ["example", "example"] }]),
    refuses("a number in requires", [{ items: {}, requires: [7] }]),
    refuses("an object in place of the array", EMPTY),
    refuses("null in place of the array", null),
    readCase("the array's JCS bytes after a space", textToken(" " + canonicalize([EMPTY])), null),
    readCase("an item one level past the depth limit", textToken(nested(29)), null),
  ];
  // Each commitment by hand: "" for the empty block, else b64url(SHA-256(the JCS text)), which sorts member names and
  // keeps every list in the order written.
  const commitCase = (name: string, block: BlockJson, jcs: string) => {
    const ext = extOf(block);
    check(`blocks commit ${name} JCS`, canonicalize(block), jcs);
    check(`blocks commit ${name}`, ext, block === EMPTY ? "" : encode(sha256(utf8(jcs))));
    return { name, block, jcs, ext };
  };
  const commit = [
    commitCase("the empty block", EMPTY, '{"items":{},"requires":[]}'),
    commitCase("a name with no items", named("example"), '{"items":{"example":[]},"requires":[]}'),
    commitCase("a name only in requires", { items: {}, requires: ["example"] }, '{"items":{},"requires":["example"]}'),
    commitCase(
      "the wire.md example's second block", named("example", [{ note: "..." }], ["example"]),
      '{"items":{"example":[{"note":"..."}]},"requires":["example"]}',
    ),
    commitCase(
      "two names, each list in the order written",
      { items: { influence: [3, 1, 2], example: [{ note: "b" }, { note: "a" }] }, requires: [] },
      '{"items":{"example":[{"note":"b"},{"note":"a"}],"influence":[3,1,2]},"requires":[]}',
    ),
  ];
  return { read, commit };
}

type PolicyName = "client" | "server" | "mesh" | "mesh-second" | "mesh-relabelled" | "ops";

/** A pinned keyring or root of a case with several: the keyring's service-to-key-name map or the root's policy, and its window. */
type KeyringPin = { keyring: Record<string, KeyName>; notAfter?: number };
type RootPin = { policy: PolicyName; notAfter?: number };

/** A hand-over as the file records it: for each name acted on, one entry per stamp in chain order. */
type HandOverJson = Record<string, { svc: string; items: JsonValue[] | null }[]>;

type Expected = { reason: string; suspectSvc: string; suspectInst: string; handOver: HandOverJson | null };

/** A verifier's result as the file records it, its hand-over a plain object of plain values. */
function outcomeOf(result: ChainVerification): Expected {
  const handOver = result.handOver === null ? null
    : (JSON.parse(JSON.stringify(Object.fromEntries(result.handOver))) as HandOverJson);
  return { reason: result.reason, suspectSvc: result.suspectSvc, suspectInst: result.suspectInst, handOver };
}

/** What a verify case shares with an offline one. */
type CaseInputs = {
  name: string;
  chain: Stamp[];
  expectedBind: string;
  /** The blocks as received, null for no token; `blocksToken`, when set, is the token in their place. */
  blocks: JsonValue[] | null;
  blocksToken?: string;
  actsOn: string[];
  allowedExtensions: string[] | null;
  policy: PolicyName;
  proofRoute: string | null;
  receiver: string;
  receiverInRoute: boolean;
  keyring: Record<string, KeyName>;
  allowedOrigins: string[];
  sess: string;
  nonceKey: string;
};

/** A case's blocks token: the one it sets, else null for no blocks, else the token of its blocks. */
const blocksTokenOf = (c: Pick<CaseInputs, "blocks" | "blocksToken">): string | null =>
  c.blocksToken ?? (c.blocks === null ? null : tokenOf(c.blocks));

/** A case's extension settings, built and checked by the library. */
const settingsOf = (c: Pick<CaseInputs, "actsOn" | "allowedExtensions">) =>
  extensionSettings(c.actsOn, c.allowedExtensions ?? undefined);

/** A hand-over's entries for one name: each stamp's signer and the items its block holds, or null. */
const entries = (...pairs: [string, JsonValue[] | null][]) => pairs.map(([svc, items]) => ({ svc, items }));

/** Whether `read` reads the item, as an entry or a label: a reader that refuses it throws. */
const readsAs = (read: (item: JsonValue) => unknown, item: JsonValue): boolean =>
  readOr(() => read(item)) !== undefined;

/**
 * The member `influence`: everything that needs the influence extension's rules (influence.md). Every answer is
 * stated by hand and checked against the library.
 */
function influenceSection(run: {
  A_LABEL: JsonValue; SESSION_ENTRIES: JsonValue[]; RESULT_HASH: string;
  recordedCall: { name: string; expected: { reason: string }[] };
}) {
  type Item = Record<string, JsonValue>;
  const [THIRD_PARTY, PRIVATE_ALICE] = run.SESSION_ENTRIES as [Item, Item];
  const PRIVATE_BOB = { cls: "private", src: "github:acme/app#7", h: "h3", owner: "bob" };
  const PUBLIC = { cls: "public", src: "web:docs.example.org", h: "h4" };

  // An item on a request's block, read as an entry (influence.md, Entries).
  const entryCase = (name: string, item: JsonValue, reads: boolean) => {
    check(`influence entry ${name}`, readsAs(entryOf, item), reads);
    return { name, item, reads };
  };
  const entryItems = [
    entryCase("the three required members", THIRD_PARTY, true),
    entryCase("with cid", { ...THIRD_PARTY, cid: "cid-2" }, true),
    entryCase("with owner", PRIVATE_BOB, true),
    entryCase("with cid and owner", PRIVATE_ALICE, true),
    // only compared as text: an empty one is a string like any other
    entryCase("an empty cid", { ...THIRD_PARTY, cid: "" }, true),
    entryCase("a string", "third-party", false),
    entryCase("an array", ["third-party", "web:example.com", "h2"], false),
    entryCase("null", null, false),
    entryCase("another member", { ...THIRD_PARTY, note: "n1" }, false),
    // the classes are the four names exactly
    entryCase("an unknown cls", { ...THIRD_PARTY, cls: "Third-party" }, false),
    entryCase("no h", { cls: "third-party", src: "web:example.com" }, false),
    entryCase("a number as src", { ...THIRD_PARTY, src: 7 }, false),
    entryCase("a number as h", { ...THIRD_PARTY, h: 7 }, false),
    entryCase("a number as cid", { ...THIRD_PARTY, cid: 7 }, false),
    entryCase("an empty owner", { ...PRIVATE_BOB, owner: "" }, false),
    entryCase("a null owner", { ...PRIVATE_BOB, owner: null }, false),
    entryCase("a label", run.A_LABEL, false),
  ];

  // An item on a response's block, read as a label (influence.md, Content labels).
  const labelCase = (name: string, item: JsonValue, reads: boolean) => {
    check(`influence label ${name}`, readsAs(labelOf, item), reads);
    return { name, item, reads };
  };
  const LABEL = { cls: "third-party", cid: "cid-2" };
  const labels = [
    labelCase("cid and cls", LABEL, true),
    labelCase("with owner", run.A_LABEL, true),
    labelCase("an empty cid", { ...LABEL, cid: "" }, true),
    labelCase("another member", { ...LABEL, note: "n1" }, false),
    labelCase("an unknown cls", { ...LABEL, cls: "Third-party" }, false),
    labelCase("an empty owner", { ...LABEL, owner: "" }, false),
    labelCase("no cid", { cls: "third-party" }, false),
    labelCase("a number as cid", { ...LABEL, cid: 7 }, false),
    // every member a label has, and an entry's src and h besides
    labelCase("an entry", { ...THIRD_PARTY, cid: "cid-2" }, false),
  ];

  // The owner-aware rule's truth table, by hand: v3.json's `rule`, whose rule did not change.
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
  ] as [string, InfluenceFact[], string | null, boolean][]).map(([name, facts, destinationOwner, refused]) => {
    check(`rule ${name}`, publicWriteRefused(facts, destinationOwner ?? undefined), refused);
    return { name, influence: facts, destinationOwner, refused };
  });

  // What a request holds at an attested MCP server that acts on influence: the items handed on, one entry per stamp,
  // and the classes it served in the session; `write` is a write to a public destination.
  const requestCase = (
    name: string, stamps: StampItems[], o: { served?: InfluenceFact["cls"][]; write?: boolean; destinationOwner?: string | null },
    expected: { reason: string; everyStampNames: boolean | null },
  ) => {
    const c = {
      name, stamps, served: o.served ?? [], write: o.write ?? true, destinationOwner: o.destinationOwner ?? "alice",
    };
    const decided = decideVerifiedCall(stamps, {
      isWrite: c.write, publicDestination: c.write, served: c.served,
      ...(c.destinationOwner === null ? {} : { destinationOwner: c.destinationOwner }),
    });
    const read = readRequestInfluence(stamps);
    const got = { reason: decided.verdict, everyStampNames: read.reads ? read.everyStampNames : null };
    check(`influence request ${name}`, got, expected);
    return { ...c, expected };
  };
  const hop = (items: JsonValue[] | null): StampItems[] => [{ svc: "session", items: [] }, { svc: "pi", items }];
  const ok = { reason: "OK", everyStampNames: true };
  const denied = { reason: "INFLUENCE_DENIED", everyStampNames: true };
  const mismatch = { reason: "INFLUENCE_MISMATCH", everyStampNames: null };
  const request = [
    // no untrusted content, so someone else's private data may be written
    requestCase("every stamp names it and nothing is untrusted", hop([PRIVATE_ALICE, PUBLIC]), { destinationOwner: "bob" }, ok),
    // a block that only requires influence does not name it: a hop that may have read anything
    requestCase("a pass-along block, a write", hop(null), {}, { reason: "INFLUENCE_DENIED", everyStampNames: false }),
    requestCase("a pass-along block, a read", hop(null), { write: false }, { reason: "OK", everyStampNames: false }),
    requestCase("untrusted content and someone else's private data", hop([THIRD_PARTY, PRIVATE_BOB]), {}, denied),
    requestCase("untrusted content and someone else's private data, a read", hop([THIRD_PARTY, PRIVATE_BOB]), { write: false }, ok),
    requestCase("untrusted content and the destination owner's own private data", hop([THIRD_PARTY, PRIVATE_ALICE]), {}, ok),
    // a served class carries no owner, so it counts as someone else's
    requestCase("a served private class with an untrusted entry", hop([THIRD_PARTY]), { served: ["private"] }, denied),
    requestCase("an item that is not an entry, a write", hop([THIRD_PARTY, run.A_LABEL]), {}, mismatch),
    requestCase("an item that is not an entry, a read", hop([THIRD_PARTY, run.A_LABEL]), { write: false }, mismatch),
    // the item check comes first (sessions.md, The server decision, step 2 before step 3), though the block before it
    // does not name influence
    requestCase(
      "an item that is not an entry after a block that does not name it",
      [{ svc: "session", items: null }, { svc: "pi", items: [run.A_LABEL] }], {}, mismatch,
    ),
    // no stamp to read: the every-stamp rule does not refuse, and the owner-aware rule reads what the service added
    requestCase("no stamps", [], {}, ok),
    requestCase("no stamps, the classes served refusing it", [], { served: ["third-party", "private"] }, denied),
  ];

  // What a caller that acts on influence adds for a response over MCP: `reason` is the core check's result, and
  // `stamps` what the response's blocks hold under influence, one per stamp, as the hand-over gives it on OK.
  const SRC = "server:github";
  const untrusted = [{ cls: "local-untrusted", src: SRC, h: run.RESULT_HASH }];
  const L1 = run.A_LABEL;
  const L2 = { cls: "third-party", cid: "cid-2" };
  const L3 = { cls: "public", cid: "cid-3" };
  const server = (first: JsonValue[] | null, last: JsonValue[] | null): StampItems[] =>
    [{ svc: "mcp-entry", items: first }, { svc: "github-tools", items: last }];
  const responseCase = (name: string, reason: ReasonCode, stamps: StampItems[], expected: JsonValue[]) => {
    const c = { name, reason, stamps, src: SRC, resultHash: run.RESULT_HASH };
    check(`influence response ${name}`, responseEntries(reason, stamps, SRC, run.RESULT_HASH), expected);
    return { ...c, expected: { entries: expected } };
  };
  const response = [
    responseCase("verified, one label", "OK", server([L1], []), [{ cls: "private", src: SRC, h: run.RESULT_HASH, cid: "cid-1", owner: "alice" }]),
    responseCase("verified, two blocks, [] then two labels", "OK", server([], [L2, L3]), [
      { cls: "third-party", src: SRC, h: run.RESULT_HASH, cid: "cid-2" },
      { cls: "public", src: SRC, h: run.RESULT_HASH, cid: "cid-3" },
    ]),
    // every item a label, of none: no entry at all
    responseCase("verified, every block naming it with no label", "OK", server([], []), []),
    responseCase("verified, one label and one item that is not a label", "OK", server([], [L1, THIRD_PARTY]), untrusted),
    responseCase("verified, a label, and an item that is not a label in another block", "OK", server([THIRD_PARTY], [L1]), untrusted),
    responseCase("verified, a block that does not name it", "OK", server(null, [L1]), untrusted),
    responseCase("a response refused at check 9c", "EXTENSION_REQUIRED", server([], [L1]), untrusted),
    responseCase("a response whose signature fails", "BAD_SIGNATURE", server([], [L1]), untrusted),
  ];

  // A record set at a verifier that acts on influence: an item that does not read is the extension's code, in the
  // session and past its limits alike.
  check("influence recorded call answers", run.recordedCall.expected.map((e) => e.reason), [
    "OK", "INFLUENCE_MISMATCH", "INFLUENCE_MISMATCH", "OUTSIDE_SESSION",
  ]);

  return { entries: entryItems, labels, rule, request, response, recordedCall: [run.recordedCall] };
}

export function buildVectors(): Record<string, unknown> {
  const keys = Object.fromEntries(KEY_NAMES.map((n) => [n, vectorKey(n)])) as Record<KeyName, { pub: string; priv: string }>;
  const stampBy = (fields: Omit<Stamp, "v" | "sig">, key: KeyName) => signStamp(fields, keys[key].priv);

  const TOOL = "create_pull_request";
  const CALL_RCV = mcpReceiver("github", TOOL);
  const OTHER_RCV = mcpReceiver("github", "add_issue_comment");
  const LOCAL_RCV = localReceiver("read");
  const meshRoutes = [routeOf(["gateway", "orders", "payment"])];
  const mesh = policy(meshRoutes);
  const meshSecond = policy(meshRoutes, "second");
  // mesh's proofs with the rootId of the second tree: a proof that selects the second root and cannot prove against it
  const relabelledProofs = Object.fromEntries(Object.entries(mesh.proofs).map(([route, p]) => [route, { ...p, rootId: meshSecond.rootId }]));
  const policies: Record<PolicyName, Policy> = {
    client: policy([routeOf(["session", "pi", CALL_RCV]), routeOf(["session", "pi", OTHER_RCV]), routeOf(["session", "pi", LOCAL_RCV])]),
    server: policy([routeOf(["mcp-entry", "github-tools"])]),
    mesh,
    "mesh-second": meshSecond,
    "mesh-relabelled": {
      ...mesh,
      proofs: relabelledProofs,
      proofTokens: Object.fromEntries(Object.entries(relabelledProofs).map(([route, p]) => [route, writeToken(p)])),
    },
    // Routes whose nodes name operations: a node is a service, or a service and an operation joined by `#`.
    ops: policy(["gateway/orders#createOrder/payment#charge", "gateway/orders#createOrder"]),
  };
  check("the second tree has its own rootId and root", [meshSecond.rootId !== mesh.rootId, meshSecond.root !== mesh.root], [true, true]);
  const [CALL_ROUTE, OTHER_ROUTE, LOCAL_ROUTE] = policies.client.routes as [string, string, string];

  // signingBytes: the second is wire.md's worked example, with a non-ASCII inst; the third holds what JCS escapes in
  // a string, and a `|`, which version 3's delimited bytes refused and JCS writes as itself.
  const sbStamps: Omit<Stamp, "sig">[] = [
    { v: 4, svc: "pi", inst: "pi-1", rid: "rid-1", ts: 1767225600000, sess: "sess-1", rcv: CALL_RCV, bind: "bind-1", ext: "ext-1", prev: "prev-1" },
    { v: 4, svc: "pi", inst: "pi-é", rid: "rid-1", ts: 1767225600000, sess: "", rcv: LOCAL_RCV, bind: "bind-2", ext: "", prev: "prev-2" },
    { v: 4, svc: "pi", inst: 'pi-"1"\n', rid: "rid|1", ts: 1767225600000, sess: "sess-1", rcv: CALL_RCV, bind: "bind-3", ext: "ext-3", prev: "prev-3" },
  ];
  const signingBytesCases = sbStamps.map((stamp) => {
    const bytes = Buffer.from(signingBytes(stamp));
    return { stamp, hex: bytes.toString("hex"), text: bytes.toString("utf8") };
  });
  check("signingBytes, wire.md's worked example", signingBytesCases[1]!.text,
    'paztport-stamp\n{"bind":"bind-2","ext":"","inst":"pi-é","prev":"prev-2","rcv":"local:read","rid":"rid-1","sess":"","svc":"pi","ts":1767225600000,"v":4}');
  check("signingBytes UTF-8", signingBytesCases[1]!.hex.includes(Buffer.from('"pi-é"', "utf8").toString("hex")), true);
  const escaped = signingBytesCases[2]!.text;
  check("signingBytes escapes", [escaped.includes('"inst":"pi-\\"1\\"\\n"'), escaped.includes('"rid":"rid|1"')], [true, true]);

  // The client run: one prompt, an mcp call and a local step. The call's origin acts on example and adds nothing, and
  // its hop adds two items; a receiver that acts on example is handed both.
  const NOW = 1_767_225_600_000;
  const SESS = "sess-1";
  const RID = "rid-1";
  const PROMPT = "open a PR for issue #42";
  const CALL_ID = "call-1";
  const ARGS = { title: "Fix #42", body: "Closes #42", draft: false };
  const HOP_ITEMS: JsonValue[] = [{ note: "n1" }, 7];
  const ORIGIN_BLOCK: BlockJson = { items: { example: [] }, requires: [] };
  const HOP_BLOCK: BlockJson = { items: { example: HOP_ITEMS }, requires: [] };
  const BLOCKS = [ORIGIN_BLOCK, HOP_BLOCK];
  const EXAMPLE = ["example"];
  const HANDED: HandOverJson = { example: entries(["session", []], ["pi", HOP_ITEMS]) };
  const callBind = bindMcpCall(TOOL, CALL_ID, ARGS);
  const originFields = { svc: "session", inst: "pi-1", rid: RID, ts: NOW - 2000, sess: SESS, rcv: "pi", bind: bindPrompt(PROMPT), ext: extOf(ORIGIN_BLOCK), prev: "" };
  const origin = stampBy(originFields, "session");
  const hopFields = (prev: string) => ({ svc: "pi", inst: "pi-1", rid: RID, ts: NOW - 1000, sess: SESS, rcv: CALL_RCV, bind: callBind, ext: extOf(HOP_BLOCK), prev });
  const hop = stampBy(hopFields(origin.sig), "pi");
  const call = [origin, hop];
  /** The call with each stamp's ext given, and `o` in both stamps' fields. */
  const callWith = (exts: [string, string], o: Partial<typeof originFields> = {}): Stamp[] => {
    const first = stampBy({ ...originFields, ext: exts[0], ...o }, "session");
    return [first, stampBy({ ...hopFields(first.sig), ext: exts[1], ...o }, "pi")];
  };
  /** The call signed over `blocks`, each stamp committing to its own. */
  const callOver = (blocks: [BlockJson, BlockJson]) => callWith([extOf(blocks[0]), extOf(blocks[1])]);
  /** The call with its origin's and its hop's times. */
  const callAt = (originTs: number, hopTs: number) => {
    const first = stampBy({ ...originFields, ts: originTs }, "session");
    return [first, stampBy({ ...hopFields(first.sig), ts: hopTs }, "pi")];
  };

  // The server's response to that call, back to pi.
  const respBind = bindResponse(bindResult({ content: [{ type: "text", text: "opened #43" }], isError: false }), CALL_ID);
  const entry = stampBy({ svc: "mcp-entry", inst: "entry-1", rid: RID, ts: NOW - 800, sess: SESS, rcv: "github-tools", bind: callBind, ext: "", prev: "" }, "mcp-entry");
  const toolsFields = { svc: "github-tools", inst: "gh-1", rid: RID, ts: NOW - 500, sess: SESS, rcv: "pi", bind: respBind, ext: "", prev: entry.sig };
  const tools = stampBy(toolsFields, "github-tools");

  // A local step: its own chain, with no session, and no blocks.
  const localBind = bindLocalTool("read", { path: "notes.md" }, { callId: "tc-1", verdict: "OK" });
  const localOrigin = stampBy({ ...originFields, sess: "", ext: "" }, "session");
  const local = [localOrigin, stampBy({ svc: "pi", inst: "pi-1", rid: RID, ts: NOW - 1000, sess: "", rcv: LOCAL_RCV, bind: localBind, ext: "", prev: localOrigin.sig }, "pi")];

  // Two plain HTTP hops in a mesh.
  const HTTP_BIND = "bind-orders-to-payment";
  const gateway = stampBy({ svc: "gateway", inst: "gw-1", rid: "rid-2", ts: NOW - 1500, sess: "sess-2", rcv: "orders", bind: "bind-gateway-to-orders", ext: "", prev: "" }, "gateway");
  const http = [gateway, stampBy({ svc: "orders", inst: "ord-1", rid: "rid-2", ts: NOW - 500, sess: "sess-2", rcv: "payment", bind: HTTP_BIND, ext: "", prev: gateway.sig }, "orders")];

  // Broken variants of the call.
  const strayOrigin = stampBy({ ...originFields, rcv: "search" }, "session");
  const strayCall = [strayOrigin, stampBy(hopFields(strayOrigin.sig), "pi")];
  const forgedCall = [origin, stampBy(hopFields(origin.sig), "session")];
  const strayForgedCall = [strayOrigin, stampBy(hopFields(strayOrigin.sig), "session")];
  // An origin older than the run's lifetime when the call was made.
  const staleOrigin = stampBy({ ...originFields, ts: NOW - 1000 - RUN_MAX_AGE_MS - 1 }, "session");
  const staleCall = [staleOrigin, stampBy(hopFields(staleOrigin.sig), "pi")];
  // The call's stamp `age` ms after the run's origin; a negative age puts the origin after the stamp.
  const windowCall = (age: number) => [origin, stampBy({ ...hopFields(origin.sig), ts: origin.ts + age }, "pi")];
  // Malformed stamps, built by hand: the parse comes before signatures.
  const { rcv: _rcv, ...hopWithoutRcv } = hop;
  const malformed = (last: unknown) => [origin, last] as unknown as Stamp[];
  // A stamp of version 3 beside a current one, and one that carries version 3's `infl` in place of `ext`.
  const wrongVersionCall = [origin, { ...hop, v: 3 }] as unknown as Stamp[];
  const { ext: hopExt, ...hopWithoutExt } = hop;
  const inflCall = malformed({ ...hopWithoutExt, infl: hopExt });

  const CALL_KEY = nonceKey([RID, CALL_ID, "req"]);
  const MESH_KEY = nonceKey(["rid-2", "orders", "payment", "req"]);
  const clientCall: Omit<CaseInputs, "name"> = {
    chain: call, expectedBind: callBind, blocks: BLOCKS, actsOn: EXAMPLE, allowedExtensions: null, policy: "client", proofRoute: CALL_ROUTE,
    receiver: CALL_RCV, receiverInRoute: true, keyring: { session: "session", pi: "pi" }, allowedOrigins: ["session"], sess: SESS, nonceKey: CALL_KEY,
  };
  /** A case that carries no blocks token and acts on nothing, as every chain off the client's call does. */
  const NO_BLOCKS = { blocks: null, actsOn: [], allowedExtensions: null };
  const resolveKeyring = (k: Record<string, KeyName>) => Object.fromEntries(Object.entries(k).map(([svc, name]) => [svc, keys[name].pub]));
  const rootOf = (name: CaseInputs["policy"]) => decode(policies[name].root);
  const proofTokenOf = (c: { policy: CaseInputs["policy"]; proofRoute: string | null }) =>
    c.proofRoute === null ? null : policies[c.policy].proofTokens[c.proofRoute]!;

  /** A verify case's pinned policy window unless it sets its own: 2100-01-01, far past `now`. */
  const PINNED_NOT_AFTER = 4_102_444_800_000;
  type Live = CaseInputs & {
    peer: Peer | null; peers?: (Peer | null)[]; uses: number; policyNotAfter?: number; keyrings?: KeyringPin[];
    roots?: RootPin[];
  };
  /** A live member's window: the format requires an integer. */
  const windowOf = (name: string, notAfter: number | undefined): number => {
    if (notAfter === undefined) throw new Error(`verify ${name}: a live keyring or root has no notAfter`);
    return notAfter;
  };
  const live = (c: Live, expected: Expected) => {
    const nonces = new NonceCache(NONCE_TTL_MS);
    const policyNotAfter = c.policyNotAfter ?? PINNED_NOT_AFTER;
    // one keyring and one root, each with the case's policy window, unless the case pins several (each with its own, in a verify case)
    const cfg = {
      keyrings: c.keyrings === undefined ? [{ keys: resolveKeyring(c.keyring), notAfter: policyNotAfter }]
        : c.keyrings.map((k) => ({ keys: resolveKeyring(k.keyring), notAfter: windowOf(c.name, k.notAfter) })),
      roots: c.roots === undefined ? [{ root: rootOf(c.policy), rootId: policies[c.policy].rootId, notAfter: policyNotAfter }]
        : c.roots.map((r) => ({ root: rootOf(r.policy), rootId: policies[r.policy].rootId, notAfter: windowOf(c.name, r.notAfter) })), allowedOrigins: c.allowedOrigins,
      sess: c.sess, nonces, nonceKey: c.nonceKey, now: NOW, callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS, policyNotAfter,
      extensions: settingsOf(c),
    };
    // the case's policyNotAfter is the pinning factory's: the earlier of the latest keyring and the latest root window
    check(`verify ${c.name} policyNotAfter`, policyNotAfter, pinnedNotAfter(cfg.keyrings, cfg.roots));
    const chainToken = chainTokenOf(c.name, c.chain);
    const blocksToken = blocksTokenOf(c);
    const input = {
      chain: chainToken, expectedBind: c.expectedBind, blocks: blocksToken, proof: proofTokenOf(c),
      receiver: c.receiver, receiverInRoute: c.receiverInRoute,
    };
    // each use is sent by its own peer when the case has `peers`, else by `peer`
    const peers = c.peers ?? Array.from({ length: c.uses }, () => c.peer);
    if (peers.length !== c.uses) throw new Error(`verify ${c.name}: a peer per use`);
    let result: ChainVerification | undefined;
    for (const peer of peers) result = verifyChain(peer === null ? input : { ...input, peer }, cfg);
    check(`verify ${c.name}`, outcomeOf(result!), expected);
    const {
      name, chain, expectedBind, blocks, actsOn, allowedExtensions, policy: p, proofRoute, receiver, receiverInRoute, peer, keyring,
      allowedOrigins, sess, nonceKey: key, uses,
    } = c;
    return {
      name, chain, chainToken, expectedBind, blocks, blocksToken, actsOn, allowedExtensions, policy: p, proofRoute, receiver,
      receiverInRoute, ...(c.peers === undefined ? { peer } : { peers: c.peers }),
      ...(c.keyrings === undefined ? { keyring } : { keyrings: c.keyrings }), ...(c.roots === undefined ? {} : { roots: c.roots }),
      allowedOrigins, sess, nonceKey: key, now: NOW, callMaxAgeMs: CALL_MAX_AGE_MS,
      runMaxAgeMs: RUN_MAX_AGE_MS, nonceTtlMs: NONCE_TTL_MS, policyNotAfter, uses, expected,
    };
  };
  const ok = (svc: string, inst: string, handOver: HandOverJson): Expected =>
    ({ reason: "OK", suspectSvc: svc, suspectInst: inst, handOver });
  const no = (reason: string, svc = "", inst = ""): Expected =>
    ({ reason, suspectSvc: svc, suspectInst: inst, handOver: null });
  const callCase = (name: string, extra: Partial<Live> = {}): Live => ({ name, ...clientCall, peer: null, uses: 1, ...extra });
  /** A call case signed over `blocks`, which it carries. */
  const blocksCase = (name: string, blocks: [BlockJson, BlockJson], extra: Partial<Live> = {}): Live =>
    callCase(name, { chain: callOver(blocks), blocks, ...extra });
  const responseCase: Live = {
    name: "response ok", chain: [entry, tools], expectedBind: respBind, ...NO_BLOCKS, policy: "server", proofRoute: "mcp-entry/github-tools",
    receiver: "pi", receiverInRoute: false, peer: null, keyring: { "mcp-entry": "mcp-entry", "github-tools": "github-tools" },
    allowedOrigins: ["mcp-entry"], sess: SESS, nonceKey: nonceKey([RID, CALL_ID, "resp"]), uses: 1,
  };
  const SEARCH: Peer = { svc: "search", inst: "10.0.0.9" };
  const PI: Peer = { svc: "pi", inst: "10.0.0.7" };
  // Blocks the cases below alter or extend: the hop's item altered after signing; the hop also naming influence, an
  // opaque second name; the hop, or the origin, requiring influence; a requires-only hop; a hop listing constructor.
  const ALTERED: BlockJson[] = [ORIGIN_BLOCK, { items: { example: [{ note: "n2" }, 7] }, requires: [] }];
  const WITH_INFLUENCE: BlockJson = { items: { example: HOP_ITEMS, influence: [{ note: "i1" }] }, requires: [] };
  const HOP_REQUIRES: BlockJson = { items: { example: HOP_ITEMS }, requires: ["influence"] };
  const ORIGIN_REQUIRES: BlockJson = { items: { example: [] }, requires: ["influence"] };
  const CONSTRUCTOR_ITEMS: JsonValue[] = [{ note: "c1" }];
  const NO_HAND_OVER = { example: entries(["session", null], ["pi", null]) };
  const verify = [
    live(callCase("mcp call ok"), ok("pi", "pi-1", HANDED)),
    live(
      {
        name: "http hops ok", chain: http, expectedBind: HTTP_BIND, ...NO_BLOCKS, policy: "mesh", proofRoute: "gateway/orders/payment",
        receiver: "payment", receiverInRoute: true, peer: null, keyring: { gateway: "gateway", orders: "orders" }, allowedOrigins: ["gateway"],
        sess: "sess-2", nonceKey: MESH_KEY, uses: 1,
      },
      ok("orders", "ord-1", {}),
    ),
    live(responseCase, ok("github-tools", "gh-1", {})),
    live(
      callCase("local step ok", {
        chain: local, expectedBind: localBind, ...NO_BLOCKS, proofRoute: LOCAL_ROUTE, receiver: LOCAL_RCV, sess: "", nonceKey: nonceKey([RID, "tc-1", "local"]),
      }),
      ok("pi", "pi-1", {}),
    ),
    live(callCase("receiver chain broken", { chain: strayCall }), no("BINDING_MISMATCH")),
    live(callCase("wrong receiver", { receiver: OTHER_RCV }), no("BINDING_MISMATCH")),
    live(callCase("peer ok", { peer: PI }), ok("pi", "10.0.0.7", HANDED)),
    live(callCase("peer mismatch", { peer: SEARCH }), no("PEER_MISMATCH", "search", "10.0.0.9")),
    live(callCase("peer blamed on bad signature", { chain: forgedCall, peer: SEARCH }), no("BAD_SIGNATURE", "search", "10.0.0.9")),
    live(callCase("no peer, bad signature", { chain: forgedCall }), no("BAD_SIGNATURE")),
    live(callCase("no peer, path not allowed", { proofRoute: OTHER_ROUTE }), no("PATH_NOT_ALLOWED", "pi", "pi-1")),
    live(callCase("replay", { uses: 2 }), no("REPLAY")),
    live(callCase("an item altered", { blocks: ALTERED }), no("EXTENSION_MISMATCH")),
    // Refusals no other case reaches: checks 3, 4 (the link), 5 and 6.
    live(callCase("an origin that is not allowed", { allowedOrigins: ["gateway"] }), no("BAD_ORIGIN")),
    live(callCase("a stamp linked to another origin", { chain: [origin, stampBy(hopFields(strayOrigin.sig), "pi")] }), no("BROKEN_LINK")),
    live(callCase("a stamp with another rid", { chain: [origin, stampBy({ ...hopFields(origin.sig), rid: "rid-other" }, "pi")] }), no("RID_MISMATCH")),
    live(callCase("a stamp from another session", { sess: "sess-other" }), no("SESSION_UNKNOWN")),
    // The check order: signatures before receivers; the peer before the route.
    live(callCase("bad signature beats bad receiver", { chain: strayForgedCall }), no("BAD_SIGNATURE")),
    live(callCase("the peer fails before the route", { proofRoute: OTHER_ROUTE, peer: SEARCH }), no("PEER_MISMATCH", "search", "10.0.0.9")),
    live({ ...responseCase, name: "response to wrong receiver", receiver: "other" }, no("BINDING_MISMATCH")),
    // Operations named in rcv: a hop addresses the next service, with an operation of it or none, and the route carries them.
    ...(() => {
      const opsCase = (name: string, firstRcv: string, receiver: string, expected: Expected) => {
        const first = stampBy({ svc: "gateway", inst: "gw-1", rid: "rid-2", ts: NOW - 1500, sess: "sess-2", rcv: firstRcv, bind: "bind-gateway-to-orders", ext: "", prev: "" }, "gateway");
        const chain = [first, stampBy({ svc: "orders", inst: "ord-1", rid: "rid-2", ts: NOW - 500, sess: "sess-2", rcv: "payment#charge", bind: HTTP_BIND, ext: "", prev: first.sig }, "orders")];
        return live(
          {
            name, chain, expectedBind: HTTP_BIND, ...NO_BLOCKS, policy: "ops", proofRoute: "gateway/orders#createOrder/payment#charge", receiver,
            receiverInRoute: true, peer: null, keyring: { gateway: "gateway", orders: "orders" }, allowedOrigins: ["gateway"], sess: "sess-2",
            nonceKey: nonceKey(["rid-2", "orders", "payment#charge", "req"]), uses: 1,
          },
          expected,
        );
      };
      return [
        opsCase("an operation named in rcv", "orders#createOrder", "payment#charge", ok("orders", "ord-1", {})),
        opsCase("a chain naming another operation", "orders#createOrder", "payment#refund", no("BINDING_MISMATCH")),
        opsCase("an operation, at a receiver that names none", "orders#createOrder", "payment", no("BINDING_MISMATCH")),
        opsCase("an inner rcv naming another service's operation", "search#find", "payment#charge", no("BINDING_MISMATCH")),
        opsCase("an empty operation", "orders#", "payment#charge", no("BINDING_MISMATCH")),
        opsCase("an inner operation holding a `/`", "orders#a/b", "payment#charge", no("BINDING_MISMATCH")),
        opsCase("an inner operation holding a `#`", "orders#a#b", "payment#charge", no("BINDING_MISMATCH")),
        // An operation is a route node, which holds no `|`: the signed bytes take it, the receiver check refuses it.
        opsCase("an inner operation holding a `|`", "orders#a|b", "payment#charge", no("BINDING_MISMATCH")),
        opsCase("a proof for another operation's route", "orders#getOrder", "payment#charge", no("PATH_NOT_ALLOWED", "orders", "ord-1")),
      ];
    })(),
    // Malformed stamps: a version 3 stamp, or a field of another type or missing, does not read.
    live(callCase("a stamp whose v is 3", { chain: wrongVersionCall }), no("CHAIN_MISSING")),
    live(callCase("a stamp with infl in place of ext", { chain: inflCall }), no("CHAIN_MISSING")),
    live(callCase("stamp with no rcv", { chain: malformed(hopWithoutRcv) }), no("CHAIN_MISSING")),
    live(callCase("non-string rcv", { chain: malformed({ ...hop, rcv: 7 }) }), no("CHAIN_MISSING")),
    // A `|` is no delimiter in version 4's signed bytes: in rid and inst it signs and verifies, and a service named with
    // one is looked up like any other name, and has no key.
    live(
      callCase("a `|` in rid and inst", { chain: callWith([extOf(ORIGIN_BLOCK), extOf(HOP_BLOCK)], { rid: "rid|1", inst: "pi|1" }), nonceKey: nonceKey(["rid|1", CALL_ID, "req"]) }),
      ok("pi", "pi|1", HANDED),
    ),
    live(callCase("a `|` in a service name that has no key", { chain: [origin, stampBy({ ...hopFields(origin.sig), svc: "p|i" }, "pi")] }), no("BAD_SIGNATURE")),
    // A ts out of the safe-integer range, at the low end a 64-bit reader could take for a long.
    live(callCase(TS_MIN_CASE, { chain: malformed({ ...hop, ts: -(2 ** 63) }) }), no("CHAIN_MISSING")),
    // Freshness at its bounds: the origin at the run's lifetime and 1 ms past it, and the last stamp at the call window,
    // 1 ms past it, and 1 ms ahead of it.
    live(callCase("an origin at the run's lifetime", { chain: callAt(NOW - RUN_MAX_AGE_MS, NOW - 1000) }), ok("pi", "pi-1", HANDED)),
    live(callCase("an origin 1 ms past the run's lifetime", { chain: callAt(NOW - RUN_MAX_AGE_MS - 1, NOW - 1000) }), no("EXPIRED")),
    live(callCase("a last stamp at the call window", { chain: callAt(NOW - 6000, NOW - CALL_MAX_AGE_MS) }), ok("pi", "pi-1", HANDED)),
    live(callCase("a last stamp 1 ms past the call window", { chain: callAt(NOW - 6000, NOW - CALL_MAX_AGE_MS - 1) }), no("EXPIRED")),
    live(callCase("a last stamp 1 ms ahead of the call window", { chain: callAt(NOW - 2000, NOW + CALL_MAX_AGE_MS + 1) }), no("EXPIRED")),
    // the origin's third limit: at most the call window after now, though the last stamp is within it
    live(callCase("an origin the call window ahead of now", { chain: callAt(NOW + CALL_MAX_AGE_MS, NOW) }), ok("pi", "pi-1", HANDED)),
    live(callCase("an origin 1 ms more than the call window ahead of now", { chain: callAt(NOW + CALL_MAX_AGE_MS + 1, NOW) }), no("EXPIRED")),
    // A call id is hashed content and a nonce key the verifier's own text, so one holding a noncharacter verifies.
    ...(() => {
      const callId = "call-\uFFFF";
      const bind = bindMcpCall(TOOL, callId, ARGS);
      const first = stampBy(originFields, "session");
      const chain = [first, stampBy({ ...hopFields(first.sig), bind }, "pi")];
      return [live(callCase(NONCHARACTER_CASE, { chain, expectedBind: bind, nonceKey: nonceKey([RID, callId, "req"]) }), ok("pi", "pi-1", HANDED))];
    })(),
    // The verifier's own pinned policy: checked before the stamps, and naming no one, not even a peer.
    live(callCase("at policy notAfter", { policyNotAfter: NOW }), ok("pi", "pi-1", HANDED)),
    live(callCase("policy expired", { policyNotAfter: NOW - 1 }), no("POLICY_EXPIRED")),
    live(callCase("policy expired beats bad signature, names no peer", { policyNotAfter: NOW - 1, chain: forgedCall, peer: SEARCH }), no("POLICY_EXPIRED")),
    live(callCase("policy expired beats a malformed chain", { policyNotAfter: NOW - 1, chain: [] }), no("POLICY_EXPIRED")),
    live(callCase("policy notAfter out of range", { policyNotAfter: 2 ** 53 }), no("POLICY_EXPIRED")),
    // Several keyrings and roots, each with its own window: current ones end at PINNED_NOT_AFTER, expired ones 1 ms before `now`.
    // The mesh chain is pinned under the mesh keyring and root and the second tree; `policy` names where the proof comes from.
    ...(() => {
      const EXPIRED = NOW - 1;
      const meshCase = (name: string, extra: Partial<Live>): Live => ({
        name, chain: http, expectedBind: HTTP_BIND, ...NO_BLOCKS, policy: "mesh", proofRoute: "gateway/orders/payment", receiver: "payment",
        receiverInRoute: true, peer: null, keyring: { gateway: "gateway", orders: "orders" }, allowedOrigins: ["gateway"], sess: "sess-2",
        nonceKey: MESH_KEY, uses: 1, ...extra,
      });
      const ring = (keyring: Record<string, KeyName>, notAfter: number): KeyringPin => ({ keyring, notAfter });
      const rootPin = (policy: PolicyName, notAfter: number): RootPin => ({ policy, notAfter });
      const meshRing = { gateway: "gateway", orders: "orders" } as const;
      const bothRoots = [rootPin("mesh", PINNED_NOT_AFTER), rootPin("mesh-second", PINNED_NOT_AFTER)];
      // the mesh chain's second hop, signed by the rotated key
      const ordersNext = [gateway, stampBy({ svc: "orders", inst: "ord-1", rid: "rid-2", ts: NOW - 500, sess: "sess-2", rcv: "payment", bind: HTTP_BIND, ext: "", prev: gateway.sig }, "orders-next")];
      return [
        live(meshCase("a proof under the second pinned root", { policy: "mesh-second", keyrings: [ring(meshRing, PINNED_NOT_AFTER)], roots: bothRoots }), ok("orders", "ord-1", {})),
        live(meshCase("a proof whose rootId is pinned nowhere", { keyrings: [ring(meshRing, PINNED_NOT_AFTER)], roots: [rootPin("mesh-second", PINNED_NOT_AFTER), rootPin("client", PINNED_NOT_AFTER)] }), no("PATH_NOT_ALLOWED", "orders", "ord-1")),
        live(meshCase("a rotated key only in the second keyring", {
          chain: ordersNext, keyrings: [ring(meshRing, PINNED_NOT_AFTER), ring({ orders: "orders-next" }, PINNED_NOT_AFTER)], roots: bothRoots,
        }), ok("orders", "ord-1", {})),
        live(meshCase("a chain whose keys come from two keyrings", {
          keyrings: [ring({ gateway: "gateway" }, PINNED_NOT_AFTER), ring({ orders: "orders" }, PINNED_NOT_AFTER)], roots: bothRoots,
        }), ok("orders", "ord-1", {})),
        live(meshCase("a proof under an expired root while another is current", {
          keyrings: [ring(meshRing, PINNED_NOT_AFTER)], roots: [rootPin("mesh", EXPIRED), rootPin("mesh-second", PINNED_NOT_AFTER)],
        }), no("PATH_NOT_ALLOWED", "orders", "ord-1")),
        live(meshCase("a key only in an expired keyring", {
          keyrings: [ring(meshRing, EXPIRED), ring({ gateway: "gateway", orders: "orders-next" }, PINNED_NOT_AFTER)], roots: bothRoots,
        }), no("BAD_SIGNATURE")),
        // a renewal keeps the rootId and the root, so the expired member and the current one are one tree
        live(meshCase("one root expired and one current", {
          keyrings: [ring(meshRing, PINNED_NOT_AFTER)], roots: [rootPin("mesh", EXPIRED), rootPin("mesh", PINNED_NOT_AFTER)],
        }), ok("orders", "ord-1", {})),
        live(meshCase("every keyring expired", {
          policyNotAfter: EXPIRED, keyrings: [ring(meshRing, EXPIRED), ring({ orders: "orders-next" }, EXPIRED)], roots: bothRoots,
        }), no("POLICY_EXPIRED")),
        live(meshCase("every root expired", {
          policyNotAfter: EXPIRED, keyrings: [ring(meshRing, PINNED_NOT_AFTER)], roots: [rootPin("mesh", EXPIRED), rootPin("mesh-second", EXPIRED)],
        }), no("POLICY_EXPIRED")),
        live(meshCase("a proof relabelled with the other pinned root's rootId", {
          policy: "mesh-relabelled", keyrings: [ring(meshRing, PINNED_NOT_AFTER)], roots: bothRoots,
        }), no("PATH_NOT_ALLOWED", "orders", "ord-1")),
      ];
    })(),
    // Blocks (check 9a): an absent token is one empty block per stamp, which a stamp committing to a block refuses;
    // every block is matched to its own stamp, and must read as a block.
    ...(() => {
      const emptyCall = callWith(["", ""]);
      return [
        live(callCase("no blocks token, every ext empty", { chain: emptyCall, ...NO_BLOCKS }), ok("pi", "pi-1", {})),
        live(callCase("no blocks token, every ext empty, at a receiver acting on example", { chain: emptyCall, blocks: null }), ok("pi", "pi-1", NO_HAND_OVER)),
        live(callCase("an array of empty blocks", { chain: emptyCall, blocks: [EMPTY, EMPTY] }), ok("pi", "pi-1", NO_HAND_OVER)),
        // the token holds JSON null, which is no array of blocks, not an absent token
        live(callCase(NULL_BLOCKS_CASE, { chain: emptyCall, blocks: null, blocksToken: tokenOf(null) }), no("EXTENSION_MISMATCH")),
        live(callCase("no blocks token where a stamp commits to a block", { blocks: null }), no("EXTENSION_MISMATCH")),
        // the empty block's commitment is "", never the hash of its JCS
        live(callCase("ext the hash of the empty block", { chain: callWith(["", hashOf(EMPTY)]), blocks: [EMPTY, EMPTY] }), no("EXTENSION_MISMATCH")),
        live(callCase("one block too few", { blocks: [ORIGIN_BLOCK] }), no("EXTENSION_MISMATCH")),
        // the missing block would be the empty block, which the last stamp commits to: still one block per stamp
        live(
          callCase("one block for two stamps, the stamp without one committing to the empty block", {
            chain: callWith([extOf(ORIGIN_BLOCK), ""]), blocks: [ORIGIN_BLOCK],
          }),
          no("EXTENSION_MISMATCH"),
        ),
        live(callCase("one block too many", { blocks: [ORIGIN_BLOCK, HOP_BLOCK, EMPTY] }), no("EXTENSION_MISMATCH")),
        live(callCase("the two blocks swapped", { blocks: [HOP_BLOCK, ORIGIN_BLOCK] }), no("EXTENSION_MISMATCH")),
        // the base blocks' JCS bytes after a space: the hashes would match, but the token is not canonical bytes
        live(callCase(UNREADABLE_BLOCKS_CASE, { blocks: null, blocksToken: encode(utf8(" " + canonicalize(BLOCKS))) }), no("EXTENSION_MISMATCH")),
        // signed over its JCS, so only the block schema refuses it
        ...(() => {
          const extra = { ...HOP_BLOCK, note: "n1" };
          const chain = callWith([extOf(ORIGIN_BLOCK), hashOf(extra)]);
          return [live(callCase(EXTRA_MEMBER_CASE, { chain, blocks: [ORIGIN_BLOCK, extra] }), no("EXTENSION_MISMATCH"))];
        })(),
      ];
    })(),
    // The names (checks 9b and 9c), and what is handed over on OK.
    live(blocksCase("a name the allowed list does not hold, in items", [ORIGIN_BLOCK, WITH_INFLUENCE], { allowedExtensions: EXAMPLE }), no("EXTENSION_NOT_ALLOWED")),
    live(blocksCase("a name the allowed list does not hold, only in the first block's requires", [ORIGIN_REQUIRES, HOP_BLOCK], { allowedExtensions: EXAMPLE }), no("EXTENSION_NOT_ALLOWED")),
    live(blocksCase("a name not allowed by a list, with no list: carried, not handed over", [ORIGIN_BLOCK, WITH_INFLUENCE]), ok("pi", "pi-1", HANDED)),
    live(blocksCase("the caller requires an extension the receiver does not act on", [ORIGIN_BLOCK, HOP_REQUIRES]), no("EXTENSION_REQUIRED")),
    live(blocksCase("an earlier block requires it, the caller's does not", [ORIGIN_REQUIRES, HOP_BLOCK]), ok("pi", "pi-1", HANDED)),
    live(blocksCase("the caller requires constructor", [ORIGIN_BLOCK, { items: { example: HOP_ITEMS }, requires: ["constructor"] }]), no("EXTENSION_REQUIRED")),
    live(callCase("the receiver acts on constructor, no block lists it", { actsOn: ["constructor"] }), ok("pi", "pi-1", { constructor: entries(["session", null], ["pi", null]) })),
    live(
      blocksCase("a block lists constructor", [ORIGIN_BLOCK, { items: { constructor: CONSTRUCTOR_ITEMS }, requires: [] }], { actsOn: ["constructor"] }),
      ok("pi", "pi-1", { constructor: entries(["session", null], ["pi", CONSTRUCTOR_ITEMS]) }),
    ),
    live(
      blocksCase("a block lists constructor, the allowed list does not", [ORIGIN_BLOCK, { items: { constructor: CONSTRUCTOR_ITEMS }, requires: [] }], { allowedExtensions: EXAMPLE }),
      no("EXTENSION_NOT_ALLOWED"),
    ),
    live(
      blocksCase("a block that only requires example, at a receiver that acts on it", [ORIGIN_BLOCK, { items: {}, requires: ["example"] }]),
      ok("pi", "pi-1", { example: entries(["session", []], ["pi", null]) }),
    ),
    live(
      blocksCase("a block naming example and influence, at a receiver acting on both", [ORIGIN_BLOCK, WITH_INFLUENCE], { actsOn: ["example", "influence"] }),
      ok("pi", "pi-1", { ...HANDED, influence: entries(["session", null], ["pi", [{ note: "i1" }]]) }),
    ),
    // The order among checks 8 to 10.
    live(callCase("a wrong binding and altered blocks", { expectedBind: bindMcpCall(TOOL, CALL_ID, { ...ARGS, draft: true }), blocks: ALTERED }), no("BINDING_MISMATCH")),
    live(callCase("altered blocks and a name not allowed", { blocks: [ORIGIN_BLOCK, WITH_INFLUENCE], allowedExtensions: EXAMPLE }), no("EXTENSION_MISMATCH")),
    live(blocksCase("a name not allowed and a requirement not met", [ORIGIN_BLOCK, HOP_REQUIRES], { allowedExtensions: EXAMPLE }), no("EXTENSION_NOT_ALLOWED")),
    live(blocksCase("a requirement not met and a wrong peer", [ORIGIN_BLOCK, HOP_REQUIRES], { peer: SEARCH }), no("EXTENSION_REQUIRED", "search", "10.0.0.9")),
    live(callCase("a block mismatch and a wrong peer", { blocks: ALTERED, peer: SEARCH }), no("EXTENSION_MISMATCH", "search", "10.0.0.9")),
    // The nonce: a request sent again by another peer spends nothing, so its signer's own sending after it verifies;
    // a key is spent before the route is checked.
    live(callCase("sent by another peer, then by its signer", { peers: [SEARCH, PI], uses: 2 }), ok("pi", "10.0.0.7", HANDED)),
    live(callCase("sent by another peer, then twice by its signer", { peers: [SEARCH, PI, PI], uses: 3 }), no("REPLAY", "pi", "10.0.0.7")),
    live(callCase("no proof, twice", { proofRoute: null, uses: 2 }), no("REPLAY")),
  ];

  /** An offline case; the recorded time defaults to the last stamp's, the prompt to the run's, and `seen` to none. */
  type Offline = CaseInputs & {
    recordedTs?: { last: number } | null; prompt?: string; seen?: string[]; limits?: null; rid?: string; keyrings?: KeyringPin[]; roots?: RootPin[];
  };
  const offlineCase = (c: Offline, expected: Expected) => {
    // recordedTs null: the record has no time; limits null: neither age limit is configured, so the live defaults apply
    const recordedTs = c.recordedTs === undefined ? { last: c.chain[c.chain.length - 1]!.ts } : c.recordedTs;
    const callMaxAgeMs = c.limits === null ? null : CALL_MAX_AGE_MS;
    const runMaxAgeMs = c.limits === null ? null : RUN_MAX_AGE_MS;
    const prompt = c.prompt ?? PROMPT;
    const seen = c.seen ?? [];
    const chainToken = chainTokenOf(c.name, c.chain);
    const blocksToken = blocksTokenOf(c);
    const result = verifyChainOffline(
      {
        chain: chainToken, expectedBind: c.expectedBind, blocks: blocksToken, proof: proofTokenOf(c),
        receiver: c.receiver, receiverInRoute: c.receiverInRoute, rid: c.rid ?? RID, recordedTs: (recordedTs ?? undefined) as never, prompt,
      },
      {
        // one keyring and one root, each with no window, unless the case pins several (a member without notAfter has none)
        keyrings: c.keyrings === undefined ? [{ keys: resolveKeyring(c.keyring), notAfter: Infinity }]
          : c.keyrings.map((k) => ({ keys: resolveKeyring(k.keyring), notAfter: k.notAfter ?? Infinity })),
        roots: c.roots === undefined ? [{ root: rootOf(c.policy), rootId: policies[c.policy].rootId, notAfter: Infinity }]
          : c.roots.map((r) => ({ root: rootOf(r.policy), rootId: policies[r.policy].rootId, notAfter: r.notAfter ?? Infinity })), allowedOrigins: c.allowedOrigins, sess: c.sess,
        nonceKey: c.nonceKey, seen: new Set(seen), callMaxAgeMs: callMaxAgeMs ?? undefined, runMaxAgeMs: runMaxAgeMs ?? undefined,
        extensions: settingsOf(c),
      },
    );
    check(`offline ${c.name}`, outcomeOf(result), expected);
    const {
      name, chain, expectedBind, blocks, actsOn, allowedExtensions, policy: p, proofRoute, receiver, receiverInRoute, keyring, allowedOrigins,
      sess, nonceKey: key,
    } = c;
    return {
      name, chain, chainToken, expectedBind, blocks, blocksToken, actsOn, allowedExtensions, policy: p, proofRoute, receiver,
      receiverInRoute, ...(c.keyrings === undefined ? { keyring } : { keyrings: c.keyrings }), ...(c.roots === undefined ? {} : { roots: c.roots }),
      allowedOrigins, sess, nonceKey: key, seen, callMaxAgeMs,
      runMaxAgeMs, rid: c.rid ?? RID, recordedTs, prompt, expected,
    };
  };
  const offline = [
    offlineCase({ name: "recorded call", ...clientCall }, ok("pi", "pi-1", HANDED)),
    offlineCase({ name: "a stamp whose v is 3", ...clientCall, chain: wrongVersionCall }, no("CHAIN_MISSING")),
    offlineCase({ name: "receiver chain broken", ...clientCall, chain: strayCall }, no("BINDING_MISMATCH")),
    offlineCase({ name: "recorded time differs", ...clientCall, recordedTs: { last: hop.ts + 1 } }, no("TIME_MISMATCH")),
    offlineCase({ name: "expired", ...clientCall, chain: staleCall }, no("EXPIRED")),
    offlineCase({ name: "no recorded time", ...clientCall, recordedTs: null }, no("TIME_MISMATCH")),
    offlineCase({ name: "no age limits, at the run window", ...clientCall, chain: windowCall(RUN_MAX_AGE_MS), limits: null }, ok("pi", "pi-1", HANDED)),
    offlineCase({ name: "no age limits, 1 ms past the run window", ...clientCall, chain: windowCall(RUN_MAX_AGE_MS + 1), limits: null }, no("EXPIRED")),
    offlineCase({ name: "no age limits, at the call window", ...clientCall, chain: windowCall(-CALL_MAX_AGE_MS), limits: null }, ok("pi", "pi-1", HANDED)),
    offlineCase({ name: "no age limits, 1 ms past the call window", ...clientCall, chain: windowCall(-CALL_MAX_AGE_MS - 1), limits: null }, no("EXPIRED")),
    offlineCase({ name: "prompt differs", ...clientCall, prompt: "open a PR for issue #43" }, no("PROMPT_MISMATCH")),
    offlineCase({ name: "replay in the record set", ...clientCall, seen: [clientCall.nonceKey] }, no("REPLAY")),
    // Blocks offline: 9a, and 9b with a list of the verifier's own; 9c is live only.
    offlineCase({ name: "an item altered", ...clientCall, blocks: ALTERED }, no("EXTENSION_MISMATCH")),
    offlineCase(
      { name: "a name the allowed list does not hold", ...clientCall, chain: callOver([ORIGIN_BLOCK, WITH_INFLUENCE]), blocks: [ORIGIN_BLOCK, WITH_INFLUENCE], allowedExtensions: EXAMPLE },
      no("EXTENSION_NOT_ALLOWED"),
    ),
    offlineCase(
      { name: "a name not allowed by a list, with no list", ...clientCall, chain: callOver([ORIGIN_BLOCK, WITH_INFLUENCE]), blocks: [ORIGIN_BLOCK, WITH_INFLUENCE] },
      ok("pi", "pi-1", HANDED),
    ),
    offlineCase(
      { name: "the caller requires an extension the verifier does not act on", ...clientCall, chain: callOver([ORIGIN_BLOCK, HOP_REQUIRES]), blocks: [ORIGIN_BLOCK, HOP_REQUIRES], actsOn: [] },
      ok("pi", "pi-1", {}),
    ),
    // Several roots, each with its own window; the record's time is its last stamp's. The mesh run starts from the prompt.
    ...(() => {
      const origin2 = stampBy({ svc: "gateway", inst: "gw-1", rid: RID, ts: NOW - 1500, sess: "sess-2", rcv: "orders", bind: bindPrompt(PROMPT), ext: "", prev: "" }, "gateway");
      const meshRun = [origin2, stampBy({ svc: "orders", inst: "ord-1", rid: RID, ts: NOW - 500, sess: "sess-2", rcv: "payment", bind: HTTP_BIND, ext: "", prev: origin2.sig }, "orders")];
      const recorded = meshRun[1]!.ts;
      const meshOffline = (name: string, roots: RootPin[], policy: PolicyName): Offline => ({
        name, chain: meshRun, expectedBind: HTTP_BIND, ...NO_BLOCKS, policy, proofRoute: "gateway/orders/payment", receiver: "payment",
        receiverInRoute: true, keyring: { gateway: "gateway", orders: "orders" }, allowedOrigins: ["gateway"], sess: "sess-2",
        nonceKey: nonceKey([RID, "orders", "payment", "req"]), roots,
      });
      return [
        // the first root's window ends 1 ms before the record, the second has none
        offlineCase(meshOffline("a record within only the second root's window", [{ policy: "mesh", notAfter: recorded - 1 }, { policy: "mesh-second" }], "mesh-second"), ok("orders", "ord-1", {})),
        offlineCase(meshOffline("a record past every root's window", [{ policy: "mesh", notAfter: recorded - 1 }, { policy: "mesh-second", notAfter: recorded - 1 }], "mesh-second"), no("POLICY_EXPIRED")),
        // windows are judged at the record's time, and a window ending at it still counts
        offlineCase(meshOffline("a record at the second root's notAfter", [{ policy: "mesh", notAfter: recorded - 1 }, { policy: "mesh-second", notAfter: recorded }], "mesh-second"), ok("orders", "ord-1", {})),
        offlineCase({
          ...meshOffline("a record past every keyring's window", [{ policy: "mesh-second" }], "mesh-second"),
          keyrings: [{ keyring: { gateway: "gateway" }, notAfter: recorded - 1 }, { keyring: { orders: "orders" }, notAfter: recorded - 1 }],
        }, no("POLICY_EXPIRED")),
        // offline check 0 runs before the chain is read
        offlineCase({
          ...meshOffline("a record past every root's window, its chain malformed", [{ policy: "mesh", notAfter: recorded - 1 }, { policy: "mesh-second", notAfter: recorded - 1 }], "mesh-second"),
          chain: [], recordedTs: { last: recorded },
        }, no("POLICY_EXPIRED")),
      ];
    })(),
  ];

  const signatures = [
    { fields: originFields, key: "session" },
    { fields: hopFields(origin.sig), key: "pi" },
    { fields: toolsFields, key: "github-tools" },
  ].map((c) => {
    const sig = encode(sign(keys[c.key as KeyName].priv, signingBytes({ v: 4, ...c.fields })));
    check(`signature by ${c.key}`, sig, [origin, hop, tools].find((s) => s.svc === c.fields.svc)!.sig);
    return { ...c, sig };
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
    const signedBytes = bytes === null ? null : encode(bytes);
    const sig = signed.sig;
    return { name, policyKey: "client-policy", services, signingBytes: signedBytes, sig, signed, file, verifies, ...current };
  };
  const tamperedServices = { session: "session", pi: "gateway" } as const;
  // A keyring genuinely signed over a service name that is not a route node. signKeyring refuses it, so the signature is made over
  // keyringSigningBytes directly: only the name rule, never the signature, refuses what is signed here.
  const badNameServices = { "a/b": "session", pi: "pi" } as const;
  const signedOverBadName = (notAfter: number): SignedKeyring => {
    const resolved = resolveKeyring(badNameServices);
    return { policy: ringPolicy, services: resolved, sig: encode(sign(keys["client-policy"].priv, keyringSigningBytes(ringPolicy, resolved, notAfter))), notAfter };
  };
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
    keyringFormCase(NOT_A_NODE_CASE, signedOverBadName(POLICY_NOT_AFTER), false, undefined, badNameServices),
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
    const signedBytes = bytes === null ? null : encode(bytes);
    return { name, policyKey: "client-policy", policy: "client", signingBytes: signedBytes, signed, file, verifies, ...current };
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
    const signedBytes = bytes ?? null;
    return { name, signer, pin: "server-policy", cert, file, signingBytes: signedBytes, verifies };
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
  // The server keyring signed over a name that is not a route node (signKeyring refuses it), in an otherwise valid entry-key reply.
  const badNameReply = () => {
    const services = { ...serverRingServices, "a/b": keys["github-tools"].pub };
    const sig = encode(sign(keys["server-policy"].priv, keyringSigningBytes(keys["server-policy"].pub, services, LIVE_NOT_AFTER)));
    return reply("mcp-entry", { serverKeyring: services, serverKeyringSig: sig });
  };
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
      serverKeyringNotAfter: LIVE_NOT_AFTER, serverReplyCert: entryCert, nonce: SERVER_NONCE, sess: sessFor(root), status: "attested", disabled: [],
      extensions: [], ...o,
    };
    for (const f of drop) delete body[f];
    return signAnyReply(body, keys[signer].priv) as unknown as Record<string, unknown>;
  };
  // The keyring's signature and its window travel together: neither is in the policy-key form.
  const NO_RING_SIG = ["serverKeyringSig", "serverKeyringNotAfter"];
  const POLICY_KEY_FORM = [...NO_RING_SIG, "serverReplyCert"];
  const sessionReplyCase = (
    name: string, raw: Record<string, unknown>, expected: ReplyCheck,
    o: { pin?: KeyName; serverEntry?: string; now?: number; requires?: string[] } = {},
  ) => {
    const pin = o.pin ?? "server-policy";
    const serverEntry = o.serverEntry ?? "mcp-entry";
    const now = o.now ?? NOW;
    const requestToken = tokenOf(request);
    const replyToken = tokenOf(raw);
    const read = readSessionRequest(requestToken);
    const got = checkSessionReply(replyToken, read, keys[pin].pub, serverEntry, now, o.requires);
    check(`session reply ${name}`, got, expected);
    // Offline the same reply opened an attested session exactly when steps 1 to 4 pass: step 5 is live only.
    const attested = isAttestedSession(read, replyToken, keys[pin].pub, serverEntry, now);
    check(`session reply ${name}, offline`, attested, expected === "ATTESTED" || expected === "EXTENSION_REQUIRED");
    const requires = o.requires === undefined ? {} : { requires: o.requires };
    return { name, request, requestToken, reply: raw, replyToken, pin, serverEntry, now, ...requires, expected };
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
    // Signed over the bad name by the server policy key, and the reply by the entry key: only the name rule refuses it.
    sessionReplyCase(NOT_A_NODE_CASE, badNameReply(), "MALFORMED_REPLY"),
    // The extensions the server acts on: signed, and read as extension names, sorted, none twice.
    sessionReplyCase("extensions missing", reply("mcp-entry", {}, ["extensions"]), "MALFORMED_REPLY"),
    sessionReplyCase("extensions null", reply("mcp-entry", { extensions: null }), "MALFORMED_REPLY"),
    sessionReplyCase("extensions unsorted", reply("mcp-entry", { extensions: ["influence", "example"] }), "MALFORMED_REPLY"),
    sessionReplyCase("extensions naming one twice", reply("mcp-entry", { extensions: ["example", "example"] }), "MALFORMED_REPLY"),
    sessionReplyCase("extensions naming Example", reply("mcp-entry", { extensions: ["Example"] }), "MALFORMED_REPLY"),
    sessionReplyCase("extensions not an array", reply("mcp-entry", { extensions: "example" }), "MALFORMED_REPLY"),
    sessionReplyCase("extensions changed after signing", { ...reply("mcp-entry", { extensions: ["influence"] }), extensions: [] }, "BAD_SIGNATURE"),
    // Step 5: an attested reply lists every extension the client requires; it comes after the status (step 4) and
    // after the pin (step 2).
    sessionReplyCase("attested, listing what the client requires", reply("mcp-entry", { extensions: ["influence"] }), "ATTESTED", { requires: ["influence"] }),
    sessionReplyCase(
      "attested, listing more than the client requires", reply("mcp-entry", { extensions: ["example", "influence"] }), "ATTESTED", { requires: ["influence"] },
    ),
    sessionReplyCase("attested, listing nothing the client requires", reply("mcp-entry"), "EXTENSION_REQUIRED", { requires: ["influence"] }),
    sessionReplyCase(
      "attested, listing one of two the client requires", reply("mcp-entry", { extensions: ["influence"] }), "EXTENSION_REQUIRED",
      { requires: ["example", "influence"] },
    ),
    sessionReplyCase(
      "unsafe, listing what the client requires", reply("mcp-entry", { status: "unsafe", disabled: [TOOL], extensions: ["influence"] }), "UNSAFE",
      { requires: ["influence"] },
    ),
    sessionReplyCase("another key's reply, to a client with a requirement", reply("mcp-entry"), "PIN_MISMATCH", { pin: "client-policy", requires: ["influence"] }),
    // Steps 1 and 3 come before step 5 too: each reply lists nothing, so checking the requirement early would give
    // EXTENSION_REQUIRED.
    sessionReplyCase(
      "the server's root expired, to a client with a requirement", reply("mcp-entry", { serverRoot: serverRootUntil(NOW - 1) }), "BAD_SIGNATURE",
      { requires: ["influence"] },
    ),
    sessionReplyCase("extensions missing, to a client with a requirement", reply("mcp-entry", {}, ["extensions"]), "MALFORMED_REPLY", { requires: ["influence"] }),
  ];

  // What a client that requires extensions may do in the session its handshake left it (sessions.md, A client that
  // requires extensions): only an attested reply listing every one lets it call under its requirement, and only its
  // switch lets it go on without.
  const requirementCase = (
    name: string, outcome: ReplyCheck | null, listed: string[], requires: string[], continueWithout: boolean,
    expected: { calls: boolean; requires: string[] },
  ) => {
    const got = callsAfter(outcome, listed, { extensions: requires, continueWithout });
    check(`session requirement ${name}`, got, expected);
    return { name, check: outcome, listed, requires, continueWithout, expected };
  };
  const NO_CALLS = { calls: false, requires: [] };
  const CALLS = { calls: true, requires: [] };
  const BOTH = ["influence", "example"];
  const sessionRequirement = [
    requirementCase("no requirement, after a failed handshake", null, [], [], false, CALLS),
    requirementCase("no requirement, after an unsafe reply", "UNSAFE", [], [], false, CALLS),
    requirementCase("attested, listing every one", "ATTESTED", ["example", "influence"], BOTH, false, { calls: true, requires: ["example", "influence"] }),
    requirementCase("attested, listing every one, with the switch", "ATTESTED", ["example", "influence"], BOTH, true, { calls: true, requires: ["example", "influence"] }),
    requirementCase("a reply listing one of two", "EXTENSION_REQUIRED", ["example"], BOTH, false, NO_CALLS),
    requirementCase("a reply listing one of two, with the switch", "EXTENSION_REQUIRED", ["example"], BOTH, true, { calls: true, requires: ["example"] }),
    // An unsafe session, whether the reply said so or the handshake failed: no calls, unless the switch is set, and
    // then calls carry no requires, whatever an unsafe reply listed.
    ...([
      ["an unsafe reply", "UNSAFE", ["influence"]],
      ["a malformed reply", "MALFORMED_REPLY", []],
      ["a reply under another key", "PIN_MISMATCH", ["influence"]],
      ["a reply whose signature fails", "BAD_SIGNATURE", ["influence"]],
      ["a JSON-RPC error or a timeout", null, []],
    ] as [string, ReplyCheck | null, string[]][]).flatMap(([what, outcome, listed]) => [
      requirementCase(what, outcome, listed, ["influence"], false, NO_CALLS),
      requirementCase(`${what}, with the switch`, outcome, listed, ["influence"], true, CALLS),
    ]),
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
  const badNameRing = signedOverBadName(LIVE_NOT_AFTER);
  const badNameRequest = { ...wireRequest, clientKeyring: badNameRing.services, clientKeyringSig: badNameRing.sig };
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
    // Signed over the bad name, so only the name rule refuses it, and before any signature is checked.
    sessionRequestCase(NOT_A_NODE_CASE, badNameRequest, "MALFORMED"),
  ];


  // Recorded handshakes (sessions.md §Recorded handshakes): the session a recorded request and reply
  // opened, judged offline at each `at`, at all (at the earliest of its limits), the policyNotAfter a response in it
  // is checked with, null when the server's signatures do not verify. The reply's session id is bound to the request
  // it answers.
  const replyTo = (req: SessionRequest, signer: KeyName, o: Record<string, unknown> = {}, drop: string[] = []): SessionReply => {
    const root = (Object.hasOwn(o, "serverRoot") ? o.serverRoot : serverRoot) as { sig: string } | null;
    const body: Record<string, unknown> = {
      serverRoot: root, serverPolicyKey: keys["server-policy"].pub, serverKeyring: serverRing.services, serverKeyringSig: serverRing.sig,
      serverKeyringNotAfter: LIVE_NOT_AFTER, serverReplyCert: entryCert, nonce: SERVER_NONCE,
      sess: deriveSessionId(req.clientRoot?.sig ?? null, root?.sig ?? null, req.nonce, SERVER_NONCE, req), status: "attested", disabled: [],
      extensions: [], ...o,
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
    const expected = { attested: s.attested, attestedAt: at.map((t) => s.attestedAt(t)), responseNotAfter: s.responseNotAfter ?? null };
    return { name, request, requestToken, reply, replyToken, pin, serverEntry, at, expected };
  };
  const clientRootAt = (t: number): SessionRequest => ({ ...request, clientRoot: clientRootUntil(t) });
  // Client material a reader refuses as malformed, recorded all the same: the session it opened is never attested.
  const unsignedRequest = withoutSig as unknown as SessionRequest;
  const unwindowedRingRequest = withoutRingWindow as unknown as SessionRequest;
  const unwindowedRootRequest = { ...wireRequest, clientRoot: unwindowedClientRoot } as unknown as SessionRequest;
  const serverRootByAnotherKey = signRoot(decode(policies.server.root), policies.server.rootId, keys["mcp-entry"].priv, LIVE_NOT_AFTER);
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
    handshakeCase("a reply with no server root: no response limit", request, replyTo(request, "mcp-entry", { serverRoot: null }), [NOW]),
    handshakeCase("a server root another key signed: no response limit", request, replyTo(request, "mcp-entry", { serverRoot: serverRootByAnotherKey }), [NOW]),
    handshakeCase("client keyring window moved", { ...withClientRing(newRing(NOW)), clientKeyringNotAfter: LIVE_NOT_AFTER }, replyTo({ ...withClientRing(newRing(NOW)), clientKeyringNotAfter: LIVE_NOT_AFTER }, "mcp-entry"), [NOW]),
    handshakeCase("client root signed by another key", { ...request, clientRoot: newRoot(LIVE_NOT_AFTER, "server-policy") }, replyTo({ ...request, clientRoot: newRoot(LIVE_NOT_AFTER, "server-policy") }, "mcp-entry"), [NOW]),
    handshakeCase("request without a client keyring signature", unsignedRequest, replyTo(unsignedRequest, "mcp-entry"), [NOW]),
    handshakeCase("request without a client keyring notAfter", unwindowedRingRequest, replyTo(unwindowedRingRequest, "mcp-entry"), [NOW]),
    handshakeCase("client root without notAfter", unwindowedRootRequest, replyTo(unwindowedRootRequest, "mcp-entry"), [NOW]),
    // A recorded reply is read as a reply, extensions included; step 5 reads the client's live configuration, which a
    // record does not hold, so a reply listing an extension is judged with no requirement.
    handshakeCase("a reply without extensions", request, replyTo(request, "mcp-entry", {}, ["extensions"]), [NOW]),
    handshakeCase("a reply listing an extension, judged with no requirement", request, replyTo(request, "mcp-entry", { extensions: ["influence"] }), [NOW]),
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
    ["a reply with no server root: no response limit", false, [false]],
    ["a server root another key signed: no response limit", false, [false]],
    ["client keyring window moved", false, [false]],
    ["client root signed by another key", false, [false]],
    ["request without a client keyring signature", false, [false]],
    ["request without a client keyring notAfter", false, [false]],
    ["client root without notAfter", false, [false]],
    ["a reply without extensions", false, [false]],
    ["a reply listing an extension, judged with no requirement", true, [true]],
  ]);
  // The server signed it, so only the shape check refuses it: live it is MALFORMED_REPLY, and offline never attested.
  const shapeRefused = recordedHandshake.find((c) => c.name === "a signed reply the client's shape check refuses")!;
  const serverPin = keys["server-policy"].pub;
  const shapeRefusedLive = checkSessionReply(shapeRefused.replyToken, request, serverPin, "mcp-entry", NOW);
  check("the shape-refused reply live", shapeRefusedLive, "MALFORMED_REPLY");
  // A response limit exists only where the server's signatures verify against the pin and the configured entry,
  // whatever the client's side, the status or the time: a reply that does not read, has no server root, or fails the
  // pin or the entry gives none.
  check("recorded handshake response limits", recordedHandshake.map((c) => [c.name, c.expected.responseNotAfter]), [
    ["entry-key form, limited by the certificate", LIVE_NOT_AFTER],
    ["policy-key form, limited by the roots and keyrings", LIVE_NOT_AFTER],
    ["client root's notAfter", LIVE_NOT_AFTER],
    ["client keyring's notAfter", LIVE_NOT_AFTER],
    ["server root's notAfter", NOW],
    ["server keyring's notAfter", NOW],
    ["attested at all at the earliest limit", NOW + 2],
    ["unsafe", LIVE_NOT_AFTER],
    ["a signed reply the client's shape check refuses", null],
    ["another pin", null],
    ["the configured entry, not the reply's", null],
    ["configured for another entry", null],
    ["a reply with no server root: no response limit", null],
    ["a server root another key signed: no response limit", null],
    ["client keyring window moved", LIVE_NOT_AFTER],
    ["client root signed by another key", LIVE_NOT_AFTER],
    ["request without a client keyring signature", LIVE_NOT_AFTER],
    ["request without a client keyring notAfter", LIVE_NOT_AFTER],
    ["client root without notAfter", LIVE_NOT_AFTER],
    ["a reply without extensions", null],
    ["a reply listing an extension, judged with no requirement", LIVE_NOT_AFTER],
  ]);

  // Recorded calls (verification.md §Offline verification): each call is checked by the offline verifier in the
  // session of the handshake it names, against the client keyring and root of that handshake's request and its reply's
  // session id, then limited to the session (OUTSIDE_SESSION). The calls are one record set, in order: one set of spent
  // nonce keys for them all, whatever handshakes the set holds.
  type RecordedCallInput = Omit<
    CaseInputs, "name" | "keyring" | "sess" | "allowedOrigins" | "actsOn" | "allowedExtensions" | "blocksToken"
  > & {
    handshake: number;
    chainToken: string;
    blocksToken: string | null;
    rid: string;
    recordedTs: { last: number };
    prompt: string;
  };
  /** A call recorded at `ts` in the session `reply` opened, its stamps committing to `o.blocks` (the base call's). */
  const callIn = (
    reply: SessionReply, ts: number, callId: string, o: { forged?: boolean; blocks?: [BlockJson, BlockJson] } = {},
  ): RecordedCallInput => {
    const bind = bindMcpCall(TOOL, callId, ARGS);
    const sess = reply.sess;
    const blocks = o.blocks ?? [ORIGIN_BLOCK, HOP_BLOCK];
    const first = stampBy({ ...originFields, ts: ts - 1000, sess, ext: extOf(blocks[0]) }, "session");
    const hopSigner = o.forged === true ? "session" : "pi";
    const chain = [first, stampBy({ ...hopFields(first.sig), ts, sess, bind, ext: extOf(blocks[1]) }, hopSigner)];
    return {
      handshake: 0, chain, chainToken: tokenOf(chain), expectedBind: bind, blocks,
      blocksToken: tokenOf(blocks), policy: "client", proofRoute: CALL_ROUTE, receiver: CALL_RCV,
      receiverInRoute: true, nonceKey: nonceKey([RID, callId, "req"]), rid: RID, recordedTs: { last: ts }, prompt: PROMPT,
    };
  };
  /** A record set checked by a verifier that acts on example and carries any name. */
  const RECORD_SETTINGS = { actsOn: EXAMPLE, allowedExtensions: null };
  /**
   * A record set: each call by the offline verifier with `settings`, then, when it acts on influence, the extension's
   * reading of the items once the offline order gives OK, and only then the session's limits (verification.md, Offline
   * verification, row 9).
   */
  const recordedCallCase = (
    name: string, handshakes: { request: SessionRequest; reply: SessionReply }[], calls: RecordedCallInput[],
    settings: { actsOn: string[]; allowedExtensions: string[] | null } = RECORD_SETTINGS,
  ) => {
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
          chain: c.chainToken, expectedBind: c.expectedBind, blocks: c.blocksToken, proof: proofTokenOf(c),
          receiver: c.receiver, receiverInRoute: c.receiverInRoute, rid: c.rid, recordedTs: c.recordedTs,
          prompt: c.prompt,
        },
        {
          // the session's windows are judged by callInSession, so the members have none
          keyrings: [{ keys: request.clientKeyring, notAfter: Infinity }],
          roots: [{ root: decode(clientRoot.root), rootId: clientRoot.rootId, notAfter: Infinity }],
          allowedOrigins: ["session"], sess: h.reply.sess,
          nonceKey: c.nonceKey, seen: records.spent, callMaxAgeMs: CALL_MAX_AGE_MS, runMaxAgeMs: RUN_MAX_AGE_MS,
          extensions: settingsOf(settings),
        },
      );
      const session = sessions[c.handshake]!;
      const reason = settings.actsOn.includes(INFLUENCE)
        ? recordedCallReason(v, session, c.recordedTs.last)
        : callInSession(session, v.reason, c.recordedTs.last);
      if (reason === undefined) throw new Error(`recorded call ${name}: its session is not attested`);
      return { reason };
    });
    return {
      name, handshakes: recorded, allowedOrigins: ["session"], ...settings, callMaxAgeMs: CALL_MAX_AGE_MS,
      runMaxAgeMs: RUN_MAX_AGE_MS, calls, expected,
    };
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

  // The influence the client's run holds: the origin names influence with nothing to add, and the client's hop
  // carries the session's whole influence (influence.md, Over MCP).
  const SESSION_ENTRIES: JsonValue[] = [
    { cls: "third-party", src: "web:example.com", h: "h2" },
    { cls: "private", src: "github:acme/app#42", h: "h1", cid: "cid-1", owner: "alice" },
  ];
  const THIRD_PARTY = SESSION_ENTRIES[0]!;
  const INFLUENCE_ORIGIN: BlockJson = { items: { influence: [] }, requires: [] };
  const influenceHop = (items: JsonValue[]): BlockJson => ({ items: { influence: items }, requires: [] });
  /** A response's label, which a request's block must not take for an entry: it has no `src` and no `h`. */
  const A_LABEL: JsonValue = { cls: "private", cid: "cid-1", owner: "alice" };
  /** The session's private entry with an empty owner, which is refused, never read as no owner. */
  const EMPTY_OWNER: JsonValue = { ...(SESSION_ENTRIES[1] as object), owner: "" };

  // Recorded local steps (MCP profile): the client's own steps, checked against its keyring and root, its blocks and
  // its signed local rules: the chain, then the items under influence (INFLUENCE_MISMATCH), then POLICY_EXPIRED,
  // PROOF_MISMATCH, RULES_MISMATCH and VERDICT_MISMATCH. The gate's verdict is re-derived under the classes of the
  // entries in the step's blocks.
  const LOCAL_RULES: LocalRules = parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read"] }], programs: [] });
  const OTHER_RULES: LocalRules = parseLocalRules({ v: 1, folders: [{ path: ".", access: ["read"] }, { path: "out", access: ["write"], destination: "public" }], programs: [] });
  const READ_NOTES: Resolved = { paths: [{ need: "read", at: "notes.md" }], programs: [], parse: "ok", readOnly: true };
  const READ_OUTSIDE: Resolved = { paths: [{ need: "read", at: "outside" }], programs: [], parse: "ok", readOnly: true };
  const NOTHING: Resolved = { paths: [], programs: [], parse: "ok", readOnly: false };
  // a copy of a file into the public folder `out`, which OTHER_RULES lets the gate write unless the session holds
  // both untrusted content and private data
  const COPY_OUT: Resolved = {
    paths: [{ need: "read", at: "notes.md" }, { need: "write", at: "out/notes.md" }],
    programs: [], parse: "ok", readOnly: false,
  };
  const LOCAL_SIGNERS = { svcs: ["session", "pi"], inst: "pi-1" };
  const STEP_TS = NOW - 1000;
  const stepOrigin = stampBy({ ...originFields, sess: "", ext: extOf(INFLUENCE_ORIGIN) }, "session");
  type LocalDecision = { tool: string; callId: string; input: Record<string, unknown>; resolved: Resolved; verdict: LocalVerdict; routeAllowed: boolean; rulesHash: string | null };
  type LocalClient = { keyring: Record<string, KeyName>; policy: "client"; rootNotAfter: number; keyringNotAfter: number; rules: LocalRules | null };
  /**
   * A local step; `o.signed` is the blocks its stamps commit to (the origin's, then the hop's with the session's
   * entries), and `o.carried` the blocks the record carries, the signed ones unless set.
   */
  const localStepCase = (
    name: string,
    d: Partial<LocalDecision> = {},
    o: {
      client?: Partial<LocalClient>; proofRoute?: string | null; seen?: string[]; age?: number;
      signed?: [BlockJson, BlockJson]; carried?: BlockJson[];
    } = {},
  ) => {
    const decision: LocalDecision = { tool: "read", callId: "tc-1", input: { path: "notes.md" }, resolved: READ_NOTES, verdict: "OK", routeAllowed: true, rulesHash: rulesHash(LOCAL_RULES), ...d };
    const client: LocalClient = { keyring: { session: "session", pi: "pi" }, policy: "client", rootNotAfter: LIVE_NOT_AFTER, keyringNotAfter: LIVE_NOT_AFTER, rules: LOCAL_RULES, ...o.client };
    const signed = o.signed ?? [INFLUENCE_ORIGIN, influenceHop(SESSION_ENTRIES)];
    const first = signed[0] === INFLUENCE_ORIGIN
      ? stepOrigin
      : stampBy({ ...originFields, sess: "", ext: extOf(signed[0]) }, "session");
    // the step's time: `age` ms after the run's origin, or the usual step time
    const stepTs = o.age === undefined ? STEP_TS : first.ts + o.age;
    const chain = [
      first,
      stampLocalStep(
        {
          svc: "pi", inst: "pi-1", rid: RID, ts: stepTs, prev: first.sig, toolName: decision.tool, toolCallId: decision.callId, input: decision.input,
          resolved: decision.resolved, verdict: decision.verdict, listed: decision.routeAllowed, rulesHash: decision.rulesHash,
          block: blockOf(signed[1] as unknown as JsonValue),
        },
        keys.pi.priv,
      ),
    ];
    const proofRoute = Object.hasOwn(o, "proofRoute") ? o.proofRoute! : decision.routeAllowed ? routeOf(["session", "pi", localReceiver(decision.tool)]) : null;
    // what bindLocalTool hashes, and what the step records as one token
    const decided = {
      callId: decision.callId, resolved: decision.resolved, verdict: decision.verdict,
      routeAllowed: decision.routeAllowed, rulesHash: decision.rulesHash,
    };
    const blocks = o.carried ?? signed;
    const step = {
      ...decision, decisionToken: tokenOf(decided), rid: RID, now: stepTs, chain, chainToken: tokenOf(chain),
      proofRoute, blocks, blocksToken: tokenOf(blocks),
    };
    const run = { prompt: PROMPT, ts: [first.ts] };
    const seen = o.seen ?? [];
    const result = verifyRecordedLocalStep(
      {
        tool: decision.tool, callId: decision.callId, input: decision.input, decision: step.decisionToken,
        rid: step.rid, now: step.now, chain: step.chainToken,
        proof: proofTokenOf({ policy: "client", proofRoute }), blocks: step.blocksToken,
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
  const NOT_AN_ENTRY_HOP = influenceHop([THIRD_PARTY, A_LABEL]);
  const UNLISTED = {
    tool: "bash", input: { command: "ls" }, resolved: NOTHING, verdict: "PATH_NOT_ALLOWED", routeAllowed: false,
  } as const;
  const COPY = {
    input: { path: "notes.md", to: "out/notes.md" }, resolved: COPY_OUT, rulesHash: rulesHash(OTHER_RULES),
  };
  const recordedLocalStep = [
    localStepCase("allowed"),
    localStepCase("refused by the rules", { input: { path: "/etc/passwd" }, resolved: READ_OUTSIDE, verdict: "SCOPE_DENIED" }),
    localStepCase("unlisted tool", UNLISTED),
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
    localStepCase("replay in the record set", {}, { seen: [nonceKey([RID, "tc-1", "local"])] }),
    localStepCase("at the run window", {}, { age: RUN_MAX_AGE_MS }),
    localStepCase("1 ms past the run window", {}, { age: RUN_MAX_AGE_MS + 1 }),
    // The step's blocks: matched to its stamps first (check 9a), then its items read as entries, after the chain check
    // (which goes on for an unproven route) and before the step's POLICY_EXPIRED check.
    localStepCase("a block altered", {}, { carried: [INFLUENCE_ORIGIN, influenceHop([THIRD_PARTY, { ...(SESSION_ENTRIES[1] as object), owner: "bob" }])] }),
    localStepCase("an influence item that is not an entry", {}, { signed: [INFLUENCE_ORIGIN, NOT_AN_ENTRY_HOP] }),
    localStepCase("an influence item that is not an entry, in the origin's block", {}, { signed: [influenceHop([A_LABEL]), influenceHop(SESSION_ENTRIES)] }),
    localStepCase("an influence item that is not an entry, under an expired root", {}, { signed: [INFLUENCE_ORIGIN, NOT_AN_ENTRY_HOP], client: { rootNotAfter: STEP_TS - 1 } }),
    localStepCase("an influence item that is not an entry, in an unlisted step", UNLISTED, { signed: [INFLUENCE_ORIGIN, NOT_AN_ENTRY_HOP] }),
    localStepCase("an influence item that is not an entry, and a bad signature", {}, { signed: [INFLUENCE_ORIGIN, NOT_AN_ENTRY_HOP], client: { keyring: { session: "session", pi: "gateway" } } }),
    // The gate's verdict under the classes of the step's entries: a write into a public folder is refused while the
    // session holds untrusted content and private data, and allowed with no entries. The client's policy lists one
    // local tool, read; the verdict is re-derived from the resolution the step recorded, whatever the tool is called.
    localStepCase("a write into a public folder, under untrusted and private entries", { ...COPY, verdict: "INFLUENCE_DENIED" }, { client: { rules: OTHER_RULES } }),
    localStepCase("a write into a public folder, signed as allowed under untrusted and private entries", { ...COPY, verdict: "OK" }, { client: { rules: OTHER_RULES } }),
    localStepCase("a write into a public folder, with no entries", { ...COPY, verdict: "OK" }, { client: { rules: OTHER_RULES }, signed: [INFLUENCE_ORIGIN, influenceHop([])] }),
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
    ["at the run window", "OK", "OK"],
    ["1 ms past the run window", "EXPIRED", null],
    ["a block altered", "EXTENSION_MISMATCH", null],
    ["an influence item that is not an entry", "INFLUENCE_MISMATCH", null],
    ["an influence item that is not an entry, in the origin's block", "INFLUENCE_MISMATCH", null],
    ["an influence item that is not an entry, under an expired root", "INFLUENCE_MISMATCH", null],
    ["an influence item that is not an entry, in an unlisted step", "INFLUENCE_MISMATCH", null],
    ["an influence item that is not an entry, and a bad signature", "BAD_SIGNATURE", null],
    ["a write into a public folder, under untrusted and private entries", "OK", "INFLUENCE_DENIED"],
    ["a write into a public folder, signed as allowed under untrusted and private entries", "VERDICT_MISMATCH", null],
    ["a write into a public folder, with no entries", "OK", "OK"],
  ]);

  // The server's response through the client's check (MCP profile): the attestation carries one block per stamp of the
  // response chain, and the client checks it with its own actsOn and allowedExtensions, check 9c included.
  const RESULT_BODY = { content: [{ type: "text", text: "opened #43" }], isError: false };
  const RESULT_HASH = bindResult(RESULT_BODY);
  const RESPONSE_SERVER = {
    policy: "server" as const,
    keyring: { "mcp-entry": "mcp-entry", "github-tools": "github-tools" } as Record<string, KeyName>,
    allowedOrigins: ["mcp-entry"],
    sess: SESS,
    policyNotAfter: 4_102_444_800_000,
    nonceTtlMs: NONCE_TTL_MS,
  };
  const ENTRY_BLOCK: BlockJson = { items: { example: [] }, requires: [] };
  const TOOLS_BLOCK: BlockJson = { items: { example: [{ note: "r1" }] }, requires: [] };
  /** The server's response chain to the call `callId`, each stamp committing to its ext in `exts`. */
  const responseChain = (exts: [string, string], callId = CALL_ID): Stamp[] => {
    const first = stampBy({
      svc: "mcp-entry", inst: "entry-1", rid: RID, ts: NOW - 800, sess: SESS, rcv: "github-tools",
      bind: bindMcpCall(TOOL, callId, ARGS), ext: exts[0], prev: "",
    }, "mcp-entry");
    const last = stampBy({
      svc: "github-tools", inst: "gh-1", rid: RID, ts: NOW - 500, sess: SESS, rcv: "pi",
      bind: bindResponse(RESULT_HASH, callId), ext: exts[1], prev: first.sig,
    }, "github-tools");
    return [first, last];
  };
  /** An attestation carrying `blocks`, over a chain whose stamps commit to them unless `chain` is given. */
  const attestationOver = (
    blocks: BlockJson[], chain = responseChain([extOf(blocks[0]!), extOf(blocks[1]!)]),
  ): Record<string, unknown> =>
    ({ blocks, chain, proof: policies.server.proofs["mcp-entry/github-tools"]!, resultHash: RESULT_HASH });
  const attestationCase = (
    name: string, attestation: Record<string, unknown>, expected: string,
    o: { actsOn?: string[]; allowedExtensions?: string[]; callId?: string } = {},
  ) => {
    const result = RESULT_BODY;
    const attestationToken = name === UNSORTED_ATTESTATION_CASE
      ? unsortedAttestationToken(attestation as Attestation)
      : tokenOf(attestation);
    const call = { rid: RID, toolCallId: o.callId ?? CALL_ID, receiver: "pi" };
    const actsOn = o.actsOn ?? EXAMPLE;
    const allowedExtensions = o.allowedExtensions ?? null;
    const got = verifyResponse(attestationToken, result, call, {
      keyrings: [{ keys: resolveKeyring(RESPONSE_SERVER.keyring), notAfter: RESPONSE_SERVER.policyNotAfter }],
      roots: [{ root: rootOf("server"), rootId: policies.server.rootId, notAfter: RESPONSE_SERVER.policyNotAfter }],
      allowedOrigins: RESPONSE_SERVER.allowedOrigins, sess: RESPONSE_SERVER.sess,
      nonces: new NonceCache(RESPONSE_SERVER.nonceTtlMs), now: NOW, policyNotAfter: RESPONSE_SERVER.policyNotAfter,
      extensions: settingsOf({ actsOn, allowedExtensions }),
    });
    check(`response attestation ${name}`, got.reason, expected);
    return {
      name, attestation, attestationToken, result, call, actsOn, allowedExtensions, server: RESPONSE_SERVER, now: NOW,
      expected: { reason: expected },
    };
  };
  const BASE_BLOCKS = [ENTRY_BLOCK, TOOLS_BLOCK];
  const attested = attestationOver(BASE_BLOCKS);
  // a chain whose every ext is "", which an absent blocks token would match: the attestation has no absent form
  const emptyResponse = responseChain(["", ""]);
  const { blocks: _blocks, ...noBlocks } = attested;
  const responseAttestation = [
    attestationCase("attested", attested, "OK"),
    attestationCase("a member the attestation does not have", { ...attested, extra: 1 }, "CHAIN_MISSING"),
    attestationCase("a labels member in place of blocks", { ...noBlocks, chain: emptyResponse, labels: [A_LABEL] }, "CHAIN_MISSING"),
    attestationCase("no blocks member, every ext empty", { ...noBlocks, chain: emptyResponse }, "CHAIN_MISSING"),
    attestationCase("blocks null, every ext empty", { ...attested, blocks: null, chain: emptyResponse }, "CHAIN_MISSING"),
    // signed over the second element's JCS, so only the attestation's reading of blocks refuses it
    ...(() => {
      const extra = { ...TOOLS_BLOCK, note: "n1" };
      const chain = responseChain([extOf(ENTRY_BLOCK), hashOf(extra)]);
      return [attestationCase("a blocks that is not an array of blocks", { ...attested, blocks: [ENTRY_BLOCK, extra], chain }, "CHAIN_MISSING")];
    })(),
    attestationCase(UNSORTED_ATTESTATION_CASE, attested, "CHAIN_MISSING"),
    // the missing block would be the empty block, which the last stamp commits to: still one block per stamp
    attestationCase(
      "one block for two stamps, the stamp without one committing to the empty block",
      attestationOver([ENTRY_BLOCK], responseChain([extOf(ENTRY_BLOCK), ""])), "EXTENSION_MISMATCH",
    ),
    attestationCase("a block altered", { ...attested, blocks: [ENTRY_BLOCK, { items: { example: [{ note: "r2" }] }, requires: [] }] }, "EXTENSION_MISMATCH"),
    attestationCase("a result hash for another result", { ...attested, resultHash: bindResult({ content: [], isError: false }) }, "BINDING_MISMATCH"),
    attestationCase("a name the client's allowed list does not hold", attested, "EXTENSION_NOT_ALLOWED", { actsOn: [], allowedExtensions: [INFLUENCE] }),
    // check 9c, on the responder's last block only: the client is held to what the responder requires of it
    attestationCase(
      "the last block requires example, which the client does not act on",
      attestationOver([ENTRY_BLOCK, { ...TOOLS_BLOCK, requires: ["example"] }]), "EXTENSION_REQUIRED", { actsOn: [] },
    ),
    attestationCase(
      "the first block requires example, which the client does not act on",
      attestationOver([{ ...ENTRY_BLOCK, requires: ["example"] }, TOOLS_BLOCK]), "OK", { actsOn: [] },
    ),
    // a call id is hashed content and a nonce key the verifier's own text (verification.md, Freshness and replay)
    ...(() => {
      const callId = "call-\uFFFF";
      const chain = responseChain([extOf(ENTRY_BLOCK), extOf(TOOLS_BLOCK)], callId);
      return [attestationCase(NONCHARACTER_CASE, attestationOver(BASE_BLOCKS, chain), "OK", { callId })];
    })(),
  ];

  // paztport/session's params and result as they arrive (MCP profile): the server reads the params, exactly a request
  // token plus an optional `_meta`, and the client the result, exactly a reply token plus an optional `_meta`.
  const wellFormed = sessionRequestCases[0]!.requestToken;
  const sessionParamsCase = (name: string, params: Record<string, unknown>, expected: "OK" | "INVALID_PARAMS") => {
    let got: "OK" | "INVALID_PARAMS" = "OK";
    try {
      readSessionParams(params);
    } catch (e) {
      if (!(e instanceof InvalidParams)) throw e;
      got = "INVALID_PARAMS";
    }
    check(`session params ${name}`, got, expected);
    return { name, params, expected };
  };
  const sessionParams = [
    sessionParamsCase("a request token", { request: wellFormed }, "OK"),
    sessionParamsCase("a request token and _meta", { request: wellFormed, _meta: { progressToken: 1 } }, "OK"),
    sessionParamsCase("a member the params do not have", { request: wellFormed, other: 1 }, "INVALID_PARAMS"),
    sessionParamsCase("the request itself", { request: wireRequest }, "INVALID_PARAMS"),
    sessionParamsCase("no request", { _meta: { progressToken: 1 } }, "INVALID_PARAMS"),
    // the request's JCS bytes after a space, which a token never holds
    sessionParamsCase("a request token that does not read", { request: encode(utf8(" " + canonicalize(wireRequest))) }, "INVALID_PARAMS"),
  ];
  // the version 4 reply of sessionReply's first case, "entry-key form attested", whose check that section pins
  const attestedReply = sessionReply[0]!.replyToken;
  const sessionResultCase = (name: string, result: Record<string, unknown>, expected: "OK" | "MALFORMED_REPLY") => {
    const token = sessionReplyToken(result);
    const got = token !== undefined && readOr(() => readSessionReply(token)) !== undefined ? "OK" : "MALFORMED_REPLY";
    check(`session result ${name}`, got, expected);
    return { name, result, expected };
  };
  const sessionResult = [
    sessionResultCase("a reply token", { reply: attestedReply }, "OK"),
    sessionResultCase("a reply token and _meta", { reply: attestedReply, _meta: { progressToken: 1 } }, "OK"),
    sessionResultCase("a member the result does not have", { reply: attestedReply, other: 1 }, "MALFORMED_REPLY"),
    sessionResultCase("the reply itself", { reply: sessionReply[0]!.reply }, "MALFORMED_REPLY"),
    sessionResultCase("no reply", { _meta: { progressToken: 1 } }, "MALFORMED_REPLY"),
    // the reply's JCS bytes after a space, which a token never holds
    sessionResultCase("a reply token that does not read", { reply: encode(utf8(" " + canonicalize(sessionReply[0]!.reply))) }, "MALFORMED_REPLY"),
  ];

  const influence = influenceSection({
    A_LABEL, SESSION_ENTRIES, RESULT_HASH,
    recordedCall: recordedCallCase(
      "items under influence, at a verifier that acts on it",
      [{ request: shortRoot, reply: shortRootReply }],
      // in the session (its client root's notAfter is NOW) and 1 ms past it, each with entries that read and with one
      // that does not
      [
        callIn(shortRootReply, NOW, "call-1", { blocks: [INFLUENCE_ORIGIN, influenceHop(SESSION_ENTRIES)] }),
        callIn(shortRootReply, NOW, "call-2", { blocks: [INFLUENCE_ORIGIN, influenceHop([THIRD_PARTY, EMPTY_OWNER])] }),
        callIn(shortRootReply, NOW + 1, "call-3", { blocks: [INFLUENCE_ORIGIN, influenceHop([THIRD_PARTY, EMPTY_OWNER])] }),
        callIn(shortRootReply, NOW + 1, "call-4", { blocks: [INFLUENCE_ORIGIN, influenceHop(SESSION_ENTRIES)] }),
      ],
      { actsOn: [INFLUENCE], allowedExtensions: null },
    ),
  });

  const vectors = {
    about: ABOUT,
    keys,
    policies,
    blocks: blocksSection(),
    signingBytes: signingBytesCases,
    signatures,
    keyring,
    root: signedRoots,
    verify,
    offline,
    recordedHandshake,
    recordedCall,
    recordedLocalStep,
    responseAttestation,
    sessionParams,
    sessionResult,
    replyCert,
    sessionReply,
    sessionRequirement,
    sessionStatus: sessionStatusCases,
    sessionRequest: sessionRequestCases,
    ...sharedPrimitives(),
    ...mcpBindings(),
    influence,
  };
  checkTokens(vectors);
  return vectors;
}

/** v4.json's text: the built vectors as JSON. */
export function vectorsText(): string {
  const vectors = buildVectors();
  let text = JSON.stringify(vectors, null, 2) + "\n";
  // JSON.stringify prints −2^63 as -9223372036854776000; the file spells it exactly, so a 64-bit reader meets the long
  // it could take it for
  const at = text.indexOf(`"name": ${JSON.stringify(TS_MIN_CASE)}`);
  const printed = `"ts": ${JSON.stringify(-(2 ** 63))},`;
  const ts = text.indexOf(printed, at);
  const next = text.indexOf('"name": ', at + 1);
  if (at < 0 || ts < 0 || (next >= 0 && next < ts)) throw new Error(`no ts in the verify case ${TS_MIN_CASE}`);
  text = text.slice(0, ts) + `"ts": ${TS_MIN_TEXT},` + text.slice(ts + printed.length);
  check("v4.json text", JSON.parse(text), vectors);
  return text;
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url) && process.argv.includes("--write")) {
  writeFileSync(VECTORS_JSON, vectorsText());
}
