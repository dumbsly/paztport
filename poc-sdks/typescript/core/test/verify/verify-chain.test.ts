// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindPrompt, bindResult } from "../../src/stamp/binding.ts";
import { encode } from "../../src/encoding/b64url.ts";
import { canonicalize, writeToken } from "../../src/encoding/jcs.ts";
import { generateKeyPair, randomBytes, sha256, utf8 } from "../../src/crypto/crypto.ts";
import { buildTree } from "../../src/policy/merkle.ts";
import { commitBlock, EMPTY_BLOCK, makeBlock, type Block } from "../../src/stamp/block.ts";
import { extensionSettings, NO_EXTENSIONS, recordExtensionSettings } from "../../src/verify/extensions.ts";
import { NonceCache, nonceKey } from "../../src/verify/nonce.ts";
import { readChain, signStamp, type Stamp } from "../../src/stamp/stamp.ts";
import { verifyChain, type PinnedKeyring, type PinnedRoot, type VerifierConfig, type VerifyInput } from "../../src/verify/verify-chain.ts";

const NOW = 10_000_000;
/** The pinned keyring and root's window: 2100-01-01, past every clock here. */
const POLICY_NOT_AFTER = 4_102_444_800_000;
const RECEIVER = "mcp:github.t";
const ROUTE = `session/pi/${RECEIVER}`;
const SESS = "sess-1";
/** The blocks a chain carries unless a test gives its own: the origin attaches nothing, the hop one `example` item. */
const HOP_BLOCK = makeBlock({ example: [{ note: "n1" }] });
const BLOCKS: readonly [Block, Block] = [EMPTY_BLOCK, HOP_BLOCK];

type Fields = Partial<Omit<Stamp, "sig" | "v">>;
type ChainOpts = {
  s0?: Fields; s1?: Fields; s0rcv?: string; tamperS1Sig?: boolean; dropRcv?: boolean; blocks?: readonly [Block, Block];
};
/** A chain and its blocks, each carried as its token. */
type Carried = { chain: string; blocks: string | null };
type Over = Partial<VerifyInput> & { proofRoute?: string };

const session = generateKeyPair();
const pi = generateKeyPair();
const other = generateKeyPair();
const tree = buildTree([ROUTE, "session/pi"].map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
const bind = bindPrompt("t call-1");
const keys: Record<string, string> = { session: session.privateKey, pi: pi.privateKey };

const mk = (svc: string, over: Fields = {}, key = Object.hasOwn(keys, svc) ? keys[svc]! : other.privateKey): Stamp =>
  signStamp({ svc, inst: `${svc}-1`, rid: "rid-1", ts: NOW, sess: SESS, rcv: "", bind: "b0", ext: "", prev: "", ...over }, key);

/** Flips the first character: still canonical base64url, no longer the signature. */
const tamper = (sig: string) => (sig[0] === "A" ? "B" : "A") + sig.slice(1);

/**
 * A token of `value`'s JCS bytes, written by the hashing rules, so a value no protocol writer writes still reaches
 * the reader.
 */
const token = (value: unknown): string => encode(utf8(canonicalize(value)));
/** A token holding exactly `text`'s bytes. */
const raw = (text: string): string => encode(utf8(text));

/** `stamps` and `blocks`, each carried as its token. */
const carry = (stamps: unknown, blocks: unknown = BLOCKS): Carried => ({ chain: token(stamps), blocks: token(blocks) });

/** s0 (session, rcv pi) then s1 (pi, rcv the receiver), each committing to its block, and the blocks beside them. */
function chain(o: ChainOpts = {}): Carried {
  const [b0, b1] = o.blocks ?? BLOCKS;
  const s0 = mk("session", { rcv: o.s0rcv ?? "pi", ext: commitBlock(b0), ...o.s0 });
  const s1 = mk("pi", { rcv: RECEIVER, bind, ext: commitBlock(b1), prev: s0.sig, ...o.s1 });
  const last = o.tamperS1Sig ? { ...s1, sig: tamper(s1.sig) } : s1;
  if (o.dropRcv) {
    const { rcv: _rcv, ...rest } = last;
    return carry([s0, rest], [b0, b1]);
  }
  return carry([s0, last], [b0, b1]);
}

/** The stamps a carried chain holds. */
const stampsOf = (c: Carried) => readChain(c.chain) as [Stamp, Stamp];

/** The same chain whose last stamp names `rcv` as its receiver. */
const chainEndingAt = (rcv: string) => chain({ s1: { rcv } });

/** A pinned keyring of `keys`, current until `notAfter`. */
const ring = (keys: Record<string, string>, notAfter = POLICY_NOT_AFTER): PinnedKeyring => ({ keys, notAfter });
/** `t`'s root, pinned until `notAfter`. */
const pinned = (t: { root: Uint8Array; rootId: string }, notAfter = POLICY_NOT_AFTER): PinnedRoot => ({ root: t.root, rootId: t.rootId, notAfter });

const cfg = (over: Partial<VerifierConfig> = {}): VerifierConfig => ({
  keyrings: [ring({ session: session.publicKey, pi: pi.publicKey })],
  roots: [pinned(tree)],
  allowedOrigins: ["session"],
  sess: SESS,
  nonces: new NonceCache(60_000),
  nonceKey: '["rid-1","call-1","req"]',
  now: NOW,
  policyNotAfter: POLICY_NOT_AFTER,
  extensions: NO_EXTENSIONS,
  ...over,
});

function input(c: Carried, over: Over = {}): VerifyInput {
  const { proofRoute, ...rest } = over;
  return {
    ...c, expectedBind: bind, proof: writeToken(tree.proofFor(proofRoute ?? ROUTE)), receiver: RECEIVER,
    receiverInRoute: true, ...rest,
  };
}

/** Verifies the carried chain, with its result and hand-over. */
const full = (c: Carried, over: Over = {}, config: VerifierConfig = cfg()) => verifyChain(input(c, over), config);

/** Verifies the carried chain: its result, without the hand-over. */
const verify = (c: Carried, over: Over = {}, config: VerifierConfig = cfg()) => {
  const { handOver: _handOver, ...result } = full(c, over, config);
  return result;
};

/** A stamp's JSON in the wire table's member order, not JCS's. */
const wireOrder = (s: Stamp): string =>
  `{"v":4,"svc":"${s.svc}","inst":"${s.inst}","rid":"${s.rid}","ts":${s.ts},"sess":"${s.sess}","rcv":"${s.rcv}",` +
  `"bind":"${s.bind}","ext":"${s.ext}","prev":"${s.prev}","sig":"${s.sig}"}`;

describe("verifyChain", () => {
  it("ok names the last signer", () => expect(verify(chain())).toEqual({ ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi-1" }));
  it("a stamp whose rcv is not the next hop", () => expect(verify(chain({ s0rcv: "orders" })).reason).toBe("BINDING_MISMATCH"));
  it("a chain delivered to another receiver", () => expect(verify(chain(), { receiver: "mcp:github.u" }).reason).toBe("BINDING_MISMATCH"));
  it("a bad signature beats a bad rcv", () => expect(verify(chain({ s0rcv: "orders", tamperS1Sig: true })).reason).toBe("BAD_SIGNATURE"));
  it("a stamp whose v is not 4 is chain missing", () => {
    const [s0, s1] = stampsOf(chain());
    for (const v of [1, 2, 3, 5]) {
      for (const odd of [[{ ...s0, v }, s1], [s0, { ...s1, v }], [{ ...s0, v }, { ...s1, v }]]) {
        expect(verify(carry(odd)).reason).toBe("CHAIN_MISSING");
      }
    }
  });
  it("a stamp with rcv missing or non-string", () => expect(verify(chain({ dropRcv: true })).reason).toBe("CHAIN_MISSING"));
  it("the receiver can sit off the route", () => expect(verify(chainEndingAt("pi"), { receiver: "pi", receiverInRoute: false, proofRoute: "session/pi" }).reason).toBe("OK"));
  it("a matching peer is named with its address", () => expect(verify(chain(), { peer: { svc: "pi", inst: "10.0.0.7" } })).toEqual({ ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "10.0.0.7" }));
  it("a peer other than the last signer", () => expect(verify(chain(), { peer: { svc: "search", inst: "10.0.0.9" } })).toEqual({ ok: false, reason: "PEER_MISMATCH", suspectSvc: "search", suspectInst: "10.0.0.9" }));
  it("with a peer, any rejection names it", () => {
    expect(verify(chain({ tamperS1Sig: true }), { peer: { svc: "search", inst: "10.0.0.9" } })).toMatchObject({ reason: "BAD_SIGNATURE", suspectSvc: "search", suspectInst: "10.0.0.9" });
    expect(verify(carry("garbage"), { peer: { svc: "search", inst: "10.0.0.9" } })).toMatchObject({ reason: "CHAIN_MISSING", suspectSvc: "search" });
  });
  it("without a peer, early rejections name no one", () => expect(verify(chain({ tamperS1Sig: true }))).toMatchObject({ suspectSvc: "", suspectInst: "" }));
  it("a null peer is no peer, and never throws", () => {
    expect(verify(chain(), { peer: null })).toEqual(verify(chain()));
    expect(verify(chain({ tamperS1Sig: true }), { peer: null })).toEqual({ ok: false, reason: "BAD_SIGNATURE", suspectSvc: "", suspectInst: "" });
  });

  it("an rcv that is not a string", () => {
    const [s0, s1] = stampsOf(chain());
    expect(verify(carry([s0, { ...s1, rcv: 5 }])).reason).toBe("CHAIN_MISSING");
    expect(verify(carry([s0, { ...s1, rcv: null }])).reason).toBe("CHAIN_MISSING");
  });
  it("a lone surrogate in rcv", () => {
    const [s0, s1] = stampsOf(chain());
    const text = canonicalize([s0, { ...s1, rcv: "mcp:@" }]).replace('"mcp:@"', '"mcp:\\ud800"');
    expect(verify({ chain: raw(text), blocks: token(BLOCKS) }).reason).toBe("CHAIN_MISSING");
  });
  it("aChainTokenInWireMemberOrderIsChainMissing", () => {
    const stamps = stampsOf(chain());
    const blocks = token(BLOCKS);
    expect(verify({ chain: raw(`[${stamps.map(wireOrder).join(",")}]`), blocks }).reason).toBe("CHAIN_MISSING");
    expect(verify({ chain: raw(` ${canonicalize(stamps)}`), blocks }).reason).toBe("CHAIN_MISSING");
    expect(verify({ chain: writeToken(stamps), blocks }).reason).toBe("OK");
  });
  it("aStampFieldHoldingANoncharacterIsChainMissing", () => {
    const [s0, s1] = stampsOf(chain());
    expect(verify(carry([s0, { ...s1, inst: "pi-\uFDD0" }])).reason).toBe("CHAIN_MISSING");
    expect(verify(carry([{ ...s0, rid: "rid-\uFFFF" }, s1])).reason).toBe("CHAIN_MISSING");
  });
  it("aNegativeTsIsChainMissing", () => {
    const [s0, s1] = stampsOf(chain());
    expect(verify(carry([s0, { ...s1, ts: -1 }])).reason).toBe("CHAIN_MISSING");
    expect(verify(carry([{ ...s0, ts: -(2 ** 63) }, s1])).reason).toBe("CHAIN_MISSING");
  });
  it("aTsOfOnePointZeroIsChainMissing", () => {
    const [s0, s1] = stampsOf(chain());
    const text = canonicalize([s0, s1]).replace(`"ts":${s1.ts},`, `"ts":${s1.ts}.0,`);
    expect(text).toContain(`"ts":${NOW}.0,`);
    expect(verify({ chain: raw(text), blocks: token(BLOCKS) }).reason).toBe("CHAIN_MISSING");
  });
  it("aStampWithAnExtraMemberIsChainMissing", () => {
    const [s0, s1] = stampsOf(chain());
    expect(verify(carry([s0, { ...s1, extra: true }])).reason).toBe("CHAIN_MISSING");
  });
  it("rcv is signed: altering it is a bad signature", () => {
    const [s0, s1] = stampsOf(chain());
    expect(verify(carry([s0, { ...s1, rcv: "mcp:github.u" }]), { receiver: "mcp:github.u" }).reason).toBe("BAD_SIGNATURE");
  });
  it("ext is signed: altering it is a bad signature", () => {
    const [s0, s1] = stampsOf(chain());
    expect(verify(carry([s0, { ...s1, ext: "" }], [EMPTY_BLOCK, EMPTY_BLOCK])).reason).toBe("BAD_SIGNATURE");
  });
  it("the receiver is appended to the route only when it is on it", () => {
    // a call's receiver ends its route; off the route the same chain's services alone are proven
    expect(verify(chain(), { receiverInRoute: false }).reason).toBe("PATH_NOT_ALLOWED");
    expect(verify(chain(), { receiverInRoute: false, proofRoute: "session/pi" }).reason).toBe("OK");
  });

  // The verdict, the suspect and the order in which a chain's faults are found.
  it("validPasses", () => {
    expect(verify(chain())).toEqual({ ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi-1" });
  });
  it("suspectIsSetOnlyAtPathNotAllowed", () => {
    expect(verify(chain(), { proofRoute: "session/pi" })).toEqual({ ok: false, reason: "PATH_NOT_ALLOWED", suspectSvc: "pi", suspectInst: "pi-1" });
  });
  it("suspectIsEmptyForEveryOtherRejection", () => {
    const spent = cfg();
    verify(chain(), {}, spent);
    const requires = chain({ blocks: [EMPTY_BLOCK, makeBlock({}, ["example"])] });
    const cases: [string, ReturnType<typeof verify>][] = [
      ["CHAIN_MISSING", verify(carry([]))],
      ["BAD_ORIGIN", verify(chain(), {}, cfg({ allowedOrigins: ["x"] }))],
      ["BAD_SIGNATURE", verify(chain(), {}, cfg({ keyrings: [ring({ session: session.publicKey, pi: other.publicKey })] }))],
      ["BROKEN_LINK", verify(chain({ s1: { prev: "x" } }))],
      ["BINDING_MISMATCH", verify(chain({ s0rcv: "orders" }))],
      ["RID_MISMATCH", verify(chain({ s1: { rid: "rid-2" } }))],
      ["SESSION_UNKNOWN", verify(chain(), {}, cfg({ sess: "other" }))],
      ["EXPIRED", verify(chain(), {}, cfg({ now: NOW + 10 * 60_000 * 60 }))],
      ["BINDING_MISMATCH", verify(chain(), { expectedBind: "zz" })],
      ["EXTENSION_MISMATCH", verify(chain(), { blocks: null })],
      ["EXTENSION_NOT_ALLOWED", verify(chain(), {}, cfg({ extensions: extensionSettings([], ["other"]) }))],
      ["EXTENSION_REQUIRED", verify(requires)],
      ["REPLAY", verify(chain(), {}, spent)],
    ];
    for (const [reason, r] of cases) {
      expect([reason, r.reason, r.suspectSvc, r.suspectInst]).toEqual([reason, reason, "", ""]);
    }
  });
  it("notArray", () => {
    expect(verify(carry({})).reason).toBe("CHAIN_MISSING");
    expect(verify({ chain: "not*base64url", blocks: null }).reason).toBe("CHAIN_MISSING");
    expect(verify({ chain: "", blocks: null }).reason).toBe("CHAIN_MISSING");
  });
  it("emptyArray", () => {
    expect(verify(carry([])).reason).toBe("CHAIN_MISSING");
  });
  it("aStampOfAnotherVersionMixedIn", () => {
    const [s0, s1] = stampsOf(chain());
    const { v: _v, sess: _s, ext: _e, rcv: _r, ...v1like } = s0;
    expect(verify(carry([v1like, s1])).reason).toBe("CHAIN_MISSING");
    expect(verify(carry([{ ...s0, v: 1 }, s1])).reason).toBe("CHAIN_MISSING");
    expect(verify(carry([{ ...s0, ts: 1.5 }, s1])).reason).toBe("CHAIN_MISSING");
  });
  it("wrongOrigin", () => {
    const s0 = mk("pi", { rcv: "pi" });
    const s1 = mk("pi", { rcv: RECEIVER, bind, ext: commitBlock(HOP_BLOCK), prev: s0.sig });
    expect(verify(carry([s0, s1])).reason).toBe("BAD_ORIGIN");
  });
  it("badSig", () => {
    const s0 = mk("session", { rcv: "pi" });
    const s1 = mk("pi", { rcv: RECEIVER, bind, ext: commitBlock(HOP_BLOCK), prev: s0.sig }, other.privateKey);
    expect(verify(carry([s0, s1])).reason).toBe("BAD_SIGNATURE");
    const unknown = mk("ghost", { rcv: RECEIVER, bind, prev: s0.sig });
    expect(verify(carry([s0, unknown])).reason).toBe("BAD_SIGNATURE");
    const proto = mk("constructor", { rcv: RECEIVER, bind, prev: s0.sig });
    expect(verify(carry([s0, proto])).reason).toBe("BAD_SIGNATURE");
  });
  it("brokenLink", () => {
    expect(verify(chain({ s1: { prev: "nope" } })).reason).toBe("BROKEN_LINK");
  });
  it("ridMismatch", () => {
    expect(verify(chain({ s1: { rid: "rid-2" } })).reason).toBe("RID_MISMATCH");
  });
  it("wrongSess", () => {
    expect(verify(chain({ s1: { sess: "other" } })).reason).toBe("SESSION_UNKNOWN");
    expect(verify(chain(), {}, cfg({ sess: "other" })).reason).toBe("SESSION_UNKNOWN");
  });
  it("lastStampOlderThan5s", () => {
    expect(verify(chain({ s1: { ts: NOW - 5001 } })).reason).toBe("EXPIRED");
    expect(verify(chain({ s1: { ts: NOW - 5000 } })).reason).toBe("OK");
  });
  it("originOlderThan30min", () => {
    expect(verify(chain({ s0: { ts: NOW - 1_800_001 } })).reason).toBe("EXPIRED");
  });
  it("lastStampFutureBeyond5s", () => {
    expect(verify(chain({ s1: { ts: NOW + 5001 } })).reason).toBe("EXPIRED");
  });
  it("originFutureBeyond5s", () => {
    expect(verify(chain({ s0: { ts: NOW + 5001 } })).reason).toBe("EXPIRED");
  });
  it("originMinutesOldButLastFresh", () => {
    expect(verify(chain({ s0: { ts: NOW - 600_000 } })).reason).toBe("OK");
  });
  it("bindMismatch", () => {
    expect(verify(chain(), { expectedBind: "other" }).reason).toBe("BINDING_MISMATCH");
  });
  it("replayedNonceKey", () => {
    const c = cfg();
    expect(verify(chain(), {}, c).reason).toBe("OK");
    expect(verify(chain(), {}, c).reason).toBe("REPLAY");
  });
  it("routeNotInClientRoot", () => {
    const r = verify(chain({ s1: { rcv: "mcp:github.delete_repo" } }), { receiver: "mcp:github.delete_repo" });
    expect(r.reason).toBe("PATH_NOT_ALLOWED");
  });
  it("badProofShapeOrRootId", () => {
    expect(verify(chain(), { proof: writeToken("junk") }).reason).toBe("PATH_NOT_ALLOWED");
    expect(verify(chain(), { proof: "not*base64url" }).reason).toBe("PATH_NOT_ALLOWED");
    expect(verify(chain(), { proof: null }).reason).toBe("PATH_NOT_ALLOWED");
    const p = { ...tree.proofFor(ROUTE), rootId: "v-OLD" };
    expect(verify(chain(), { proof: writeToken(p) }).reason).toBe("PATH_NOT_ALLOWED");
    const extra = writeToken({ ...tree.proofFor(ROUTE), extra: "x" });
    expect(verify(chain(), { proof: extra }).reason).toBe("PATH_NOT_ALLOWED");
  });
  it("responseChainWithoutReceiver", () => {
    const serverTree = buildTree([{ salt: randomBytes(16), path: "mcp-entry/github-tools" }], 8, "v1");
    const s0 = mk("mcp-entry", { rcv: "github-tools" }, session.privateKey);
    const s1 = mk("github-tools", { rcv: "pi", bind: "resp", prev: s0.sig }, session.privateKey);
    const c = cfg({
      keyrings: [ring({ "mcp-entry": session.publicKey, "github-tools": session.publicKey })],
      roots: [pinned(serverTree)],
      allowedOrigins: ["mcp-entry"],
    });
    const r = verifyChain(
      {
        chain: writeToken([s0, s1]), expectedBind: "resp", blocks: null,
        proof: writeToken(serverTree.proofFor("mcp-entry/github-tools")), receiver: "pi", receiverInRoute: false,
      },
      c,
    );
    expect(r.reason).toBe("OK");
  });
  it("loneSurrogateSwapRejected", () => {
    expect(() => mk("session", { inst: "i\uD800" })).toThrow();
    const [s0, s1] = stampsOf(chain());
    const text = canonicalize([{ ...s0, inst: "i@" }, s1]).replace('"i@"', '"i\\ud800"');
    expect(verify({ chain: raw(text), blocks: token(BLOCKS) }).reason).toBe("CHAIN_MISSING");
  });
  it("nonCanonicalSigRejected", () => {
    const [s0, s1] = stampsOf(chain());
    expect(verify(carry([{ ...s0, sig: s0.sig + "==" }, s1])).reason).toBe("CHAIN_MISSING");
    // 64-byte signature: last char carries 2 unused bits; flip them to a non-canonical variant.
    const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const lastIdx = alpha.indexOf(s0.sig[s0.sig.length - 1]!);
    const variant = s0.sig.slice(0, -1) + alpha[lastIdx ^ 1];
    expect(verify(carry([{ ...s0, sig: variant }, s1])).reason).toBe("CHAIN_MISSING");
  });
  it("nonFiniteNowIsExpired", () => {
    for (const bad of [NaN, Infinity]) {
      expect(verify(chain(), {}, cfg({ now: bad })).reason).toBe("EXPIRED");
    }
    expect(verify(chain(), {}, cfg({ callMaxAgeMs: NaN })).reason).toBe("EXPIRED");
    expect(verify(chain(), {}, cfg({ runMaxAgeMs: Infinity })).reason).toBe("EXPIRED");
  });
  it("bindingGoldenValues", () => {
    expect(bindPrompt("hi")).toBe(encode(sha256(utf8("prompt\nhi"))));
    expect(bindResult({ a: 1, _meta: { x: 1 } })).toBe(bindResult({ a: 1 }));
    expect(bindResult({ a: 1 })).toBe(encode(sha256(utf8('result\n{"a":1}'))));
  });

  it("aPipe", () => {
    // a field that is no route node signs and verifies with a pipe in it
    expect(verify(chain({ s0: { rid: "a|b" }, s1: { rid: "a|b", inst: "pi|1" } }))).toEqual({ ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi|1" });
    // an inner operation with a pipe is not an operation name
    expect(verify(chain({ s0rcv: "pi#a|b" })).reason).toBe("BINDING_MISMATCH");
    // a service name with a pipe has no key
    const s0 = mk("session", { rcv: "pi|x" });
    const s1 = mk("pi|x", { rcv: RECEIVER, bind, ext: commitBlock(HOP_BLOCK), prev: s0.sig });
    expect(verify(carry([s0, s1])).reason).toBe("BAD_SIGNATURE");
  });
  it.each([["a number", 5], ["an object", {}], ["undefined", undefined]])("neverThrows: blocks given as %s", (_name, blocks) => {
    expect(() => full(chain(), { blocks: blocks as never })).not.toThrow();
    expect(verify(chain(), { blocks: blocks as never }).reason).toBe("EXTENSION_MISMATCH");
  });
});

describe("checks 9a to 9c and the hand-over", () => {
  /** A fresh config, its own nonce cache, for a service that acts on `example`. */
  const actsOnExample = () => cfg({ extensions: extensionSettings(["example"]) });
  const emptyBlocks = [EMPTY_BLOCK, EMPTY_BLOCK] as const;

  it("handsOverOneEntryPerStampForEachNameItActsOn", () => {
    const blocks = [makeBlock({ example: [] }), makeBlock({ example: [{ note: "n1" }, 7], other: [1] })] as const;
    const r = full(chain({ blocks }), {}, actsOnExample());
    expect(r.reason).toBe("OK");
    expect([...r.handOver!.keys()]).toEqual(["example"]);
    expect(r.handOver!.get("example")).toEqual([{ svc: "session", items: [] }, { svc: "pi", items: [{ note: "n1" }, 7] }]);
  });
  it("aBlockThatOnlyRequiresDoesNotNameTheExtension", () => {
    const r = full(chain({ blocks: [EMPTY_BLOCK, makeBlock({}, ["example"])] }), {}, actsOnExample());
    expect(r.reason).toBe("OK");
    expect(r.handOver!.get("example")).toEqual([{ svc: "session", items: null }, { svc: "pi", items: null }]);
  });
  it("anAbsentTokenIsOneEmptyBlockPerStamp", () => {
    const r = full(chain({ blocks: emptyBlocks }), { blocks: null }, actsOnExample());
    expect(r.reason).toBe("OK");
    expect(r.handOver!.get("example")).toEqual([{ svc: "session", items: null }, { svc: "pi", items: null }]);
  });
  it("aPresentArrayOfEmptyBlocksReadsToo", () => {
    expect(verify(chain({ blocks: emptyBlocks }), { blocks: writeToken([{ items: {}, requires: [] }, { items: {}, requires: [] }]) }).reason).toBe("OK");
  });
  it("aBlocksTokenThatReadsAsNullIsNotAnAbsentToken", () => {
    expect(verify(chain({ blocks: emptyBlocks }), { blocks: writeToken(null) }).reason).toBe("EXTENSION_MISMATCH");
  });
  it("theHandOverIsGivenExactlyWhenTheResultIsOk", () => {
    expect(full(chain()).handOver).toEqual(new Map());
    expect(full(chain(), { peer: { svc: "pi", inst: "10.0.0.7" } }).handOver).toEqual(new Map());
    expect(full(chain(), { proof: null }, actsOnExample()).handOver).toBeNull();
    expect(full(chain(), { blocks: null }, actsOnExample()).handOver).toBeNull();
    expect(full(chain(), {}, cfg({ policyNotAfter: NOW - 1 })).handOver).toBeNull();
  });

  const hop = commitBlock(HOP_BLOCK);
  const mismatches: [string, Carried][] = [
    ["an absent token where a stamp's ext is not empty", { ...chain(), blocks: null }],
    [
      "an ext of the empty block's hash with the empty block sent",
      chain({ blocks: emptyBlocks, s1: { ext: encode(sha256(utf8('{"items":{},"requires":[]}'))) } }),
    ],
    ["one block too few", { ...chain(), blocks: token([EMPTY_BLOCK]) }],
    ["one block too many", { ...chain(), blocks: token([EMPTY_BLOCK, HOP_BLOCK, EMPTY_BLOCK]) }],
    ["an item altered", { ...chain(), blocks: token([EMPTY_BLOCK, makeBlock({ example: [{ note: "n2" }] })]) }],
    ["the two blocks swapped", { ...chain(), blocks: token([HOP_BLOCK, EMPTY_BLOCK]) }],
    ["a token that does not read", { ...chain(), blocks: "!" }],
    ["a block with another member", { ...chain(), blocks: token([EMPTY_BLOCK, { ...HOP_BLOCK, extra: 1 }]) }],
  ];
  it.each(mismatches)("9a: %s is EXTENSION_MISMATCH", (_name, c) => {
    expect(hop).not.toBe("");
    expect(verify(c).reason).toBe("EXTENSION_MISMATCH");
  });

  it("9b: every name in any block is in the allowed list, when there is one", () => {
    const allowExample = cfg({ extensions: extensionSettings([], ["example"]) });
    const inItems = chain({ blocks: [EMPTY_BLOCK, makeBlock({ example: [], other: [1] })] });
    expect(verify(inItems, {}, allowExample).reason).toBe("EXTENSION_NOT_ALLOWED");
    const inFirstRequires = chain({ blocks: [makeBlock({}, ["other"]), HOP_BLOCK] });
    expect(verify(inFirstRequires, {}, allowExample).reason).toBe("EXTENSION_NOT_ALLOWED");
    // the list is looked up by its own members only
    const proto = chain({ blocks: [EMPTY_BLOCK, makeBlock({ constructor: [] })] });
    expect(verify(proto, {}, allowExample).reason).toBe("EXTENSION_NOT_ALLOWED");
    // unset, any name is carried
    for (const c of [inItems, inFirstRequires, proto]) expect(verify(c).reason).toBe("OK");
    expect(verify(chain(), {}, allowExample).reason).toBe("OK");
  });
  it("9c: every name the last block requires is acted on", () => {
    const lastRequires = chain({ blocks: [EMPTY_BLOCK, makeBlock({}, ["example"])] });
    expect(verify(lastRequires).reason).toBe("EXTENSION_REQUIRED");
    expect(verify(lastRequires, {}, actsOnExample()).reason).toBe("OK");
    // only the direct caller's requires binds
    expect(verify(chain({ blocks: [makeBlock({}, ["example"]), HOP_BLOCK] })).reason).toBe("OK");
    // a recorded response is not held to it
    expect(verify(lastRequires, {}, cfg({ extensions: recordExtensionSettings([]) })).reason).toBe("OK");
  });
  it("aRequiredNameOfObjectsPrototypeIsNotActedOn", () => {
    expect(verify(chain({ blocks: [EMPTY_BLOCK, makeBlock({}, ["constructor"])] })).reason).toBe("EXTENSION_REQUIRED");
    const actsOnConstructor = cfg({ extensions: extensionSettings(["constructor"]) });
    const r = full(chain(), {}, actsOnConstructor);
    expect(r.reason).toBe("OK");
    expect(r.handOver!.get("constructor")).toEqual([{ svc: "session", items: null }, { svc: "pi", items: null }]);
    // and a block that lists it hands its items over
    const listed = full(chain({ blocks: [EMPTY_BLOCK, makeBlock({ constructor: [1] })] }), {}, cfg({ extensions: extensionSettings(["constructor"]) }));
    expect(listed.handOver!.get("constructor")).toEqual([{ svc: "session", items: null }, { svc: "pi", items: [1] }]);
  });

  describe("the order", () => {
    const search = { svc: "search", inst: "10.0.0.9" };
    it("aWrongBindingBeatsAlteredBlocks", () => {
      expect(verify(chain(), { expectedBind: "zz", blocks: token(emptyBlocks) }).reason).toBe("BINDING_MISMATCH");
    });
    it("alteredBlocksBeatANameNotAllowed", () => {
      const c = chain({ blocks: [EMPTY_BLOCK, makeBlock({ other: [1] })] });
      const altered = token([EMPTY_BLOCK, makeBlock({ other: [2] })]);
      expect(verify(c, { blocks: altered }, cfg({ extensions: extensionSettings([], ["example"]) })).reason).toBe("EXTENSION_MISMATCH");
    });
    it("aNameNotAllowedBeatsARequirementNotMet", () => {
      const c = chain({ blocks: [EMPTY_BLOCK, makeBlock({ other: [1] }, ["example"])] });
      expect(verify(c, {}, cfg({ extensions: extensionSettings([], ["example"]) })).reason).toBe("EXTENSION_NOT_ALLOWED");
    });
    it("aRequirementNotMetBeatsAWrongPeer", () => {
      const c = chain({ blocks: [EMPTY_BLOCK, makeBlock({}, ["example"])] });
      expect(verify(c, { peer: search })).toEqual({ ok: false, reason: "EXTENSION_REQUIRED", suspectSvc: "search", suspectInst: "10.0.0.9" });
    });
    it("aWrongPeerBeatsNoProof", () => {
      expect(verify(chain(), { proof: null, peer: search })).toEqual({ ok: false, reason: "PEER_MISMATCH", suspectSvc: "search", suspectInst: "10.0.0.9" });
    });
    it("aRequestSentAgainByAnotherPeerSpendsNothing", () => {
      const once = cfg();
      const c = chain();
      expect(verify(c, { peer: search }, once).reason).toBe("PEER_MISMATCH");
      expect(verify(c, { peer: { svc: "pi", inst: "10.0.0.7" } }, once).reason).toBe("OK");
      expect(verify(c, { peer: { svc: "pi", inst: "10.0.0.7" } }, once).reason).toBe("REPLAY");
    });
    it("aReplayIsRefusedBeforeTheRouteIsLookedAt", () => {
      const once = cfg();
      expect(verify(chain(), { proof: null }, once).reason).toBe("PATH_NOT_ALLOWED");
      expect(verify(chain(), { proof: null }, once).reason).toBe("REPLAY");
    });
  });
});

describe("the pinned policy's window", () => {
  const expired = { ok: false, reason: "POLICY_EXPIRED", suspectSvc: "", suspectInst: "" };
  it("at notAfter still verifies", () => expect(verify(chain(), {}, cfg({ policyNotAfter: NOW })).reason).toBe("OK"));
  it("one ms past it is POLICY_EXPIRED, naming no one", () => expect(verify(chain(), {}, cfg({ policyNotAfter: NOW - 1 }))).toEqual(expired));
  it("expires while running: the same config refuses once its clock passes notAfter", () => {
    const c = cfg({ policyNotAfter: NOW + 1000 });
    expect(verify(chain(), {}, c).reason).toBe("OK");
    expect(verify(chain(), {}, { ...c, now: NOW + 1001, nonceKey: nonceKey(["rid-1", "call-2", "req"]) })).toEqual(expired);
  });
  it("is checked before the stamps, and names no peer", () => {
    const c = cfg({ policyNotAfter: NOW - 1 });
    expect(verify(carry("garbage"), { peer: { svc: "search", inst: "10.0.0.9" } }, c)).toEqual(expired);
    expect(verify(chain({ tamperS1Sig: true }), { peer: { svc: "pi", inst: "10.0.0.7" } }, c)).toEqual(expired);
  });
  it("spends no nonce", () => {
    const nonces = new NonceCache(60_000);
    expect(verify(chain(), {}, cfg({ nonces, policyNotAfter: NOW - 1 })).reason).toBe("POLICY_EXPIRED");
    expect(verify(chain(), {}, cfg({ nonces })).reason).toBe("OK");
  });
  it("a window that is absent or not a safe integer fails closed", () => {
    for (const policyNotAfter of [undefined, NaN, Infinity, 1.5, -1, 2 ** 53, "9999999999999" as unknown as number]) {
      expect(verify(chain(), {}, cfg({ policyNotAfter })), String(policyNotAfter)).toEqual(expired);
    }
    const { policyNotAfter: _dropped, ...noWindow } = cfg();
    expect(verify(chain(), {}, noWindow as VerifierConfig)).toEqual(expired);
  });
  it("a non-finite clock is left to freshness, which fails it", () => {
    for (const now of [NaN, Infinity]) expect(verify(chain(), {}, cfg({ now, policyNotAfter: NOW })).reason, String(now)).toBe("EXPIRED");
    // it expires no keyring or root either, so check 7 is still the one that refuses it
    const lapsed = { keyrings: [ring({ session: session.publicKey, pi: pi.publicKey }, NOW - 1)], roots: [pinned(tree, NOW - 1)] };
    for (const now of [NaN, Infinity]) expect(verify(chain(), {}, cfg({ now, ...lapsed })).reason, String(now)).toBe("EXPIRED");
  });
});

describe("several pinned keyrings and roots", () => {
  // the same routes under a second policy, and the mesh root renewed: a new tree under the same rootId
  const second = buildTree([ROUTE, "session/pi"].map((path) => ({ salt: randomBytes(16), path })), 8, "v2");
  const renewed = buildTree([ROUTE, "session/pi"].map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
  const unpinned = buildTree([ROUTE, "session/pi"].map((path) => ({ salt: randomBytes(16), path })), 8, "unpinned");
  const both = ring({ session: session.publicKey, pi: pi.publicKey });
  const proofIn = (t: typeof tree): Over => ({ proof: writeToken(t.proofFor(ROUTE)) });
  const okPi = { ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi-1" };
  const denied = { ok: false, reason: "PATH_NOT_ALLOWED", suspectSvc: "pi", suspectInst: "pi-1" };

  it("aStampVerifiesUnderAKeyOnlyInTheSecondKeyring", () => {
    // the first keyring has the old pi key, or none: each key the current keyrings give is tried
    expect(verify(chain(), {}, cfg({ keyrings: [ring({ session: session.publicKey, pi: other.publicKey }), ring({ pi: pi.publicKey })] }))).toEqual(okPi);
    expect(verify(chain(), {}, cfg({ keyrings: [ring({ session: session.publicKey }), ring({ session: session.publicKey, pi: pi.publicKey })] }))).toEqual(okPi);
  });
  it("aChainMayTakeItsKeysFromTwoKeyrings", () => {
    expect(verify(chain(), {}, cfg({ keyrings: [ring({ session: session.publicKey }), ring({ pi: pi.publicKey })] }))).toEqual(okPi);
    expect(verify(chain(), {}, cfg({ keyrings: [ring({ pi: pi.publicKey }), ring({ session: session.publicKey })] }))).toEqual(okPi);
  });
  it("aKeyOnlyInAnExpiredKeyringIsBadSignature", () => {
    const keyrings = [ring({ session: session.publicKey, pi: other.publicKey }), ring({ pi: pi.publicKey }, NOW - 1)];
    expect(verify(chain(), {}, cfg({ keyrings }))).toEqual({ ok: false, reason: "BAD_SIGNATURE", suspectSvc: "", suspectInst: "" });
    expect(verify(chain(), {}, cfg({ keyrings: [ring({ session: session.publicKey }), ring({ pi: pi.publicKey }, NOW - 1)] })).reason).toBe("BAD_SIGNATURE");
  });
  it("aProofUnderTheSecondRootProves", () => {
    const roots = [pinned(tree), pinned(second)];
    expect(verify(chain(), proofIn(second), cfg({ roots }))).toEqual(okPi);
    expect(verify(chain(), proofIn(tree), cfg({ roots }))).toEqual(okPi);
  });
  it("aProofWhoseRootIdIsPinnedNowhereIsPathNotAllowed", () => {
    expect(verify(chain(), proofIn(unpinned), cfg({ roots: [pinned(tree), pinned(second)] }))).toEqual(denied);
  });
  it("aProofUnderAnExpiredRootIsPathNotAllowedWhileAnotherIsCurrent", () => {
    const roots = [pinned(tree, NOW - 1), pinned(second)];
    expect(verify(chain(), proofIn(tree), cfg({ roots }))).toEqual(denied);
    expect(verify(chain(), proofIn(second), cfg({ roots }))).toEqual(okPi);
  });
  it("twoRootsSharingARootIdBothServe", () => {
    const roots = [pinned(tree), pinned(renewed)];
    expect(verify(chain(), proofIn(tree), cfg({ roots }))).toEqual(okPi);
    expect(verify(chain(), proofIn(renewed), cfg({ roots }))).toEqual(okPi);
    // the renewal's tree is not the old one's: each proof proves against its own root only
    expect(verify(chain(), proofIn(renewed), cfg({ roots: [pinned(tree)] }))).toEqual(denied);
  });
  it("aMemberAtNowIsCurrentAndOneMsPastIsNot", () => {
    const keysUntil = (notAfter: number) => [ring({ session: session.publicKey }), ring({ pi: pi.publicKey }, notAfter)];
    expect(verify(chain(), {}, cfg({ keyrings: keysUntil(NOW) })).reason).toBe("OK");
    expect(verify(chain(), {}, cfg({ keyrings: keysUntil(NOW - 1) })).reason).toBe("BAD_SIGNATURE");
    expect(verify(chain(), {}, cfg({ keyrings: [both], roots: [pinned(tree, NOW)] })).reason).toBe("OK");
    expect(verify(chain(), {}, cfg({ keyrings: [both], roots: [pinned(tree, NOW - 1)] })).reason).toBe("PATH_NOT_ALLOWED");
  });
  it("aWindowThatIsNotANotAfterIsNeverCurrent", () => {
    // a window is an integer in [0, 2^53 - 1], or Infinity for none: any other never makes its member current
    const windows: [number, boolean][] = [
      [1.5, false], [NOW + 0.5, false], [-1, false], [2 ** 53, false], [Number.NaN, false], [2 ** 53 - 1, true], [Infinity, true],
    ];
    for (const [window, current] of windows) {
      const keyrings = [ring({ session: session.publicKey }), ring({ pi: pi.publicKey }, window)];
      expect(verify(chain(), {}, cfg({ keyrings })).reason, `a keyring until ${window}`).toBe(current ? "OK" : "BAD_SIGNATURE");
      const roots = [pinned(tree, window)];
      expect(verify(chain(), {}, cfg({ keyrings: [both], roots })).reason, `a root until ${window}`).toBe(current ? "OK" : "PATH_NOT_ALLOWED");
    }
  });
  it("aKeyringGivesAKeyByOwnNameOnly", () => {
    const inherited = ring(Object.create({ pi: pi.publicKey }) as Record<string, string>);
    expect(verify(chain(), {}, cfg({ keyrings: [ring({ session: session.publicKey }), inherited] })).reason).toBe("BAD_SIGNATURE");
  });
  it("aKeyringWhoseKeysAreNotAMapGivesNoKeyAndNeverThrows", () => {
    for (const keys of [null, undefined, "pi", 5]) {
      const odd = { keys, notAfter: POLICY_NOT_AFTER } as unknown as PinnedKeyring;
      expect(verify(chain(), {}, cfg({ keyrings: [odd, both] })).reason, String(keys)).toBe("OK");
      expect(verify(chain(), {}, cfg({ keyrings: [ring({ session: session.publicKey }), odd] })).reason, String(keys)).toBe("BAD_SIGNATURE");
    }
  });
});
