// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindMcpCall, bindPrompt, bindResult } from "../src/binding.ts";
import { encode } from "../src/b64url.ts";
import { generateKeyPair, randomBytes, sha256, utf8 } from "../src/crypto.ts";
import { commitInfluence, type InfluenceEntry } from "../src/influence.ts";
import { buildTree } from "../src/merkle.ts";
import { NonceCache } from "../src/nonce.ts";
import { signStampV2, type StampV2 } from "../src/stamp.ts";
import { verifyChainV2, type V2Config, type V2Input } from "../src/verify-v2.ts";

const NOW = 10_000_000;
const RECEIVER = "mcp:github.create_pull_request";
const ROUTE = `session/pi/${RECEIVER}`;
const SESS = "sess-1";
const infl: InfluenceEntry[] = [{ cls: "third-party", src: "web:example.com", h: "h1" }];

function world() {
  const harness = generateKeyPair();
  const other = generateKeyPair();
  const tree = buildTree(
    [ROUTE, "session/pi/mcp:github.get_issue"].map((path) => ({ salt: randomBytes(16), path })),
    8,
    "v1",
  );
  const bind = bindMcpCall("create_pull_request", "call-1", { title: "t" });
  const mk = (
    svc: string,
    over: Partial<Omit<StampV2, "sig" | "v">>,
    key = harness.privateKey,
  ): StampV2 =>
    signStampV2(
      { svc, inst: `${svc}-1`, rid: "rid-1", ts: NOW, sess: SESS, bind: "b0", infl: "", prev: "", ...over },
      key,
    );
  const chain = (lastOver: Partial<Omit<StampV2, "sig" | "v">> = {}, firstOver: Partial<Omit<StampV2, "sig" | "v">> = {}) => {
    const s0 = mk("session", firstOver);
    const s1 = mk("pi", { bind, infl: commitInfluence(infl), prev: s0.sig, ...lastOver });
    return [s0, s1];
  };
  const cfg = (over: Partial<V2Config> = {}): V2Config => ({
    keyring: { session: harness.publicKey, pi: harness.publicKey },
    root: tree.root,
    rootId: tree.rootId,
    allowedOrigins: ["session"],
    sess: SESS,
    nonces: new NonceCache(60_000),
    nonceKey: "rid-1|pi|call-1",
    now: NOW,
    ...over,
  });
  const input = (stamps: unknown, over: Partial<V2Input> = {}): V2Input => ({
    stamps,
    expectedBind: bind,
    influence: infl,
    proof: tree.proofFor(ROUTE),
    receiver: RECEIVER,
    ...over,
  });
  return { harness, other, tree, bind, mk, chain, cfg, input };
}

describe("verifyChainV2", () => {
  it("validPasses", () => {
    const w = world();
    const r = verifyChainV2(w.input(w.chain()), w.cfg());
    expect(r).toEqual({ ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi-1" });
  });
  it("notArray", () => {
    const w = world();
    expect(verifyChainV2(w.input({}), w.cfg()).reason).toBe("CHAIN_MISSING");
    expect(verifyChainV2(w.input(undefined), w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("emptyArray", () => {
    const w = world();
    expect(verifyChainV2(w.input([]), w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("v1StampMixedIn", () => {
    const w = world();
    const [s0, s1] = w.chain() as [StampV2, StampV2];
    const { v: _v, sess: _s, infl: _i, ...v1like } = s0;
    expect(verifyChainV2(w.input([v1like, s1]), w.cfg()).reason).toBe("CHAIN_MISSING");
    expect(verifyChainV2(w.input([{ ...s0, v: 1 }, s1]), w.cfg()).reason).toBe("CHAIN_MISSING");
    expect(verifyChainV2(w.input([{ ...s0, ts: 1.5 }, s1]), w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("pipeInField", () => {
    const w = world();
    expect(() => w.mk("session", { inst: "a|b" })).toThrow();
    const [s0, s1] = w.chain() as [StampV2, StampV2];
    expect(verifyChainV2(w.input([{ ...s0, inst: "a|b" }, s1]), w.cfg()).reason).toBe("BAD_SIGNATURE");
  });
  it("wrongOrigin", () => {
    const w = world();
    const s0 = w.mk("pi", {});
    const s1 = w.mk("pi", { bind: w.bind, infl: commitInfluence(infl), prev: s0.sig });
    expect(verifyChainV2(w.input([s0, s1]), w.cfg()).reason).toBe("BAD_ORIGIN");
  });
  it("badSig", () => {
    const w = world();
    const s0 = w.mk("session", {});
    const s1 = w.mk("pi", { bind: w.bind, infl: commitInfluence(infl), prev: s0.sig }, w.other.privateKey);
    expect(verifyChainV2(w.input([s0, s1]), w.cfg()).reason).toBe("BAD_SIGNATURE");
    const unknown = w.mk("ghost", { bind: w.bind, prev: s0.sig });
    expect(verifyChainV2(w.input([s0, unknown]), w.cfg()).reason).toBe("BAD_SIGNATURE");
    const proto = w.mk("constructor", { bind: w.bind, prev: s0.sig });
    expect(verifyChainV2(w.input([s0, proto]), w.cfg()).reason).toBe("BAD_SIGNATURE");
  });
  it("brokenLink", () => {
    const w = world();
    expect(verifyChainV2(w.input(w.chain({ prev: "nope" })), w.cfg()).reason).toBe("BROKEN_LINK");
  });
  it("ridMismatch", () => {
    const w = world();
    expect(verifyChainV2(w.input(w.chain({ rid: "rid-2" })), w.cfg()).reason).toBe("RID_MISMATCH");
  });
  it("wrongSess", () => {
    const w = world();
    expect(verifyChainV2(w.input(w.chain({ sess: "other" })), w.cfg()).reason).toBe("SESSION_UNKNOWN");
    expect(verifyChainV2(w.input(w.chain()), w.cfg({ sess: "other" })).reason).toBe("SESSION_UNKNOWN");
  });
  it("lastStampOlderThan5s", () => {
    const w = world();
    expect(verifyChainV2(w.input(w.chain({ ts: NOW - 5001 })), w.cfg()).reason).toBe("EXPIRED");
    expect(verifyChainV2(w.input(w.chain({ ts: NOW - 5000 })), w.cfg()).reason).toBe("OK");
  });
  it("originOlderThan30min", () => {
    const w = world();
    expect(verifyChainV2(w.input(w.chain({}, { ts: NOW - 1_800_001 })), w.cfg()).reason).toBe("EXPIRED");
  });
  it("lastStampFutureBeyond5s", () => {
    const w = world();
    expect(verifyChainV2(w.input(w.chain({ ts: NOW + 5001 })), w.cfg()).reason).toBe("EXPIRED");
  });
  it("originFutureBeyond5s", () => {
    const w = world();
    expect(verifyChainV2(w.input(w.chain({}, { ts: NOW + 5001 })), w.cfg()).reason).toBe("EXPIRED");
  });
  it("originMinutesOldButLastFresh", () => {
    const w = world();
    expect(verifyChainV2(w.input(w.chain({}, { ts: NOW - 600_000 })), w.cfg()).reason).toBe("OK");
  });
  it("bindMismatch", () => {
    const w = world();
    expect(verifyChainV2(w.input(w.chain(), { expectedBind: "other" }), w.cfg()).reason).toBe("BINDING_MISMATCH");
  });
  it("influenceSetDiffersFromInfl", () => {
    const w = world();
    const more = [...infl, { cls: "private" as const, src: "file:x", h: "h2" }];
    expect(verifyChainV2(w.input(w.chain(), { influence: more }), w.cfg()).reason).toBe("INFLUENCE_MISMATCH");
    expect(verifyChainV2(w.input(w.chain(), { influence: [] }), w.cfg()).reason).toBe("INFLUENCE_MISMATCH");
  });
  it("replayedNonceKey", () => {
    const w = world();
    const cfg = w.cfg();
    expect(verifyChainV2(w.input(w.chain()), cfg).reason).toBe("OK");
    expect(verifyChainV2(w.input(w.chain()), cfg).reason).toBe("REPLAY");
  });
  it("routeNotInClientRoot", () => {
    const w = world();
    const r = verifyChainV2(w.input(w.chain(), { receiver: "mcp:github.delete_repo" }), w.cfg());
    expect(r.reason).toBe("PATH_NOT_ALLOWED");
  });
  it("badProofShapeOrRootId", () => {
    const w = world();
    expect(verifyChainV2(w.input(w.chain(), { proof: "junk" }), w.cfg()).reason).toBe("PATH_NOT_ALLOWED");
    const p = { ...w.tree.proofFor(ROUTE), rootId: "v-OLD" };
    expect(verifyChainV2(w.input(w.chain(), { proof: p }), w.cfg()).reason).toBe("PATH_NOT_ALLOWED");
  });
  it("responseChainWithoutReceiver", () => {
    const w = world();
    const tree = buildTree([{ salt: randomBytes(16), path: "mcp-entry/github-tools" }], 8, "v1");
    const s0 = w.mk("mcp-entry", {});
    const s1 = w.mk("github-tools", { bind: "resp", prev: s0.sig });
    const cfg = w.cfg({
      keyring: { "mcp-entry": w.harness.publicKey, "github-tools": w.harness.publicKey },
      root: tree.root,
      rootId: tree.rootId,
      allowedOrigins: ["mcp-entry"],
    });
    const r = verifyChainV2(
      { stamps: [s0, s1], expectedBind: "resp", influence: [], proof: tree.proofFor("mcp-entry/github-tools") },
      cfg,
    );
    expect(r.reason).toBe("OK");
  });
  it("loneSurrogateSwapRejected", () => {
    const w = world();
    expect(() => w.mk("session", { inst: "i\uD800" })).toThrow();
    const [s0, s1] = w.chain() as [StampV2, StampV2];
    expect(verifyChainV2(w.input([{ ...s0, inst: "i\uD800" }, s1]), w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("nonCanonicalSigRejected", () => {
    const w = world();
    const [s0, s1] = w.chain() as [StampV2, StampV2];
    expect(verifyChainV2(w.input([{ ...s0, sig: s0.sig + "==" }, s1]), w.cfg()).reason).toBe("CHAIN_MISSING");
    // 64-byte signature: last char carries 2 unused bits; flip them to a non-canonical variant.
    const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const lastIdx = alpha.indexOf(s0.sig[s0.sig.length - 1]!);
    const variant = s0.sig.slice(0, -1) + alpha[lastIdx ^ 1];
    expect(verifyChainV2(w.input([{ ...s0, sig: variant }, s1]), w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("malformedInfluenceIsInfluenceMismatch", () => {
    const w = world();
    const bad = [null, [{ cls: "third-party", src: "\uD800", h: "h" }], [{ cls: "bogus", src: "s", h: "h" }]];
    for (const influence of bad) {
      const r = verifyChainV2(w.input(w.chain(), { influence: influence as never }), w.cfg());
      expect(r.reason).toBe("INFLUENCE_MISMATCH");
    }
  });
  it("bindMcpCallRejectsNewlines", () => {
    expect(() => bindMcpCall("a\nb", "c", {})).toThrow();
    expect(() => bindMcpCall("a", "b\nc", {})).toThrow();
  });
  it("nonFiniteNowIsExpired", () => {
    const w = world();
    for (const bad of [NaN, Infinity]) {
      expect(verifyChainV2(w.input(w.chain()), w.cfg({ now: bad })).reason).toBe("EXPIRED");
    }
    expect(verifyChainV2(w.input(w.chain()), w.cfg({ callMaxAgeMs: NaN })).reason).toBe("EXPIRED");
    expect(verifyChainV2(w.input(w.chain()), w.cfg({ runMaxAgeMs: Infinity })).reason).toBe("EXPIRED");
  });
  it("bindingGoldenValues", () => {
    expect(bindPrompt("hi")).toBe(encode(sha256(utf8("hi"))));
    expect(bindResult({ a: 1, _meta: { x: 1 } })).toBe(bindResult({ a: 1 }));
    expect(bindResult({ a: 1 })).toBe(encode(sha256(utf8('{"a":1}'))));
  });
});
