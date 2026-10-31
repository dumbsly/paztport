// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindPrompt, bindResult } from "../../src/stamp/binding.ts";
import { encode } from "../../src/encoding/b64url.ts";
import { generateKeyPair, randomBytes, sha256, utf8 } from "../../src/crypto/crypto.ts";
import { commitInfluence, type InfluenceEntry } from "../../src/influence/influence.ts";
import { buildTree } from "../../src/policy/merkle.ts";
import { NonceCache } from "../../src/verify/nonce.ts";
import { signStampV3, type StampV3 } from "../../src/stamp/stamp.ts";
import { verifyChainV3, type V3Config, type V3Input } from "../../src/verify/verify-v3.ts";

const NOW = 10_000_000;
/** The pinned keyring and root's window: 2100-01-01, past every clock here. */
const POLICY_NOT_AFTER = 4_102_444_800_000;
const RECEIVER = "mcp:github.t";
const ROUTE = `session/pi/${RECEIVER}`;
const SESS = "sess-1";
const infl: InfluenceEntry[] = [{ cls: "third-party", src: "web:example.com", h: "h1" }];

type Fields = Partial<Omit<StampV3, "sig" | "v">>;
type ChainOpts = { s0?: Fields; s1?: Fields; s0rcv?: string; tamperS1Sig?: boolean; dropRcv?: boolean };
type Over = Partial<V3Input> & { proofRoute?: string };

const session = generateKeyPair();
const pi = generateKeyPair();
const other = generateKeyPair();
const tree = buildTree([ROUTE, "session/pi"].map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
const bind = bindPrompt("t call-1");
const keys: Record<string, string> = { session: session.privateKey, pi: pi.privateKey };

const mk = (svc: string, over: Fields = {}, key = Object.hasOwn(keys, svc) ? keys[svc]! : other.privateKey): StampV3 =>
  signStampV3({ svc, inst: `${svc}-1`, rid: "rid-1", ts: NOW, sess: SESS, rcv: "", bind: "b0", infl: "", prev: "", ...over }, key);

/** Flips the first character: still canonical base64url, no longer the signature. */
const tamper = (sig: string) => (sig[0] === "A" ? "B" : "A") + sig.slice(1);

/** s0 (session, rcv pi) then s1 (pi, rcv the receiver). */
function chain(o: ChainOpts = {}): unknown[] {
  const s0 = mk("session", { rcv: o.s0rcv ?? "pi", ...o.s0 });
  const s1 = mk("pi", { rcv: RECEIVER, bind, infl: commitInfluence(infl), prev: s0.sig, ...o.s1 });
  const last = o.tamperS1Sig ? { ...s1, sig: tamper(s1.sig) } : s1;
  if (o.dropRcv) {
    const { rcv: _rcv, ...rest } = last;
    return [s0, rest];
  }
  return [s0, last];
}

/** The same chain whose last stamp names `rcv` as its receiver. */
const chainEndingAt = (rcv: string) => chain({ s1: { rcv } });

const cfg = (over: Partial<V3Config> = {}): V3Config => ({
  keyring: { session: session.publicKey, pi: pi.publicKey },
  root: tree.root,
  rootId: tree.rootId,
  allowedOrigins: ["session"],
  sess: SESS,
  nonces: new NonceCache(60_000),
  nonceKey: "rid-1|pi|call-1",
  now: NOW,
  policyNotAfter: POLICY_NOT_AFTER,
  ...over,
});

function input(stamps: unknown, over: Over = {}): V3Input {
  const { proofRoute, ...rest } = over;
  return { stamps, expectedBind: bind, influence: infl, proof: tree.proofFor(proofRoute ?? ROUTE), receiver: RECEIVER, receiverInRoute: true, ...rest };
}

const verify = (stamps: unknown, over: Over = {}, c: V3Config = cfg()) => verifyChainV3(input(stamps, over), c);

describe("verifyChainV3", () => {
  it("ok names the last signer", () => expect(verify(chain())).toEqual({ ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi-1" }));
  it("a stamp whose rcv is not the next hop", () => expect(verify(chain({ s0rcv: "orders" })).reason).toBe("BINDING_MISMATCH"));
  it("a chain delivered to another receiver", () => expect(verify(chain(), { receiver: "mcp:github.u" }).reason).toBe("BINDING_MISMATCH"));
  it("a bad signature beats a bad rcv", () => expect(verify(chain({ s0rcv: "orders", tamperS1Sig: true })).reason).toBe("BAD_SIGNATURE"));
  it("a stamp whose v is not 3 is chain missing", () => {
    const [s0, s1] = chain() as [StampV3, StampV3];
    for (const v of [1, 2, 4]) {
      for (const odd of [[{ ...s0, v }, s1], [s0, { ...s1, v }], [{ ...s0, v }, { ...s1, v }]]) {
        expect(verify(odd).reason).toBe("CHAIN_MISSING");
      }
    }
  });
  it("a v3 stamp with rcv missing or non-string", () => expect(verify(chain({ dropRcv: true })).reason).toBe("CHAIN_MISSING"));
  it("the receiver can sit off the route", () => expect(verify(chainEndingAt("pi"), { receiver: "pi", receiverInRoute: false, proofRoute: "session/pi" }).reason).toBe("OK"));
  it("a matching peer is named with its address", () => expect(verify(chain(), { peer: { svc: "pi", inst: "10.0.0.7" } })).toEqual({ ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "10.0.0.7" }));
  it("a peer other than the last signer", () => expect(verify(chain(), { peer: { svc: "search", inst: "10.0.0.9" } })).toEqual({ ok: false, reason: "PEER_MISMATCH", suspectSvc: "search", suspectInst: "10.0.0.9" }));
  it("with a peer, any rejection names it", () => {
    expect(verify(chain({ tamperS1Sig: true }), { peer: { svc: "search", inst: "10.0.0.9" } })).toMatchObject({ reason: "BAD_SIGNATURE", suspectSvc: "search", suspectInst: "10.0.0.9" });
    expect(verify("garbage", { peer: { svc: "search", inst: "10.0.0.9" } })).toMatchObject({ reason: "CHAIN_MISSING", suspectSvc: "search" });
  });
  it("without a peer, early rejections name no one", () => expect(verify(chain({ tamperS1Sig: true }))).toMatchObject({ suspectSvc: "", suspectInst: "" }));
  it("the route fails before the peer is checked", () => expect(verify(chain(), { proofRoute: "session/pi", peer: { svc: "search", inst: "x" } }).reason).toBe("PATH_NOT_ALLOWED"));
  it("a null peer is no peer, and never throws", () => {
    expect(verify(chain(), { peer: null })).toEqual(verify(chain()));
    expect(verify(chain({ tamperS1Sig: true }), { peer: null })).toEqual({ ok: false, reason: "BAD_SIGNATURE", suspectSvc: "", suspectInst: "" });
  });

  it("an rcv that is not a string", () => {
    const [s0, s1] = chain() as [StampV3, StampV3];
    expect(verify([s0, { ...s1, rcv: 5 }]).reason).toBe("CHAIN_MISSING");
    expect(verify([s0, { ...s1, rcv: null }]).reason).toBe("CHAIN_MISSING");
  });
  it("the delimiter in rcv is a bad signature, never a throw", () => {
    expect(() => mk("pi", { rcv: "a|b" })).toThrow();
    const [s0, s1] = chain() as [StampV3, StampV3];
    expect(verify([s0, { ...s1, rcv: "a|b" }]).reason).toBe("BAD_SIGNATURE");
    expect(verify([{ ...s0, rcv: "a|b" }, s1]).reason).toBe("BAD_SIGNATURE");
  });
  it("a lone surrogate in rcv", () => {
    const [s0, s1] = chain() as [StampV3, StampV3];
    expect(verify([s0, { ...s1, rcv: "mcp:\uD800" }]).reason).toBe("CHAIN_MISSING");
  });
  it("rcv is signed: altering it is a bad signature", () => {
    const [s0, s1] = chain() as [StampV3, StampV3];
    expect(verify([s0, { ...s1, rcv: "mcp:github.u" }], { receiver: "mcp:github.u" }).reason).toBe("BAD_SIGNATURE");
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
    const cases: [string, ReturnType<typeof verifyChainV3>][] = [
      ["CHAIN_MISSING", verify([])],
      ["BAD_ORIGIN", verify(chain(), {}, cfg({ allowedOrigins: ["x"] }))],
      ["BAD_SIGNATURE", verify(chain(), {}, cfg({ keyring: { session: session.publicKey, pi: other.publicKey } }))],
      ["BROKEN_LINK", verify(chain({ s1: { prev: "x" } }))],
      ["BINDING_MISMATCH", verify(chain({ s0rcv: "orders" }))],
      ["RID_MISMATCH", verify(chain({ s1: { rid: "rid-2" } }))],
      ["SESSION_UNKNOWN", verify(chain(), {}, cfg({ sess: "other" }))],
      ["EXPIRED", verify(chain(), {}, cfg({ now: NOW + 10 * 60_000 * 60 }))],
      ["BINDING_MISMATCH", verify(chain(), { expectedBind: "zz" })],
      ["INFLUENCE_MISMATCH", verify(chain(), { influence: [] })],
      ["REPLAY", verify(chain(), {}, spent)],
    ];
    for (const [reason, r] of cases) {
      expect([reason, r.reason, r.suspectSvc, r.suspectInst]).toEqual([reason, reason, "", ""]);
    }
  });
  it("notArray", () => {
    expect(verify({}).reason).toBe("CHAIN_MISSING");
    expect(verify(undefined).reason).toBe("CHAIN_MISSING");
  });
  it("emptyArray", () => {
    expect(verify([]).reason).toBe("CHAIN_MISSING");
  });
  it("v1StampMixedIn", () => {
    const [s0, s1] = chain() as [StampV3, StampV3];
    const { v: _v, sess: _s, infl: _i, rcv: _r, ...v1like } = s0;
    expect(verify([v1like, s1]).reason).toBe("CHAIN_MISSING");
    expect(verify([{ ...s0, v: 1 }, s1]).reason).toBe("CHAIN_MISSING");
    expect(verify([{ ...s0, ts: 1.5 }, s1]).reason).toBe("CHAIN_MISSING");
  });
  it("pipeInField", () => {
    expect(() => mk("session", { inst: "a|b" })).toThrow();
    const [s0, s1] = chain() as [StampV3, StampV3];
    expect(verify([{ ...s0, inst: "a|b" }, s1]).reason).toBe("BAD_SIGNATURE");
  });
  it("wrongOrigin", () => {
    const s0 = mk("pi", { rcv: "pi" });
    const s1 = mk("pi", { rcv: RECEIVER, bind, infl: commitInfluence(infl), prev: s0.sig });
    expect(verify([s0, s1]).reason).toBe("BAD_ORIGIN");
  });
  it("badSig", () => {
    const s0 = mk("session", { rcv: "pi" });
    const s1 = mk("pi", { rcv: RECEIVER, bind, infl: commitInfluence(infl), prev: s0.sig }, other.privateKey);
    expect(verify([s0, s1]).reason).toBe("BAD_SIGNATURE");
    const unknown = mk("ghost", { rcv: RECEIVER, bind, prev: s0.sig });
    expect(verify([s0, unknown]).reason).toBe("BAD_SIGNATURE");
    const proto = mk("constructor", { rcv: RECEIVER, bind, prev: s0.sig });
    expect(verify([s0, proto]).reason).toBe("BAD_SIGNATURE");
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
  it("influenceSetDiffersFromInfl", () => {
    const more = [...infl, { cls: "private" as const, src: "file:x", h: "h2" }];
    expect(verify(chain(), { influence: more }).reason).toBe("INFLUENCE_MISMATCH");
    expect(verify(chain(), { influence: [] }).reason).toBe("INFLUENCE_MISMATCH");
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
    expect(verify(chain(), { proof: "junk" }).reason).toBe("PATH_NOT_ALLOWED");
    const p = { ...tree.proofFor(ROUTE), rootId: "v-OLD" };
    expect(verify(chain(), { proof: p }).reason).toBe("PATH_NOT_ALLOWED");
  });
  it("responseChainWithoutReceiver", () => {
    const serverTree = buildTree([{ salt: randomBytes(16), path: "mcp-entry/github-tools" }], 8, "v1");
    const s0 = mk("mcp-entry", { rcv: "github-tools" }, session.privateKey);
    const s1 = mk("github-tools", { rcv: "pi", bind: "resp", prev: s0.sig }, session.privateKey);
    const c = cfg({
      keyring: { "mcp-entry": session.publicKey, "github-tools": session.publicKey },
      root: serverTree.root,
      rootId: serverTree.rootId,
      allowedOrigins: ["mcp-entry"],
    });
    const r = verifyChainV3(
      { stamps: [s0, s1], expectedBind: "resp", influence: [], proof: serverTree.proofFor("mcp-entry/github-tools"), receiver: "pi", receiverInRoute: false },
      c,
    );
    expect(r.reason).toBe("OK");
  });
  it("loneSurrogateSwapRejected", () => {
    expect(() => mk("session", { inst: "i\uD800" })).toThrow();
    const [s0, s1] = chain() as [StampV3, StampV3];
    expect(verify([{ ...s0, inst: "i\uD800" }, s1]).reason).toBe("CHAIN_MISSING");
  });
  it("nonCanonicalSigRejected", () => {
    const [s0, s1] = chain() as [StampV3, StampV3];
    expect(verify([{ ...s0, sig: s0.sig + "==" }, s1]).reason).toBe("CHAIN_MISSING");
    // 64-byte signature: last char carries 2 unused bits; flip them to a non-canonical variant.
    const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const lastIdx = alpha.indexOf(s0.sig[s0.sig.length - 1]!);
    const variant = s0.sig.slice(0, -1) + alpha[lastIdx ^ 1];
    expect(verify([{ ...s0, sig: variant }, s1]).reason).toBe("CHAIN_MISSING");
  });
  it("malformedInfluenceIsInfluenceMismatch", () => {
    const bad = [null, [{ cls: "third-party", src: "\uD800", h: "h" }], [{ cls: "bogus", src: "s", h: "h" }]];
    for (const influence of bad) {
      expect(verify(chain(), { influence: influence as never }).reason).toBe("INFLUENCE_MISMATCH");
    }
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
});

describe("the pinned policy's window", () => {
  const expired = { ok: false, reason: "POLICY_EXPIRED", suspectSvc: "", suspectInst: "" };
  it("at notAfter still verifies", () => expect(verify(chain(), {}, cfg({ policyNotAfter: NOW })).reason).toBe("OK"));
  it("one ms past it is POLICY_EXPIRED, naming no one", () => expect(verify(chain(), {}, cfg({ policyNotAfter: NOW - 1 }))).toEqual(expired));
  it("expires while running: the same config refuses once its clock passes notAfter", () => {
    const c = cfg({ policyNotAfter: NOW + 1000 });
    expect(verify(chain(), {}, c).reason).toBe("OK");
    expect(verify(chain(), {}, { ...c, now: NOW + 1001, nonceKey: "rid-1|pi|call-2" })).toEqual(expired);
  });
  it("is checked before the stamps, and names no peer", () => {
    const c = cfg({ policyNotAfter: NOW - 1 });
    expect(verify("garbage", { peer: { svc: "search", inst: "10.0.0.9" } }, c)).toEqual(expired);
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
    expect(verify(chain(), {}, noWindow as V3Config)).toEqual(expired);
  });
  it("a non-finite clock is left to freshness, which fails it", () => {
    for (const now of [NaN, Infinity]) expect(verify(chain(), {}, cfg({ now, policyNotAfter: NOW })).reason, String(now)).toBe("EXPIRED");
  });
});
