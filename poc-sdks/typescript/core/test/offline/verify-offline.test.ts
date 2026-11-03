// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindPrompt } from "../../src/stamp/binding.ts";
import { encode } from "../../src/encoding/b64url.ts";
import { generateKeyPair, randomBytes, utf8 } from "../../src/crypto/crypto.ts";
import { canonicalize } from "../../src/encoding/jcs.ts";
import { commitInfluence, type InfluenceEntry } from "../../src/influence/influence.ts";
import { buildTree } from "../../src/policy/merkle.ts";
import { NonceCache } from "../../src/verify/nonce.ts";
import { signStamp, type Stamp } from "../../src/stamp/stamp.ts";
import { verifyChainOffline, type OfflineConfig, type OfflineInput } from "../../src/offline/verify-offline.ts";
import { verifyChain } from "../../src/verify/verify-chain.ts";

// Recorded long ago: offline there is no clock to be fresh against.
const RUN_TS = 1_000;
const STEP_TS = 2_000;
const PROMPT = "fix the typo";
const RECEIVER = "local:read";
const ROUTE = `session/pi/${RECEIVER}`;
const infl: InfluenceEntry[] = [{ cls: "third-party", src: "server:github", h: "h1" }];

type Fields = Partial<Omit<Stamp, "sig" | "v">>;
/** An input's fields to change, the influence and proof as values. */
type Over = Partial<Omit<OfflineInput, "influence" | "proof">> & { influence?: unknown; proof?: unknown };

/**
 * A token of `value`'s JCS bytes, written by the hashing rules, so a value no protocol writer writes still reaches
 * the reader.
 */
const token = (value: unknown): string => encode(utf8(canonicalize(value)));

function world() {
  const session = generateKeyPair();
  const pi = generateKeyPair();
  const other = generateKeyPair();
  const tree = buildTree([ROUTE, "session/pi/local:write"].map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
  const bind = "step-bind";
  const origin = (over: Fields = {}, key = session.privateKey) =>
    signStamp({ svc: "session", inst: "pi-1", rid: "rid-1", ts: RUN_TS, sess: "", rcv: "pi", bind: bindPrompt(PROMPT), infl: "", prev: "", ...over }, key);
  const step = (o: Stamp, over: Fields = {}, key = pi.privateKey) =>
    signStamp({ svc: "pi", inst: "pi-1", rid: "rid-1", ts: STEP_TS, sess: "", rcv: RECEIVER, bind, infl: commitInfluence(infl), prev: o.sig, ...over }, key);
  const chain = (stepOver: Fields = {}, originOver: Fields = {}) => {
    const o = origin(originOver);
    return [o, step(o, stepOver)];
  };
  const cfg = (over: Partial<OfflineConfig> = {}): OfflineConfig => ({
    keyrings: [{ keys: { session: session.publicKey, pi: pi.publicKey }, notAfter: Infinity }],
    roots: [{ root: tree.root, rootId: tree.rootId, notAfter: Infinity }],
    allowedOrigins: ["session"],
    sess: "",
    seen: new Set<string>(),
    nonceKey: "rid-1|call-1|local",
    ...over,
  });
  /** The chain `stamps` as recorded, its influence and proof each carried as its token. */
  const input = (stamps: unknown, over: Over = {}): OfflineInput => {
    const { influence = infl, proof = tree.proofFor(ROUTE), ...rest } = over;
    return {
      chain: token(stamps),
      expectedBind: bind,
      influence: token(influence),
      proof: proof === null ? null : token(proof),
      receiver: RECEIVER,
      receiverInRoute: true,
      rid: "rid-1",
      recordedTs: { last: STEP_TS, run: new Set([RUN_TS]) },
      prompt: PROMPT,
      ...rest,
    };
  };
  return { session, pi, other, tree, bind, origin, step, chain, cfg, input };
}

const SIGNERS = { svcs: ["session", "pi"], inst: "pi-1" };

describe("verifyChainOffline", () => {
  it("aConsistentRecordedChainVerifiesWithNoFreshnessWindow", () => {
    const w = world();
    expect(verifyChainOffline(w.input(w.chain()), w.cfg())).toEqual({ ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi-1" });
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ signers: SIGNERS }))).toMatchObject({ reason: "OK" });
  });

  it("eachReasonInTheLiveOrder", () => {
    const w = world();
    const spent = w.cfg();
    verifyChainOffline(w.input(w.chain()), spent);
    const [o, s] = w.chain() as [Stamp, Stamp];
    const cases: [string, ReturnType<typeof verifyChainOffline>][] = [
      ["CHAIN_MISSING", verifyChainOffline(w.input([]), w.cfg())],
      ["BAD_SIGNATURE", verifyChainOffline(w.input([{ ...o, inst: "pi|1" }, s]), w.cfg())],
      ["BAD_ORIGIN", verifyChainOffline(w.input(w.chain()), w.cfg({ allowedOrigins: ["mcp-entry"] }))],
      ["BAD_SIGNATURE", verifyChainOffline(w.input(w.chain()), w.cfg({ keyrings: [{ keys: { session: w.session.publicKey, pi: w.other.publicKey }, notAfter: Infinity }] }))],
      ["BROKEN_LINK", verifyChainOffline(w.input([o, w.step(o, { prev: "x" })]), w.cfg())],
      ["BINDING_MISMATCH", verifyChainOffline(w.input(w.chain({}, { rcv: "orders" })), w.cfg())],
      ["RID_MISMATCH", verifyChainOffline(w.input(w.chain({ rid: "rid-2" })), w.cfg())],
      ["SESSION_UNKNOWN", verifyChainOffline(w.input(w.chain({ sess: "s" }, { sess: "s" })), w.cfg())],
      ["TIME_MISMATCH", verifyChainOffline(w.input(w.chain(), { recordedTs: { last: STEP_TS + 1 } }), w.cfg())],
      ["PROMPT_MISMATCH", verifyChainOffline(w.input(w.chain(), { prompt: "other" }), w.cfg())],
      ["BINDING_MISMATCH", verifyChainOffline(w.input(w.chain(), { expectedBind: "zz" }), w.cfg())],
      ["INFLUENCE_MISMATCH", verifyChainOffline(w.input(w.chain(), { influence: [] }), w.cfg())],
      ["REPLAY", verifyChainOffline(w.input(w.chain()), spent)],
    ];
    for (const [reason, r] of cases) {
      expect([reason, r.reason, r.suspectSvc, r.suspectInst]).toEqual([reason, reason, "", ""]);
    }
    const denied = verifyChainOffline(w.input(w.chain({ rcv: "local:bash" }), { receiver: "local:bash" }), w.cfg());
    expect(denied).toEqual({ ok: false, reason: "PATH_NOT_ALLOWED", suspectSvc: "pi", suspectInst: "pi-1" });
  });

  it("theFirstFailureInTheLiveOrderIsReported", () => {
    const w = world();
    // a chain wrong in two ways reports the check that comes first
    expect(verifyChainOffline(w.input(w.chain({ sess: "s" }), { recordedTs: { last: 0 } }), w.cfg()).reason).toBe("SESSION_UNKNOWN");
    expect(verifyChainOffline(w.input(w.chain(), { recordedTs: { last: 0 }, prompt: "other" }), w.cfg()).reason).toBe("TIME_MISMATCH");
    expect(verifyChainOffline(w.input(w.chain(), { prompt: "other", expectedBind: "zz" }), w.cfg()).reason).toBe("PROMPT_MISMATCH");
    expect(verifyChainOffline(w.input(w.chain(), { expectedBind: "zz", influence: [] }), w.cfg()).reason).toBe("BINDING_MISMATCH");
    const cfg = w.cfg();
    verifyChainOffline(w.input(w.chain()), cfg);
    expect(verifyChainOffline(w.input(w.chain({ rcv: "local:bash" }), { receiver: "local:bash" }), cfg).reason).toBe("REPLAY");
  });

  it("thePipeDelimiterIsABadSignatureBeforeTheOriginIsLookedAt", () => {
    const w = world();
    const [o, s] = w.chain() as [Stamp, Stamp];
    // an origin from another instance is BAD_ORIGIN; with the delimiter in that field it is BAD_SIGNATURE first
    expect(verifyChainOffline(w.input([{ ...o, inst: "pi-2" }, s]), w.cfg({ signers: SIGNERS })).reason).toBe("BAD_ORIGIN");
    expect(verifyChainOffline(w.input([{ ...o, inst: "pi|2" }, s]), w.cfg({ signers: SIGNERS })).reason).toBe("BAD_SIGNATURE");
    expect(verifyChainOffline(w.input([o, { ...s, bind: "a|b" }]), w.cfg()).reason).toBe("BAD_SIGNATURE");
    expect(verifyChainOffline(w.input([o, { ...s, rcv: "a|b" }]), w.cfg())).toMatchObject({ reason: "BAD_SIGNATURE" });
  });

  it("recordedTimesMustAgree", () => {
    const w = world();
    // the last stamp's time is the recorded one
    expect(verifyChainOffline(w.input(w.chain({ ts: STEP_TS - 1 })), w.cfg()).reason).toBe("TIME_MISMATCH");
    // the origin's time is one of the run's recorded times
    expect(verifyChainOffline(w.input(w.chain(), { recordedTs: { last: STEP_TS, run: new Set([RUN_TS + 1]) } }), w.cfg()).reason).toBe("TIME_MISMATCH");
    expect(verifyChainOffline(w.input(w.chain(), { recordedTs: { last: STEP_TS, run: new Set() } }), w.cfg()).reason).toBe("TIME_MISMATCH");
    expect(verifyChainOffline(w.input(w.chain(), { recordedTs: { last: STEP_TS, run: new Set([7, RUN_TS]) } }), w.cfg()).reason).toBe("OK");
    // a run with no record has no times to compare, and no prompt either
    expect(verifyChainOffline(w.input(w.chain(), { recordedTs: { last: STEP_TS } }), w.cfg()).reason).toBe("OK");
    expect(verifyChainOffline(w.input(w.chain(), { recordedTs: { last: STEP_TS }, prompt: undefined }), w.cfg()).reason).toBe("PROMPT_MISMATCH");
    // a record with no recorded time fails, whatever the chain's times; so does one that is not an object
    for (const recordedTs of [undefined, null, 5, "t"]) {
      const bad = w.input(w.chain(), { recordedTs: recordedTs as never });
      expect(verifyChainOffline(bad, w.cfg()).reason, String(recordedTs)).toBe("TIME_MISMATCH");
    }
    // and so does one whose run times are not a set
    for (const run of [null, [RUN_TS]]) {
      const bad = w.input(w.chain(), { recordedTs: { last: STEP_TS, run: run as never } });
      expect(verifyChainOffline(bad, w.cfg()).reason, JSON.stringify(run)).toBe("TIME_MISMATCH");
    }
  });

  it("theOriginBindsTheRunsPrompt", () => {
    const w = world();
    expect(verifyChainOffline(w.input(w.chain(), { prompt: undefined }), w.cfg()).reason).toBe("PROMPT_MISMATCH");
    expect(verifyChainOffline(w.input(w.chain({}, { bind: bindPrompt("other") })), w.cfg()).reason).toBe("PROMPT_MISMATCH");
  });

  it("aRecordedPromptWithALoneSurrogateIsPromptMismatch", () => {
    const w = world();
    const bad = "fix the \ud800typo";
    expect(() => verifyChainOffline(w.input(w.chain(), { prompt: bad }), w.cfg())).not.toThrow();
    expect(verifyChainOffline(w.input(w.chain(), { prompt: bad }), w.cfg()).reason).toBe("PROMPT_MISMATCH");
  });

  it("everyStampCarriesTheRecordsRid", () => {
    const w = world();
    expect(verifyChainOffline(w.input(w.chain(), { rid: "rid-2" }), w.cfg()).reason).toBe("RID_MISMATCH");
    expect(verifyChainOffline(w.input(w.chain({ rid: "rid-2" }, { rid: "rid-2" })), w.cfg()).reason).toBe("RID_MISMATCH");
    // with no record rid, the stamps agree with the origin's
    expect(verifyChainOffline(w.input(w.chain(), { rid: undefined }), w.cfg()).reason).toBe("OK");
  });

  it("signersPinTheServiceAndInstanceOfEveryStamp", () => {
    const w = world();
    const o = w.origin({ inst: "pi-2" });
    expect(verifyChainOffline(w.input([o, w.step(o)]), w.cfg({ signers: SIGNERS })).reason).toBe("BAD_ORIGIN");
    expect(verifyChainOffline(w.input(w.chain({ inst: "pi-2" })), w.cfg({ signers: SIGNERS })).reason).toBe("BAD_SIGNATURE");
    // a step signed with the session key in the pi stamp's place
    const s = w.origin();
    const swapped = w.step(s, { svc: "session" }, w.session.privateKey);
    expect(verifyChainOffline(w.input([s, swapped]), w.cfg({ signers: SIGNERS })).reason).toBe("BAD_SIGNATURE");
    expect(verifyChainOffline(w.input([...w.chain(), swapped]), w.cfg({ signers: SIGNERS })).reason).toBe("BAD_SIGNATURE");
    // without signers neither is pinned
    expect(verifyChainOffline(w.input([o, w.step(o)]), w.cfg()).reason).toBe("OK");
  });

  it("replayIsCheckedAcrossTheWholeRecordSet", () => {
    const w = world();
    const seen = new Set<string>();
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ seen })).reason).toBe("OK");
    // however much later it was recorded, the same key again is a replay
    const later = w.chain({ ts: STEP_TS + 3_600_000 });
    expect(verifyChainOffline(w.input(later, { recordedTs: { last: STEP_TS + 3_600_000 } }), w.cfg({ seen, runMaxAgeMs: 7_200_000 })).reason).toBe("REPLAY");
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ seen, nonceKey: "rid-1|call-2|local" })).reason).toBe("OK");
    expect([...seen]).toEqual(["rid-1|call-1|local", "rid-1|call-2|local"]);
  });

  it("aChainThatFailsBeforeTheReplayCheckSpendsNoKey", () => {
    const w = world();
    const seen = new Set<string>();
    expect(verifyChainOffline(w.input(w.chain(), { influence: [] }), w.cfg({ seen })).reason).toBe("INFLUENCE_MISMATCH");
    expect(seen.size).toBe(0);
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ seen })).reason).toBe("OK");
    // a chain whose route is not proven did reach the replay check: its key is spent
    const other = new Set<string>();
    expect(verifyChainOffline(w.input(w.chain(), { proof: null }), w.cfg({ seen: other })).reason).toBe("PATH_NOT_ALLOWED");
    expect(other.size).toBe(1);
  });

  it("theSharedChecksGiveTheLiveVerifiersCodes", () => {
    const w = world();
    const live = (stamps: unknown, over: Over = {}) => {
      const { chain, expectedBind, influence, proof, receiver, receiverInRoute } = w.input(stamps, over);
      return verifyChain(
        { chain, expectedBind, influence, proof, receiver, receiverInRoute },
        { keyrings: w.cfg().keyrings, roots: w.cfg().roots, allowedOrigins: ["session"], sess: "", nonces: new NonceCache(60_000), nonceKey: "k", now: STEP_TS, policyNotAfter: 4_102_444_800_000 },
      ).reason;
    };
    const offline = (stamps: unknown, over: Over = {}) => verifyChainOffline(w.input(stamps, over), w.cfg()).reason;
    const [o, s] = w.chain() as [Stamp, Stamp];
    const inputs: [unknown, Over][] = [
      [{}, {}],
      [[{ ...o, v: 1 }, s], {}],
      [[{ ...o, inst: "a|b" }, s], {}],
      [[w.step(o), s], {}],
      [[o, w.step(o, {}, w.other.privateKey)], {}],
      [[o, w.step(o, { svc: "constructor" })], {}],
      [[o, w.step(o, { prev: "x" })], {}],
      [[{ ...o, rcv: "a|b" }, s], {}],
      [w.chain({}, { rcv: "orders" }), {}],
      [[{ ...o, v: 2 }, s], {}],
      [w.chain({ rid: "rid-2" }), {}],
      [w.chain({ sess: "s" }), {}],
      [w.chain(), { expectedBind: "zz" }],
      [w.chain(), { influence: null }],
      [w.chain(), { proof: "junk" }],
      [w.chain(), { receiver: "local:bash" }],
      [w.chain({ rcv: "local:bash" }), { receiver: "local:bash" }],
      [w.chain(), {}],
    ];
    for (const [stamps, over] of inputs) {
      expect(offline(stamps, { ...over, rid: undefined })).toBe(live(stamps, over));
    }
  });

  it("aStampWhoseVersionIsNotThreeIsChainMissing", () => {
    const w = world();
    const [o, s] = w.chain() as [Stamp, Stamp];
    for (const v of [1, 2, 4]) {
      for (const odd of [[{ ...o, v }, s], [o, { ...s, v }], [{ ...o, v }, { ...s, v }]]) {
        expect(verifyChainOffline(w.input(odd), w.cfg())).toMatchObject({ reason: "CHAIN_MISSING" });
        const { chain, expectedBind, influence, proof, receiver, receiverInRoute } = w.input(odd);
        expect(
          verifyChain(
            { chain, expectedBind, influence, proof, receiver, receiverInRoute },
            { keyrings: w.cfg().keyrings, roots: w.cfg().roots, allowedOrigins: ["session"], sess: "", nonces: new NonceCache(60_000), nonceKey: "k", now: STEP_TS, policyNotAfter: 4_102_444_800_000 },
          ).reason,
        ).toBe("CHAIN_MISSING");
      }
    }
  });

  it("aBrokenRcvIsABindingMismatch", () => {
    const w = world();
    // the origin names another next hop than the one that follows it
    expect(verifyChainOffline(w.input(w.chain({}, { rcv: "search" })), w.cfg())).toMatchObject({ reason: "BINDING_MISMATCH" });
    // the last stamp names another receiver than the record's
    expect(verifyChainOffline(w.input(w.chain({ rcv: "local:write" })), w.cfg())).toMatchObject({ reason: "BINDING_MISMATCH" });
    // checked after the signatures: a bad signature still comes first
    const o = w.origin({ rcv: "search" });
    expect(verifyChainOffline(w.input([o, w.step(o, {}, w.other.privateKey)]), w.cfg()).reason).toBe("BAD_SIGNATURE");
  });

  it("ageBoundsNeedNoClock", () => {
    const w = world();
    const at = (originTs: number, stepTs: number) => {
      const o = w.origin({ ts: originTs });
      return verifyChainOffline(
        w.input([o, w.step(o, { ts: stepTs })], { recordedTs: { last: stepTs } }),
        w.cfg({ runMaxAgeMs: 1_800_000, callMaxAgeMs: 5_000 }),
      ).reason;
    };
    // the call is made within the run's lifetime of its origin
    expect(at(RUN_TS, RUN_TS + 1_800_000)).toBe("OK");
    expect(at(RUN_TS, RUN_TS + 1_800_001)).toBe("EXPIRED");
    // and its origin is no more than the call window after it
    expect(at(RUN_TS + 5_000, RUN_TS)).toBe("OK");
    expect(at(RUN_TS + 5_001, RUN_TS)).toBe("EXPIRED");
    // no bounds configured, each limit is its live default, independently
    const bare = (originTs: number, stepTs: number, over: Partial<OfflineConfig> = {}) => {
      const o = w.origin({ ts: originTs });
      return verifyChainOffline(w.input([o, w.step(o, { ts: stepTs })], { recordedTs: { last: stepTs } }), w.cfg(over)).reason;
    };
    expect(bare(RUN_TS, RUN_TS + 1_800_000)).toBe("OK");
    expect(bare(RUN_TS, RUN_TS + 1_800_001)).toBe("EXPIRED");
    expect(bare(RUN_TS + 5_000, RUN_TS)).toBe("OK");
    expect(bare(RUN_TS + 5_001, RUN_TS)).toBe("EXPIRED");
    expect(bare(RUN_TS, RUN_TS + 9e9)).toBe("EXPIRED");
    // one limit configured leaves the other at its default
    expect(bare(RUN_TS, RUN_TS + 1_800_001, { callMaxAgeMs: 5_000 })).toBe("EXPIRED");
    expect(bare(RUN_TS + 5_001, RUN_TS, { runMaxAgeMs: 1_800_000 })).toBe("EXPIRED");
    expect(bare(RUN_TS, RUN_TS + 9e9, { runMaxAgeMs: 9e9 })).toBe("OK");
    expect(bare(RUN_TS + 9, RUN_TS, { callMaxAgeMs: 9 })).toBe("OK");
    // a bound that isn't finite fails closed, as the live window does
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ runMaxAgeMs: NaN, callMaxAgeMs: 5_000 })).reason).toBe("EXPIRED");
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ runMaxAgeMs: 1_800_000, callMaxAgeMs: Infinity })).reason).toBe("EXPIRED");
  });

  it("ageIsCheckedAfterTheRecordedTimesAndBeforeThePrompt", () => {
    const w = world();
    const o = w.origin({ ts: RUN_TS });
    const old = [o, w.step(o, { ts: RUN_TS + 1_800_001 })];
    const cfg = () => w.cfg({ runMaxAgeMs: 1_800_000, callMaxAgeMs: 5_000 });
    expect(verifyChainOffline(w.input(old, { recordedTs: { last: 0 } }), cfg()).reason).toBe("TIME_MISMATCH");
    expect(verifyChainOffline(w.input(old, { recordedTs: { last: RUN_TS + 1_800_001 }, prompt: "other" }), cfg()).reason).toBe("EXPIRED");
  });

  it("aMemberCountsForARecordNoLaterThanItsNotAfter", () => {
    const w = world();
    const keys = { session: w.session.publicKey, pi: w.pi.publicKey };
    const root = (notAfter: number) => ({ root: w.tree.root, rootId: w.tree.rootId, notAfter });
    const at = (keyringNotAfter: number, rootNotAfter: number) =>
      verifyChainOffline(w.input(w.chain()), w.cfg({ keyrings: [{ keys, notAfter: keyringNotAfter }], roots: [root(rootNotAfter)] })).reason;
    expect(at(STEP_TS, STEP_TS)).toBe("OK");
    expect(at(STEP_TS - 1, STEP_TS)).toBe("POLICY_EXPIRED");
    expect(at(STEP_TS, STEP_TS - 1)).toBe("POLICY_EXPIRED");
    // beside a keyring that counts, one that has expired for the record gives no key
    const rotated = [{ keys: { session: w.session.publicKey, pi: w.other.publicKey }, notAfter: STEP_TS }, { keys, notAfter: STEP_TS - 1 }];
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ keyrings: rotated })).reason).toBe("BAD_SIGNATURE");
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ keyrings: [...rotated, { keys, notAfter: STEP_TS }] })).reason).toBe("OK");
    // and a root that has expired for it proves nothing
    const other = buildTree([ROUTE].map((path) => ({ salt: randomBytes(16), path })), 8, "v2");
    const roots = [root(STEP_TS - 1), { root: other.root, rootId: other.rootId, notAfter: STEP_TS }];
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ roots })).reason).toBe("PATH_NOT_ALLOWED");
    expect(verifyChainOffline(w.input(w.chain(), { proof: other.proofFor(ROUTE) }), w.cfg({ roots })).reason).toBe("OK");
  });

  it("aKeyringWhoseKeysAreNotAMapGivesNoKeyAndNeverThrows", () => {
    const w = world();
    const keys = { session: w.session.publicKey, pi: w.pi.publicKey };
    for (const odd of [null, undefined, "pi", 5]) {
      const keyrings = [{ keys: odd as never, notAfter: Infinity }, { keys, notAfter: Infinity }];
      expect(verifyChainOffline(w.input(w.chain()), w.cfg({ keyrings })).reason, String(odd)).toBe("OK");
      expect(verifyChainOffline(w.input(w.chain()), w.cfg({ keyrings: [keyrings[0]!] })).reason, String(odd)).toBe("BAD_SIGNATURE");
    }
  });

  it("noRootCountingForTheRecordIsPolicyExpired", () => {
    const w = world();
    const other = buildTree([ROUTE].map((path) => ({ salt: randomBytes(16), path })), 8, "v2");
    const roots = [{ root: w.tree.root, rootId: w.tree.rootId, notAfter: STEP_TS - 1 }, { root: other.root, rootId: other.rootId, notAfter: 0 }];
    const seen = new Set<string>();
    const expired = { ok: false, reason: "POLICY_EXPIRED", suspectSvc: "", suspectInst: "" };
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ roots, seen }))).toEqual(expired);
    // judged before check 1, so it names no one and spends no key
    expect(verifyChainOffline(w.input([]), w.cfg({ roots, seen }))).toEqual(expired);
    expect(seen.size).toBe(0);
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ roots: [], seen })).reason).toBe("POLICY_EXPIRED");
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ keyrings: [], seen })).reason).toBe("POLICY_EXPIRED");
  });

  it("aRecordWithNoTimeIsLeftToCheck7", () => {
    const w = world();
    const lapsed = w.cfg({
      keyrings: [{ keys: { session: w.session.publicKey, pi: w.pi.publicKey }, notAfter: 0 }],
      roots: [{ root: w.tree.root, rootId: w.tree.rootId, notAfter: 0 }],
    });
    for (const recordedTs of [undefined, null, 5, "t"]) {
      expect(verifyChainOffline(w.input(w.chain(), { recordedTs: recordedTs as never }), lapsed).reason, String(recordedTs)).toBe("TIME_MISMATCH");
    }
    // a record with a time is judged at it
    expect(verifyChainOffline(w.input(w.chain()), lapsed).reason).toBe("POLICY_EXPIRED");
  });
});
