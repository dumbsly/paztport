// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindPrompt } from "../src/binding.ts";
import { generateKeyPair, randomBytes } from "../src/crypto.ts";
import { commitInfluence, type InfluenceEntry } from "../src/influence.ts";
import { buildTree } from "../src/merkle.ts";
import { NonceCache } from "../src/nonce.ts";
import { signStampV2, type StampV2 } from "../src/stamp.ts";
import { verifyChainOffline, type OfflineConfig, type OfflineInput } from "../src/verify-offline.ts";
import { verifyChainV2 } from "../src/verify-v2.ts";

// Recorded long ago: offline there is no clock to be fresh against.
const RUN_TS = 1_000;
const STEP_TS = 2_000;
const PROMPT = "fix the typo";
const RECEIVER = "local:read";
const ROUTE = `session/pi/${RECEIVER}`;
const infl: InfluenceEntry[] = [{ cls: "third-party", src: "server:github", h: "h1" }];

type Fields = Partial<Omit<StampV2, "sig" | "v">>;

function world() {
  const session = generateKeyPair();
  const pi = generateKeyPair();
  const other = generateKeyPair();
  const tree = buildTree([ROUTE, "session/pi/local:write"].map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
  const bind = "step-bind";
  const origin = (over: Fields = {}, key = session.privateKey) =>
    signStampV2({ svc: "session", inst: "pi-1", rid: "rid-1", ts: RUN_TS, sess: "", bind: bindPrompt(PROMPT), infl: "", prev: "", ...over }, key);
  const step = (o: StampV2, over: Fields = {}, key = pi.privateKey) =>
    signStampV2({ svc: "pi", inst: "pi-1", rid: "rid-1", ts: STEP_TS, sess: "", bind, infl: commitInfluence(infl), prev: o.sig, ...over }, key);
  const chain = (stepOver: Fields = {}, originOver: Fields = {}) => {
    const o = origin(originOver);
    return [o, step(o, stepOver)];
  };
  const cfg = (over: Partial<OfflineConfig> = {}): OfflineConfig => ({
    keyring: { session: session.publicKey, pi: pi.publicKey },
    root: tree.root,
    rootId: tree.rootId,
    allowedOrigins: ["session"],
    sess: "",
    seen: new Set<string>(),
    nonceKey: "rid-1|call-1|local",
    ...over,
  });
  const input = (stamps: unknown, over: Partial<OfflineInput> = {}): OfflineInput => ({
    stamps,
    expectedBind: bind,
    influence: infl,
    proof: tree.proofFor(ROUTE),
    receiver: RECEIVER,
    rid: "rid-1",
    recordedTs: { last: STEP_TS, run: new Set([RUN_TS]) },
    prompt: PROMPT,
    ...over,
  });
  return { session, pi, other, tree, bind, origin, step, chain, cfg, input };
}

const SIGNERS = { svcs: ["session", "pi"], inst: "pi-1" };

describe("verifyChainOffline", () => {
  it("aConsistentRecordedChainVerifiesWithNoFreshnessWindow", () => {
    const w = world();
    expect(verifyChainOffline(w.input(w.chain()), w.cfg())).toEqual({ ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi-1" });
    expect(verifyChainOffline(w.input(w.chain()), w.cfg({ signers: SIGNERS })).reason).toBe("OK");
  });

  it("eachReasonInTheLiveOrder", () => {
    const w = world();
    const spent = w.cfg();
    verifyChainOffline(w.input(w.chain()), spent);
    const [o, s] = w.chain() as [StampV2, StampV2];
    const cases: [string, ReturnType<typeof verifyChainOffline>][] = [
      ["CHAIN_MISSING", verifyChainOffline(w.input([]), w.cfg())],
      ["BAD_SIGNATURE", verifyChainOffline(w.input([{ ...o, inst: "pi|1" }, s]), w.cfg())],
      ["BAD_ORIGIN", verifyChainOffline(w.input(w.chain()), w.cfg({ allowedOrigins: ["mcp-entry"] }))],
      ["BAD_SIGNATURE", verifyChainOffline(w.input(w.chain()), w.cfg({ keyring: { session: w.session.publicKey, pi: w.other.publicKey } }))],
      ["BROKEN_LINK", verifyChainOffline(w.input([o, w.step(o, { prev: "x" })]), w.cfg())],
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
    const denied = verifyChainOffline(w.input(w.chain(), { receiver: "local:bash" }), w.cfg());
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
    expect(verifyChainOffline(w.input(w.chain(), { receiver: "local:bash" }), cfg).reason).toBe("REPLAY");
  });

  it("thePipeDelimiterIsABadSignatureBeforeTheOriginIsLookedAt", () => {
    const w = world();
    const [o, s] = w.chain() as [StampV2, StampV2];
    // an origin from another instance is BAD_ORIGIN; with the delimiter in that field it is BAD_SIGNATURE first
    expect(verifyChainOffline(w.input([{ ...o, inst: "pi-2" }, s]), w.cfg({ signers: SIGNERS })).reason).toBe("BAD_ORIGIN");
    expect(verifyChainOffline(w.input([{ ...o, inst: "pi|2" }, s]), w.cfg({ signers: SIGNERS })).reason).toBe("BAD_SIGNATURE");
    expect(verifyChainOffline(w.input([o, { ...s, bind: "a|b" }]), w.cfg()).reason).toBe("BAD_SIGNATURE");
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
    // with no recorded times nothing is compared
    expect(verifyChainOffline(w.input(w.chain({ ts: 99 }, { ts: 98 }), { recordedTs: undefined }), w.cfg()).reason).toBe("OK");
  });

  it("theOriginBindsTheRunsPrompt", () => {
    const w = world();
    expect(verifyChainOffline(w.input(w.chain(), { prompt: undefined }), w.cfg()).reason).toBe("PROMPT_MISMATCH");
    expect(verifyChainOffline(w.input(w.chain({}, { bind: bindPrompt("other") })), w.cfg()).reason).toBe("PROMPT_MISMATCH");
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
    expect(verifyChainOffline(w.input(later, { recordedTs: { last: STEP_TS + 3_600_000 } }), w.cfg({ seen })).reason).toBe("REPLAY");
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
    const live = (stamps: unknown, over: { expectedBind?: string; influence?: InfluenceEntry[]; proof?: unknown; receiver?: string } = {}) =>
      verifyChainV2(
        { stamps, expectedBind: w.bind, influence: infl, proof: w.tree.proofFor(ROUTE), receiver: RECEIVER, ...over },
        { keyring: w.cfg().keyring, root: w.tree.root, rootId: w.tree.rootId, allowedOrigins: ["session"], sess: "", nonces: new NonceCache(60_000), nonceKey: "k", now: STEP_TS },
      ).reason;
    const offline = (stamps: unknown, over: Partial<OfflineInput> = {}) => verifyChainOffline(w.input(stamps, over), w.cfg()).reason;
    const [o, s] = w.chain() as [StampV2, StampV2];
    const inputs: [unknown, { expectedBind?: string; influence?: InfluenceEntry[]; proof?: unknown; receiver?: string }][] = [
      [{}, {}],
      [[{ ...o, v: 1 }, s], {}],
      [[{ ...o, inst: "a|b" }, s], {}],
      [[w.step(o), s], {}],
      [[o, w.step(o, {}, w.other.privateKey)], {}],
      [[o, w.step(o, { svc: "constructor" })], {}],
      [[o, w.step(o, { prev: "x" })], {}],
      [w.chain({ rid: "rid-2" }), {}],
      [w.chain({ sess: "s" }), {}],
      [w.chain(), { expectedBind: "zz" }],
      [w.chain(), { influence: null as never }],
      [w.chain(), { proof: "junk" }],
      [w.chain(), { receiver: "local:bash" }],
      [w.chain(), {}],
    ];
    for (const [stamps, over] of inputs) {
      expect(offline(stamps, { ...over, rid: undefined })).toBe(live(stamps, over));
    }
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
    // without bounds a recorded chain has no age limit
    const o = w.origin({ ts: RUN_TS });
    expect(verifyChainOffline(w.input([o, w.step(o, { ts: RUN_TS + 9e9 })], { recordedTs: { last: RUN_TS + 9e9 } }), w.cfg()).reason).toBe("OK");
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
});
