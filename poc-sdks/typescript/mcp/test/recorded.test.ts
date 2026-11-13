// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  INFLUENCE, bindPrompt, buildTree, commitBlock, extensionSettings, generateKeyPair, influenceBlock,
  makeBlock, nonceKey, randomBytes, recordedCallReason, signStamp, writeToken,
} from "@paztport/core";
import type { Block, InfluenceEntry, JsonValue, OfflineConfig, RecordedSession } from "@paztport/core";
import {
  META_CALL_ID, META_CHAIN, META_EXTENSIONS, META_PROOF, META_VERDICT, bindMcpCall, hasRefusalShape, verifyRecordedCall,
} from "../src/index.ts";
import { retoken, tokenOf } from "./helpers/client.ts";

// Recorded long ago: offline the call is checked against the time recorded with it, not a clock.
const CALL_TS = 9_000_000;
const RUN_TS = CALL_TS - 60_000;
const SESS = "sess-1";
const PROMPT = "fix the typo";
const TOOL = "create_pull_request";
const ROUTE = `session/pi/mcp:github.${TOOL}`;
const entries: InfluenceEntry[] = [{ cls: "third-party", src: "web:example.com", h: "h1" }];
/** The blocks a recorded call carries by default: the origin names influence with nothing, the hop holds `entries`. */
const BLOCKS: readonly Block[] = [influenceBlock([]), influenceBlock(entries)];

function world() {
  const harness = generateKeyPair();
  const tree = buildTree([ROUTE].map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
  const cfg = (seen = new Set<string>()): Omit<OfflineConfig, "nonceKey"> => ({
    keyrings: [{ keys: { session: harness.publicKey, pi: harness.publicKey }, notAfter: Infinity }],
    roots: [{ root: tree.root, rootId: tree.rootId, notAfter: Infinity }],
    allowedOrigins: ["session"],
    sess: SESS,
    seen,
    extensions: extensionSettings([INFLUENCE]),
  });
  const params = (
    callId = "call-1",
    args: Record<string, unknown> = { title: "t" },
    times = { run: RUN_TS, call: CALL_TS },
    rcv = `mcp:github.${TOOL}`,
    blocks: readonly Block[] = BLOCKS,
  ): Record<string, unknown> => {
    const mk = (svc: string, r: string, ts: number, bind: string, ext: string, prev: string) =>
      signStamp({ svc, inst: `${svc}-1`, rid: "rid-1", ts, sess: SESS, rcv: r, bind, ext, prev }, harness.privateKey);
    const s0 = mk("session", "pi", times.run, bindPrompt(PROMPT), commitBlock(blocks[0]!), "");
    const s1 = mk("pi", rcv, times.call, bindMcpCall(TOOL, callId, args), commitBlock(blocks[1]!), s0.sig);
    return {
      name: TOOL,
      arguments: args,
      _meta: {
        [META_CHAIN]: writeToken([s0, s1]),
        [META_PROOF]: writeToken(tree.proofFor(ROUTE)),
        [META_EXTENSIONS]: writeToken(blocks as unknown as JsonValue),
        [META_CALL_ID]: callId,
      },
    };
  };
  const call = { serverId: "github", rid: "rid-1", callId: "call-1", stampedAt: CALL_TS, prompt: PROMPT };
  return { cfg, params, call };
}

describe("verifyRecordedCall", () => {
  it("aRecordedCallVerifiesLongAfterItWasMade", () => {
    const w = world();
    const r = verifyRecordedCall(w.params(), w.call, w.cfg());
    expect(r.result).toEqual({
      ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi-1",
      handOver: new Map([[INFLUENCE, [{ svc: "session", items: [] }, { svc: "pi", items: entries }]]]),
    });
    expect([r.rid, r.callId]).toEqual(["rid-1", "call-1"]);
  });

  it("aRecordedCallRunsCheck9aAndNot9c", () => {
    const w = world();
    // the hop requires an extension the verifier does not act on: 9c is live only, so the call verifies
    const requiring = [BLOCKS[0]!, makeBlock({ [INFLUENCE]: entries as unknown as JsonValue[] }, ["example"])];
    expect(verifyRecordedCall(w.params("call-1", { title: "t" }, undefined, undefined, requiring), w.call, w.cfg()).result.reason)
      .toBe("OK");
    // a block that does not match its stamp is refused by 9a
    const p = w.params();
    (p._meta as Record<string, string>)[META_EXTENSIONS] = writeToken([BLOCKS[0], influenceBlock([])] as unknown as JsonValue);
    expect(verifyRecordedCall(p, w.call, w.cfg()).result.reason).toBe("EXTENSION_MISMATCH");
  });

  it("anItemThatIsNotAnEntryIsInfluenceMismatchBeforeTheSessionsLimits", () => {
    const w = world();
    // a session attested only before the call: the call is past its limits
    const session: RecordedSession = { attested: true, attestedAt: (at) => at < CALL_TS, responseNotAfter: undefined };
    const result = (blocks: readonly Block[]) => {
      const r = verifyRecordedCall(w.params("call-1", { title: "t" }, undefined, undefined, blocks), w.call, w.cfg());
      return recordedCallReason(r.result, session, CALL_TS);
    };
    expect(result(BLOCKS)).toBe("OUTSIDE_SESSION");
    const bad = [BLOCKS[0]!, influenceBlock([{ ...entries[0]!, owner: "" }])];
    expect(result(bad)).toBe("INFLUENCE_MISMATCH");
  });

  it("aRecordedCallMustNameTheRecordsReceiver", () => {
    const w = world();
    expect(verifyRecordedCall(w.params("call-1", { title: "t" }, undefined, "mcp:github.other"), w.call, w.cfg()).result.reason).toBe("BINDING_MISMATCH");
    expect(verifyRecordedCall(w.params(), { ...w.call, serverId: "gitlab" }, w.cfg()).result.reason).toBe("BINDING_MISMATCH");
  });

  it("theRecordMustAgreeWithTheChain", () => {
    const w = world();
    expect(verifyRecordedCall(w.params(), { ...w.call, rid: "rid-2" }, w.cfg()).result.reason).toBe("RID_MISMATCH");
    expect(verifyRecordedCall(w.params(), { ...w.call, callId: "call-2" }, w.cfg()).result.reason).toBe("RID_MISMATCH");
    expect(verifyRecordedCall(w.params(), { ...w.call, stampedAt: CALL_TS + 1 }, w.cfg()).result.reason).toBe("TIME_MISMATCH");
  });

  it("aStampWhoseVersionIsNotFourIsChainMissing", () => {
    const w = world();
    for (const v of [1, 2, 3, 5]) {
      for (const at of [0, 1]) {
        const p = w.params();
        const meta = p._meta as Record<string, string>;
        meta[META_CHAIN] = retoken(meta[META_CHAIN]!, (chain) => {
          chain[at].v = v;
          return chain;
        });
        expect(verifyRecordedCall(p, w.call, w.cfg()).result.reason, `v ${v} at ${at}`).toBe("CHAIN_MISSING");
      }
    }
  });

  it("theOriginBindsTheRecordedPrompt", () => {
    const w = world();
    expect(verifyRecordedCall(w.params(), { ...w.call, prompt: "other" }, w.cfg()).result.reason).toBe("PROMPT_MISMATCH");
    expect(verifyRecordedCall(w.params(), { ...w.call, prompt: undefined }, w.cfg()).result.reason).toBe("PROMPT_MISMATCH");
  });

  it("theBindingAndTheReceiverAreDerivedAsTheServerDerivesThem", () => {
    const w = world();
    const p = w.params();
    (p.arguments as Record<string, unknown>).title = "other";
    expect(verifyRecordedCall(p, w.call, w.cfg()).result.reason).toBe("BINDING_MISMATCH");
    expect(verifyRecordedCall({ ...w.params(), name: "get_issue" }, w.call, w.cfg()).result.reason).toBe("BINDING_MISMATCH");
    expect(verifyRecordedCall(w.params("call-1", { title: "t" }, undefined, `mcp:gitlab.${TOOL}`), { ...w.call, serverId: "gitlab" }, w.cfg()).result.reason).toBe("PATH_NOT_ALLOWED");
    expect(verifyRecordedCall({}, w.call, w.cfg()).result.reason).toBe("CHAIN_MISSING");
  });

  it("aRecordedTokenThatDoesNotReadGetsItsReadersRefusal", () => {
    const w = world();
    const reason = (edit: (m: Record<string, unknown>) => void) => {
      const p = w.params();
      edit(p._meta as Record<string, unknown>);
      return verifyRecordedCall(p, w.call, w.cfg()).result.reason;
    };
    const edited = (m: Record<string, unknown>, name: string, edit: (value: any) => unknown) => {
      m[name] = retoken(m[name] as string, edit);
    };
    expect(reason((m) => edited(m, META_CHAIN, (c) => [c[0], { ...c[1], ts: -1 }]))).toBe("CHAIN_MISSING");
    expect(reason((m) => edited(m, META_CHAIN, (c) => [c[0], { ...c[1], extra: 1 }]))).toBe("CHAIN_MISSING");
    expect(reason((m) => edited(m, META_EXTENSIONS, (blocks) => [blocks[0], { ...blocks[1], extra: 1 }]))).toBe("EXTENSION_MISMATCH");
    expect(reason((m) => edited(m, META_PROOF, (proof) => ({ ...proof, extra: 1 })))).toBe("PATH_NOT_ALLOWED");
    // a recorded member that is not a token gets the same refusals
    expect(reason((m) => { m[META_CHAIN] = []; })).toBe("CHAIN_MISSING");
    expect(reason((m) => { m[META_EXTENSIONS] = BLOCKS; })).toBe("EXTENSION_MISMATCH");
    expect(reason((m) => { m[META_PROOF] = {}; })).toBe("PATH_NOT_ALLOWED");
  });

  it("aCallIsAReplayAnywhereInTheRecordSet", () => {
    const w = world();
    const seen = new Set<string>();
    expect(verifyRecordedCall(w.params(), w.call, w.cfg(seen)).result.reason).toBe("OK");
    expect(verifyRecordedCall(w.params(), w.call, w.cfg(seen)).result.reason).toBe("REPLAY");
    expect([...seen]).toEqual([nonceKey(["rid-1", "call-1", "req"])]);
  });
});

describe("verifyRecordedCall: the run's lifetime", () => {
  const at = (run: number, call: number) => {
    const w = world();
    return verifyRecordedCall(w.params("call-1", { title: "t" }, { run, call }), { ...w.call, stampedAt: call }, w.cfg()).result.reason;
  };

  it("aCallMoreThanThirtyMinutesIntoItsRunIsExpired", () => {
    expect(at(CALL_TS - 1_800_000, CALL_TS)).toBe("OK");
    expect(at(CALL_TS - 1_800_001, CALL_TS)).toBe("EXPIRED");
  });

  it("anOriginMoreThanFiveSecondsAfterItsCallIsExpired", () => {
    expect(at(CALL_TS + 5_000, CALL_TS)).toBe("OK");
    expect(at(CALL_TS + 5_001, CALL_TS)).toBe("EXPIRED");
  });

  it("explicitlyUndefinedLimitsStillGetTheDefaults", () => {
    const w = world();
    const cfg = { ...w.cfg(), runMaxAgeMs: undefined, callMaxAgeMs: undefined };
    const late = (run: number, call: number) =>
      verifyRecordedCall(w.params("call-1", { title: "t" }, { run, call }), { ...w.call, stampedAt: call }, cfg).result.reason;
    expect(late(CALL_TS - 1_800_001, CALL_TS)).toBe("EXPIRED");
    expect(late(CALL_TS + 5_001, CALL_TS)).toBe("EXPIRED");
  });
});

describe("verifyRecordedCall: the library's order", () => {
  it("theChainIsCheckedBeforeTheRecordsCallId", () => {
    const w = world();
    const p = w.params();
    const meta = p._meta as Record<string, string>;
    meta[META_CHAIN] = retoken(meta[META_CHAIN]!, (chain) => {
      chain[1].sig = (chain[1].sig[0] === "A" ? "B" : "A") + chain[1].sig.slice(1);
      return chain;
    });
    expect(verifyRecordedCall(p, { ...w.call, callId: "call-2" }, w.cfg()).result.reason).toBe("BAD_SIGNATURE");
    expect(verifyRecordedCall(w.params(), { ...w.call, callId: "call-2" }, w.cfg()).result.reason).toBe("RID_MISMATCH");
  });
});

describe("hasRefusalShape", () => {
  const refusal = () => ({ isError: true, content: [{ type: "text", text: "refused" }], _meta: { [META_VERDICT]: writeToken({ reason: "INFLUENCE_DENIED" }) } });

  it("aServerRefusalHasIt", () => {
    expect(hasRefusalShape(refusal())).toBe(true);
  });

  it("anythingElseDoesNot", () => {
    expect(hasRefusalShape({ ...refusal(), isError: false })).toBe(false);
    expect(hasRefusalShape({ ...refusal(), _meta: { ...refusal()._meta, extra: 1 } })).toBe(false);
    expect(hasRefusalShape({ ...refusal(), _meta: { [META_VERDICT]: writeToken({ reason: "X", audit: true }) } })).toBe(false);
    expect(hasRefusalShape({ ...refusal(), _meta: { [META_VERDICT]: "INFLUENCE_DENIED" } })).toBe(false);
    // a verdict that does not read, whether a token or the value one would hold, has no refusal shape
    expect(hasRefusalShape({ ...refusal(), _meta: { [META_VERDICT]: { reason: "INFLUENCE_DENIED" } } })).toBe(false);
    expect(hasRefusalShape({ ...refusal(), _meta: { [META_VERDICT]: tokenOf({ reason: "INFLUENCE_DENIED", audit: false }) } })).toBe(false);
    expect(hasRefusalShape({ ...refusal(), _meta: [] })).toBe(false);
    expect(hasRefusalShape({ isError: true, content: [] })).toBe(false);
  });
});
