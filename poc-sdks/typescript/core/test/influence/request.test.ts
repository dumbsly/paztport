// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { influenceReason, readRequestInfluence } from "../../src/influence/request.ts";
import type { InfluenceEntry } from "../../src/influence/influence.ts";
import type { HandOver, StampItems } from "../../src/verify/extensions.ts";
import type { ChainVerification } from "../../src/verify/verify-chain.ts";

const a: InfluenceEntry = { cls: "third-party", src: "web:example.com", h: "h1" };
const b: InfluenceEntry = { cls: "private", src: "file:notes", h: "h2", owner: "alice" };
const notAnEntry = { cls: "third-party", src: "web:example.com" };

const ok = (handOver: HandOver): ChainVerification => ({
  ok: true, reason: "OK", suspectSvc: "b", suspectInst: "b-1", handOver,
});

describe("readRequestInfluence", () => {
  it("holdsEveryItemOfEveryBlockInChainOrder", () => {
    const stamps: StampItems[] = [{ svc: "a", items: [a] }, { svc: "b", items: [b, a] }];
    expect(readRequestInfluence(stamps)).toEqual({ reads: true, entries: [a, b, a], everyStampNames: true });
  });

  it("aBlockThatDoesNotNameInfluenceFailsTheEveryStampRule", () => {
    expect(readRequestInfluence([{ svc: "a", items: [] }, { svc: "b", items: null }])).toEqual({
      reads: true, entries: [], everyStampNames: false,
    });
  });

  it("noStampToReadDoesNotRefuse", () => {
    expect(readRequestInfluence([])).toEqual({ reads: true, entries: [], everyStampNames: true });
  });

  it("anItemThatIsNotAnEntryDoesNotRead", () => {
    expect(readRequestInfluence([{ svc: "a", items: [a] }, { svc: "b", items: [b, notAnEntry] }])).toEqual({
      reads: false, signer: "b",
    });
    // the first block holding one is named, also when an earlier block does not name the extension
    const stamps: StampItems[] = [
      { svc: "a", items: null }, { svc: "b", items: ["x"] }, { svc: "c", items: [notAnEntry] },
    ];
    expect(readRequestInfluence(stamps)).toEqual({ reads: false, signer: "b" });
  });
});

describe("influenceReason", () => {
  it("anOkVerificationWhoseEntriesReadIsOk", () => {
    expect(influenceReason(ok(new Map([["influence", [{ svc: "a", items: [a] }]]])))).toBe("OK");
  });

  it("anOkVerificationHoldingAnItemThatDoesNotReadIsInfluenceMismatch", () => {
    const handOver = new Map([["influence", [{ svc: "a", items: [a] }, { svc: "b", items: [notAnEntry] }]]]);
    expect(influenceReason(ok(handOver))).toBe("INFLUENCE_MISMATCH");
  });

  it("aFailedVerificationKeepsItsReason", () => {
    const failed: ChainVerification = { ok: false, reason: "REPLAY", suspectSvc: "", suspectInst: "", handOver: null };
    expect(influenceReason(failed)).toBe("REPLAY");
  });

  it("anOkVerificationWithNoInfluenceInTheHandOverIsOk", () => {
    expect(influenceReason(ok(new Map([["example", [{ svc: "a", items: ["x"] }]]])))).toBe("OK");
    expect(influenceReason(ok(new Map()))).toBe("OK");
  });
});
