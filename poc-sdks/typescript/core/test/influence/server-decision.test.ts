// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { JsonValue } from "../../src/encoding/json.ts";
import type { InfluenceClass, InfluenceEntry } from "../../src/influence/influence.ts";
import { decideVerifiedCall } from "../../src/influence/server-decision.ts";
import type { StampItems } from "../../src/verify/extensions.ts";

const entry = (cls: InfluenceClass, owner?: string): InfluenceEntry =>
  ({ cls, src: "web:example.com", h: "h1", ...(owner === undefined ? {} : { owner }) });
/** A label, which a request's block must not take for an entry. */
const LABEL: JsonValue = { cls: "private", cid: "c1" };

/** The hand-over of a two-stamp chain, the origin naming influence with nothing and the hop holding `items`. */
const named = (...items: JsonValue[]): StampItems[] => [{ svc: "session", items: [] }, { svc: "pi", items }];

const write = (stamps: StampItems[], over: Partial<Parameters<typeof decideVerifiedCall>[1]> = {}) =>
  decideVerifiedCall(stamps, { isWrite: true, publicDestination: true, served: [], ...over }).verdict;

describe("decideVerifiedCall", () => {
  it("theRequestsInfluenceAloneDecides", () => {
    expect(write(named(entry("private"), entry("third-party")))).toBe("INFLUENCE_DENIED");
    expect(write(named(entry("private"), entry("local-untrusted")))).toBe("INFLUENCE_DENIED");
    expect(write(named(entry("third-party"), entry("public")))).toBe("OK");
    expect(write(named())).toBe("OK");
  });
  it("servedClassesCountWhenTheClientOmitsThem", () => {
    const served = new Set<InfluenceClass>(["private"]);
    expect(write(named(entry("third-party")), { served })).toBe("INFLUENCE_DENIED");
    expect(write(named(), { served: ["private"] })).toBe("OK");
    expect(write(named(), { served: ["private", "third-party"] })).toBe("INFLUENCE_DENIED");
  });
  it("theOwnerOfPrivateDataMustBeTheDestinationOwner", () => {
    const mine = named(entry("third-party"), entry("private", "alice"));
    expect(write(mine, { destinationOwner: "alice" })).toBe("OK");
    expect(write(mine, { destinationOwner: "bob" })).toBe("INFLUENCE_DENIED");
  });
  it("aServedPrivateClassHasNoOwnerSoItIsRefused", () => {
    const stamps = named(entry("third-party"));
    expect(write(stamps, { served: ["private"], destinationOwner: "alice" })).toBe("INFLUENCE_DENIED");
  });
  it("onlyPublicWritesAreDecided", () => {
    const served: InfluenceClass[] = ["private", "third-party"];
    expect(write(named(), { served, publicDestination: false })).toBe("OK");
    expect(write(named(), { served, isWrite: false })).toBe("OK");
  });
  it("aStampThatDoesNotNameInfluenceRefusesAPublicWrite", () => {
    const passAlong: StampItems[] = [{ svc: "session", items: [] }, { svc: "pi", items: null }];
    expect(write(passAlong)).toBe("INFLUENCE_DENIED");
    // a read is not decided by the every-stamp rule
    expect(write(passAlong, { isWrite: false })).toBe("OK");
    expect(write(passAlong, { publicDestination: false })).toBe("OK");
  });
  it("noStampToReadDoesNotRefuseButWhatTheServerServedStillCounts", () => {
    expect(write([])).toBe("OK");
    expect(write([], { served: ["private", "third-party"] })).toBe("INFLUENCE_DENIED");
  });
  it("anItemThatIsNotAnEntryIsInfluenceMismatchNamingItsSigner", () => {
    const opts = { isWrite: true, publicDestination: true, served: [] };
    expect(decideVerifiedCall(named(entry("third-party"), LABEL), opts))
      .toEqual({ verdict: "INFLUENCE_MISMATCH", signer: "pi" });
    // a read too: the items are checked before the rule, whatever the call does
    expect(write(named(LABEL), { isWrite: false })).toBe("INFLUENCE_MISMATCH");
  });
  it("theItemCheckComesBeforeTheEveryStampRule", () => {
    // the block before the bad item does not name influence, which alone would refuse the write
    const stamps: StampItems[] = [{ svc: "session", items: null }, { svc: "pi", items: [LABEL] }];
    expect(decideVerifiedCall(stamps, { isWrite: true, publicDestination: true, served: [] }))
      .toEqual({ verdict: "INFLUENCE_MISMATCH", signer: "pi" });
  });
});
