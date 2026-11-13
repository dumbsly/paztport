// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { InfluenceClass } from "../../src/influence/influence.ts";
import type { InfluenceFact } from "../../src/influence/influence-rule.ts";
import { decideServerCall } from "../../src/influence/server-decision.ts";

const DISABLED = ["create_branch", "create_or_update_file", "push_files", "create_pull_request", "add_issue_comment"];
const fact = (cls: InfluenceClass, owner?: string): InfluenceFact => (owner === undefined ? { cls } : { cls, owner });

const write = (over: Partial<Parameters<typeof decideServerCall>[0]> = {}) =>
  decideServerCall({
    tool: "create_branch",
    isWrite: true,
    publicDestination: true,
    attested: true,
    actsOnInfluence: true,
    served: [],
    request: { entries: [], everyStampNames: true },
    disabledWhenUnsafe: DISABLED,
    ...over,
  });
/** The request's influence: these entries, every stamp naming `influence`. */
const named = (...entries: InfluenceFact[]) => ({ entries, everyStampNames: true });

describe("decideServerCall", () => {
  it("theRequestsInfluenceAloneDecides", () => {
    expect(write({ request: named(fact("private"), fact("third-party")) })).toBe("INFLUENCE_DENIED");
    expect(write({ request: named(fact("private"), fact("local-untrusted")) })).toBe("INFLUENCE_DENIED");
    expect(write({ request: named(fact("third-party"), fact("public")) })).toBe("OK");
    expect(write()).toBe("OK");
  });
  it("servedClassesCountWhenTheClientOmitsThem", () => {
    expect(write({ served: new Set<InfluenceClass>(["private"]), request: named(fact("third-party")) }))
      .toBe("INFLUENCE_DENIED");
    expect(write({ served: ["private"] })).toBe("OK");
    expect(write({ served: ["private", "third-party"] })).toBe("INFLUENCE_DENIED");
  });
  it("theOwnerOfPrivateDataMustBeTheDestinationOwner", () => {
    const mine = [fact("third-party"), fact("private", "alice")];
    expect(write({ request: named(...mine), destinationOwner: "alice" })).toBe("OK");
    expect(write({ request: named(...mine), destinationOwner: "bob" })).toBe("INFLUENCE_DENIED");
  });
  it("aServedPrivateClassHasNoOwnerSoItIsRefused", () => {
    expect(write({ served: ["private"], request: named(fact("third-party")), destinationOwner: "alice" }))
      .toBe("INFLUENCE_DENIED");
  });
  it("onlyPublicWritesAreDecided", () => {
    const served: InfluenceClass[] = ["private", "third-party"];
    expect(write({ served, publicDestination: false })).toBe("OK");
    expect(write({ served, tool: "list_issues", isWrite: false })).toBe("OK");
  });
  it("aStampThatDoesNotNameInfluenceRefusesAPublicWrite", () => {
    expect(write({ request: { entries: [], everyStampNames: false } })).toBe("INFLUENCE_DENIED");
  });
  it("aServerThatDoesNotActOnInfluenceAllowsAnAttestedCall", () => {
    expect(write({ actsOnInfluence: false, request: { entries: [], everyStampNames: false } })).toBe("OK");
    expect(write({ actsOnInfluence: false, served: ["private"], request: named(fact("third-party")) })).toBe("OK");
  });
  it("aReadIsNotDecidedByTheEveryStampRule", () => {
    expect(write({ tool: "list_issues", isWrite: false, request: { entries: [], everyStampNames: false } })).toBe("OK");
    expect(write({ publicDestination: false, request: { entries: [], everyStampNames: false } })).toBe("OK");
  });
  it("anAttestedSessionIgnoresTheUnsafeGate", () => {
    expect(DISABLED).toContain("create_branch");
    expect(write()).toBe("OK");
  });
  it("theUnsafeGateRefusesListedTools", () => {
    expect(write({ attested: false })).toBe("UNSAFE_SESSION");
    expect(write({ attested: false, publicDestination: false })).toBe("UNSAFE_SESSION");
    expect(write({ attested: false, tool: "list_issues", isWrite: false })).toBe("OK");
  });
  it("aWriteLeftOutOfTheUnsafeListIsUngated", () => {
    const bad = [fact("private"), fact("third-party")];
    const disabledWhenUnsafe = ["create_pull_request"];
    const served: InfluenceClass[] = ["private", "third-party"];
    expect(write({ attested: false, served, request: named(...bad), disabledWhenUnsafe })).toBe("OK");
    expect(write({ attested: false, tool: "create_pull_request", disabledWhenUnsafe })).toBe("UNSAFE_SESSION");
  });
});
