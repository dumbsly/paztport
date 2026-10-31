// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { InfluenceClass } from "../../src/influence/influence.ts";
import type { InfluenceFact } from "../../src/influence/influence-rule.ts";
import { decideServerCall, publicWriteDecision } from "../../src/influence/server-decision.ts";

const DISABLED = ["create_branch", "create_or_update_file", "push_files", "create_pull_request", "add_issue_comment"];
const fact = (cls: InfluenceClass, owner?: string): InfluenceFact => (owner === undefined ? { cls } : { cls, owner });

const write = (over: Partial<Parameters<typeof decideServerCall>[0]> = {}) =>
  decideServerCall({
    tool: "create_branch",
    isWrite: true,
    publicDestination: true,
    attested: true,
    served: [],
    clientInfluence: [],
    disabledWhenUnsafe: DISABLED,
    ...over,
  });

describe("publicWriteDecision", () => {
  it("decidesOnlyAWriteToAPublicDestination", () => {
    const bad = [fact("private"), fact("third-party")];
    expect(publicWriteDecision(true, true, bad)).toBe("INFLUENCE_DENIED");
    expect(publicWriteDecision(false, true, bad)).toBe("OK");
    expect(publicWriteDecision(true, false, bad)).toBe("OK");
    expect(publicWriteDecision(true, true, [fact("third-party")])).toBe("OK");
  });
  it("takesTheDestinationOwner", () => {
    const mine = [fact("third-party"), fact("private", "alice")];
    expect(publicWriteDecision(true, true, mine, "alice")).toBe("OK");
    expect(publicWriteDecision(true, true, mine, "bob")).toBe("INFLUENCE_DENIED");
  });
});

describe("decideServerCall", () => {
  it("clientInfluenceAloneDecides", () => {
    expect(write({ clientInfluence: [fact("private"), fact("third-party")] })).toBe("INFLUENCE_DENIED");
    expect(write({ clientInfluence: [fact("private"), fact("local-untrusted")] })).toBe("INFLUENCE_DENIED");
    expect(write({ clientInfluence: [fact("third-party"), fact("public")] })).toBe("OK");
    expect(write()).toBe("OK");
  });
  it("servedClassesCountWhenTheClientOmitsThem", () => {
    expect(write({ served: new Set<InfluenceClass>(["private"]), clientInfluence: [fact("third-party")] })).toBe("INFLUENCE_DENIED");
    expect(write({ served: ["private"] })).toBe("OK");
    expect(write({ served: ["private", "third-party"] })).toBe("INFLUENCE_DENIED");
  });
  it("theOwnerOfPrivateDataMustBeTheDestinationOwner", () => {
    const mine = [fact("third-party"), fact("private", "alice")];
    expect(write({ clientInfluence: mine, destinationOwner: "alice" })).toBe("OK");
    expect(write({ clientInfluence: mine, destinationOwner: "bob" })).toBe("INFLUENCE_DENIED");
  });
  it("aServedPrivateClassHasNoOwnerSoItIsRefused", () => {
    expect(write({ served: ["private"], clientInfluence: [fact("third-party")], destinationOwner: "alice" })).toBe("INFLUENCE_DENIED");
  });
  it("onlyPublicWritesAreDecided", () => {
    const served: InfluenceClass[] = ["private", "third-party"];
    expect(write({ served, publicDestination: false })).toBe("OK");
    expect(write({ served, tool: "list_issues", isWrite: false })).toBe("OK");
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
    expect(write({ attested: false, served: ["private", "third-party"], clientInfluence: bad, disabledWhenUnsafe })).toBe("OK");
    expect(write({ attested: false, tool: "create_pull_request", disabledWhenUnsafe })).toBe("UNSAFE_SESSION");
  });
});
