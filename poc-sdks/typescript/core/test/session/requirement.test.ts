// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { ReplyCheck } from "../../src/session/reply-check.ts";
import { callsAfter, NO_REQUIREMENT, requirement } from "../../src/session/requirement.ts";

const ALL: (ReplyCheck | null)[] = ["ATTESTED", "UNSAFE", "MALFORMED_REPLY", "PIN_MISMATCH", "BAD_SIGNATURE", "EXTENSION_REQUIRED", null];
const NOT_LISTED: (ReplyCheck | null)[] = ["UNSAFE", "MALFORMED_REPLY", "PIN_MISMATCH", "BAD_SIGNATURE", null];

describe("callsAfter", () => {
  it("aClientWithNoRequirementMakesCallsAfterAnyOutcome", () => {
    for (const check of ALL) {
      for (const continueWithout of [false, true]) {
        expect(callsAfter(check, ["a"], requirement([], continueWithout))).toEqual({ calls: true, requires: [] });
      }
    }
    expect(callsAfter(null, [], NO_REQUIREMENT)).toEqual({ calls: true, requires: [] });
  });
  it("anAttestedReplyListingTheRequirementLetsCallsCarryItSorted", () => {
    for (const continueWithout of [false, true]) {
      expect(callsAfter("ATTESTED", ["a", "b"], requirement(["b", "a"], continueWithout))).toEqual({ calls: true, requires: ["a", "b"] });
    }
  });
  it("aMissingExtensionMakesNoCallsWithoutTheSwitch", () => {
    expect(callsAfter("EXTENSION_REQUIRED", ["a"], requirement(["b", "a"], false))).toEqual({ calls: false, requires: [] });
  });
  it("aMissingExtensionWithTheSwitchRequiresOnlyWhatTheReplyListsSorted", () => {
    const req = requirement(["b", "a", "c"], true);
    expect(callsAfter("EXTENSION_REQUIRED", ["a"], req)).toEqual({ calls: true, requires: ["a"] });
    expect(callsAfter("EXTENSION_REQUIRED", ["c", "b", "z"], req)).toEqual({ calls: true, requires: ["b", "c"] });
    expect(callsAfter("EXTENSION_REQUIRED", [], req)).toEqual({ calls: true, requires: [] });
  });
  it("anyOtherOutcomeMakesNoCallsWithoutTheSwitch", () => {
    for (const check of NOT_LISTED) {
      // even a reply that listed the names, and one that said "unsafe", cannot switch the requirement off
      expect(callsAfter(check, ["a", "b"], requirement(["b", "a"], false))).toEqual({ calls: false, requires: [] });
    }
  });
  it("anyOtherOutcomeWithTheSwitchMakesCallsThatRequireNothing", () => {
    for (const check of NOT_LISTED) {
      expect(callsAfter(check, ["a", "b"], requirement(["b", "a"], true))).toEqual({ calls: true, requires: [] });
    }
  });
});

describe("requirement", () => {
  it("aRepeatedNameIsRemovedAndTheNamesAreSorted", () => {
    const req = requirement(["influence", "example", "influence"]);
    expect(req.extensions).toEqual(["example", "influence"]);
    expect(callsAfter("ATTESTED", ["example", "influence"], req)).toEqual({ calls: true, requires: ["example", "influence"] });
  });
  it("constructorIsAnExtensionName", () => {
    expect(requirement(["constructor"]).extensions).toEqual(["constructor"]);
  });
  it("aNameThatIsNotAnExtensionNameIsRefused", () => {
    for (const name of ["Constructor", "", "__proto__", "a|b"]) {
      expect(() => requirement([name]), name).toThrow("a name that is not an extension name");
    }
  });
  it("isFrozenAndTheSwitchIsOffUnlessGiven", () => {
    const req = requirement(["influence"]);
    expect(req.continueWithout).toBe(false);
    expect(requirement(["influence"], true).continueWithout).toBe(true);
    expect(Object.isFrozen(req) && Object.isFrozen(req.extensions)).toBe(true);
  });
  // a string is iterable, so read as names it would be one-letter names: "influence" would require seven
  it("aStringIsNotAListOfNames", () => {
    expect(() => requirement("influence" as unknown as string[])).toThrow(TypeError);
    expect(() => requirement("influence" as unknown as string[], true)).toThrow(TypeError);
    expect(requirement(["influence"]).extensions).toEqual(["influence"]);
    expect(requirement(new Set(["influence"])).extensions).toEqual(["influence"]);
  });
  it("noRequirementIsTheEmptyOne", () => {
    expect(NO_REQUIREMENT).toEqual(requirement([]));
  });
});
