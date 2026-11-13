// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { ReplyCheck } from "../../src/session/reply-check.ts";
import { callsAfter, NO_REQUIREMENT } from "../../src/session/requirement.ts";

const ALL: (ReplyCheck | null)[] = ["ATTESTED", "UNSAFE", "MALFORMED_REPLY", "PIN_MISMATCH", "BAD_SIGNATURE", "EXTENSION_REQUIRED", null];
const NOT_LISTED: (ReplyCheck | null)[] = ["UNSAFE", "MALFORMED_REPLY", "PIN_MISMATCH", "BAD_SIGNATURE", null];

describe("callsAfter", () => {
  it("aClientWithNoRequirementMakesCallsAfterAnyOutcome", () => {
    for (const check of ALL) {
      for (const continueWithout of [false, true]) {
        expect(callsAfter(check, ["a"], { extensions: [], continueWithout })).toEqual({ calls: true, requires: [] });
      }
    }
    expect(callsAfter(null, [], NO_REQUIREMENT)).toEqual({ calls: true, requires: [] });
  });
  it("anAttestedReplyListingTheRequirementLetsCallsCarryItSorted", () => {
    for (const continueWithout of [false, true]) {
      expect(callsAfter("ATTESTED", ["a", "b"], { extensions: ["b", "a"], continueWithout })).toEqual({ calls: true, requires: ["a", "b"] });
    }
  });
  it("aMissingExtensionMakesNoCallsWithoutTheSwitch", () => {
    expect(callsAfter("EXTENSION_REQUIRED", ["a"], { extensions: ["b", "a"], continueWithout: false })).toEqual({ calls: false, requires: [] });
  });
  it("aMissingExtensionWithTheSwitchRequiresOnlyWhatTheReplyListsSorted", () => {
    const req = { extensions: ["b", "a", "c"], continueWithout: true };
    expect(callsAfter("EXTENSION_REQUIRED", ["a"], req)).toEqual({ calls: true, requires: ["a"] });
    expect(callsAfter("EXTENSION_REQUIRED", ["c", "b", "z"], req)).toEqual({ calls: true, requires: ["b", "c"] });
    expect(callsAfter("EXTENSION_REQUIRED", [], req)).toEqual({ calls: true, requires: [] });
  });
  it("anyOtherOutcomeMakesNoCallsWithoutTheSwitch", () => {
    for (const check of NOT_LISTED) {
      // even a reply that listed the names, and one that said "unsafe", cannot switch the requirement off
      expect(callsAfter(check, ["a", "b"], { extensions: ["b", "a"], continueWithout: false })).toEqual({ calls: false, requires: [] });
    }
  });
  it("anyOtherOutcomeWithTheSwitchMakesCallsThatRequireNothing", () => {
    for (const check of NOT_LISTED) {
      expect(callsAfter(check, ["a", "b"], { extensions: ["b", "a"], continueWithout: true })).toEqual({ calls: true, requires: [] });
    }
  });
});
