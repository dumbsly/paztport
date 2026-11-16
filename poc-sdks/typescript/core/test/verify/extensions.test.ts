// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { extensionSettings, NO_EXTENSIONS, recordExtensionSettings } from "../../src/verify/extensions.ts";

describe("extension settings", () => {
  it("refusesANameThatIsNotAnExtensionName", () => {
    for (const bad of ["", "Example", "a_b", "a.b", "x".repeat(33), "toString", 5 as unknown as string]) {
      expect(() => extensionSettings([bad]), String(bad)).toThrow("not an extension name");
      expect(() => extensionSettings([], [bad]), String(bad)).toThrow("not an extension name");
      expect(() => recordExtensionSettings([bad]), String(bad)).toThrow("not an extension name");
    }
    expect(extensionSettings(["x".repeat(32), "a-0", "constructor"]).actsOn.size).toBe(3);
  });
  // a string is iterable, so read as names it would be one-letter names: "influence" would act on seven
  it("aStringIsNotAListOfNames", () => {
    // a String object iterates the same way
    for (const word of ["influence", new String("influence")] as unknown as string[][]) {
      expect(() => extensionSettings(word)).toThrow(TypeError);
      expect(() => extensionSettings([], word)).toThrow(TypeError);
      expect(() => recordExtensionSettings(word, ["influence"])).toThrow(TypeError);
      expect(() => recordExtensionSettings([], word)).toThrow(TypeError);
    }
    for (const names of [["influence"], new Set(["influence"])]) {
      expect(extensionSettings(names).actsOn).toEqual(new Set(["influence"]));
      expect(extensionSettings([], names).allowed).toEqual(new Set(["influence"]));
      expect(recordExtensionSettings(names, names).actsOn).toEqual(new Set(["influence"]));
    }
  });
  it("refusesAnActsOnNameOutsideTheAllowedList", () => {
    expect(() => extensionSettings(["example"], ["other"])).toThrow("outside the allowed list");
    expect(() => recordExtensionSettings(["example"], [])).toThrow("outside the allowed list");
    // an allowed list is looked up by its own members only
    expect(() => extensionSettings(["constructor"], ["example"])).toThrow("outside the allowed list");
    expect(extensionSettings(["example"], ["example", "other"]).allowed).toEqual(new Set(["example", "other"]));
  });
  it("leavesAllowedUndefinedWhenNotGiven", () => {
    expect(extensionSettings(["example"]).allowed).toBeUndefined();
    expect(recordExtensionSettings([]).allowed).toBeUndefined();
    expect(extensionSettings([], []).allowed).toEqual(new Set());
  });
  it("enforcesRequiresLiveButNotForARecordedResponse", () => {
    expect(extensionSettings([]).enforceRequires).toBe(true);
    expect(recordExtensionSettings([]).enforceRequires).toBe(false);
  });
  it("isFrozen", () => {
    const s = extensionSettings(["example"]);
    expect(Object.isFrozen(s)).toBe(true);
    expect(s.actsOn).toEqual(new Set(["example"]));
  });
  it("noExtensionsActsOnNothingAndAllowsAnyName", () => {
    expect(NO_EXTENSIONS).toEqual({ actsOn: new Set(), allowed: undefined, enforceRequires: true });
  });
});
