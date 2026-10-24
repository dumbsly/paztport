// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { commitInfluence, influenceClasses, type InfluenceEntry } from "../src/influence.ts";

const a: InfluenceEntry = { cls: "third-party", src: "web:example.com", h: "hhh1" };
const b: InfluenceEntry = { cls: "private", src: "file:notes", h: "hhh2" };
const c: InfluenceEntry = { cls: "private", src: "file:other", h: "hhh2" };

describe("influence", () => {
  it("emptyCommitsToEmptyString", () => {
    expect(commitInfluence([])).toBe("");
  });
  it("orderInsensitive", () => {
    expect(commitInfluence([a, b, c])).toBe(commitInfluence([c, a, b]));
    expect(commitInfluence([a, b, c])).not.toBe("");
  });
  it("duplicatesCollapse", () => {
    expect(commitInfluence([a, b, a, { ...b }])).toBe(commitInfluence([a, b]));
  });
  it("cidChangesCommitment", () => {
    expect(commitInfluence([{ ...a, cid: "call-1" }])).not.toBe(commitInfluence([a]));
  });
  it("classesCollected", () => {
    expect(influenceClasses([a, b, c])).toEqual(new Set(["third-party", "private"]));
    expect(influenceClasses([])).toEqual(new Set());
  });
  it("cidAbsentVsEmptyOrderIndependent", () => {
    const e = { ...a, cid: "" };
    expect(commitInfluence([a, e])).toBe(commitInfluence([e, a]));
  });
  it("nonAdjacentDuplicatesCollapse", () => {
    expect(commitInfluence([a, b, a])).toBe(commitInfluence([a, a, b]));
    expect(commitInfluence([a, b, a])).toBe(commitInfluence([a, b]));
  });
});
