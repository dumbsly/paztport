// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/encoding/jcs.ts";
import type { JsonValue } from "../../src/encoding/json.ts";
import {
  entryOf, INFLUENCE, influenceBlock, influenceClasses, type InfluenceEntry,
} from "../../src/influence/influence.ts";
import { commitBlock, itemsUnder } from "../../src/stamp/block.ts";

const a: InfluenceEntry = { cls: "third-party", src: "web:example.com", h: "hhh1" };
const b: InfluenceEntry = { cls: "private", src: "file:notes", h: "hhh2" };
const c: InfluenceEntry = { cls: "private", src: "file:other", h: "hhh2" };

describe("entryOf", () => {
  it("readsAnEntryWithoutCidOrOwner", () => {
    expect(entryOf({ cls: "public", h: "x", src: "s" })).toEqual({ cls: "public", src: "s", h: "x" });
  });

  it("readsAnEntryWithCidAndOwner", () => {
    const item = { cid: "c", cls: "private", h: "x", owner: "o", src: "s" };
    expect(entryOf(item)).toEqual({ cls: "private", src: "s", h: "x", cid: "c", owner: "o" });
  });

  it.each([
    ["a string", "x"],
    ["an array", [{ cls: "public", h: "x", src: "s" }]],
    ["another member", { cls: "public", extra: 1, h: "x", src: "s" }],
    ["an unknown cls", { cls: "nope", h: "x", src: "s" }],
    ["a number as src", { cls: "public", h: "x", src: 1 }],
    ["a number as h", { cls: "public", h: 2, src: "s" }],
    ["a number as cid", { cid: 3, cls: "public", h: "x", src: "s" }],
    ["an empty owner", { cls: "private", h: "x", owner: "", src: "s" }],
  ])("refuses %s", (_name, item) => {
    expect(() => entryOf(item as JsonValue)).toThrow(Error);
  });
});

describe("influenceClasses", () => {
  it("collectsEachClassOnce", () => {
    expect(influenceClasses([a, b, c])).toEqual(new Set(["third-party", "private"]));
    expect(influenceClasses([])).toEqual(new Set());
  });
});

describe("influenceBlock", () => {
  it("namesInfluenceWithNothingToAddAndIsNotTheEmptyBlock", () => {
    const block = influenceBlock([]);
    expect(canonicalize(block as unknown as JsonValue)).toBe('{"items":{"influence":[]},"requires":[]}');
    expect(commitBlock(block)).not.toBe("");
  });

  it("holdsTheItemsInOrderAndTheRequiresSorted", () => {
    const block = influenceBlock([b, a], ["influence", "example"]);
    expect(itemsUnder(block, INFLUENCE)).toEqual([b, a]);
    expect(block.requires).toEqual(["example", "influence"]);
  });
});
