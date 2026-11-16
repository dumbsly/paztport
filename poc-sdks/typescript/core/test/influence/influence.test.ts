// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { canonicalize } from "../../src/encoding/jcs.ts";
import type { JsonValue } from "../../src/encoding/json.ts";
import {
  entryOf, INFLUENCE, influenceBlock, influenceClasses, influenceEntry, type InfluenceClass, type InfluenceEntry,
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

describe("influenceEntry", () => {
  it("buildsTheEntryEntryOfReads", () => {
    const full = influenceEntry("private", "github:acme/app#42", "h1", "alice", "cid-1");
    expect(full).toEqual({ cls: "private", src: "github:acme/app#42", h: "h1", cid: "cid-1", owner: "alice" });
    expect(entryOf(JSON.parse(canonicalize(full)) as JsonValue)).toEqual(full);
    // an absent member is left out, not written as undefined, so the entry's JCS is the literal's
    const bare = influenceEntry("local-untrusted", "local:read", "h2");
    expect(Object.keys(bare)).toEqual(["cls", "src", "h"]);
    expect(canonicalize(bare)).toBe(canonicalize({ cls: "local-untrusted", src: "local:read", h: "h2" }));
    expect(Object.keys(influenceEntry("public", "s", "h", undefined, "c"))).toEqual(["cls", "src", "h", "cid"]);
  });

  // what Java's constructor refuses: a member missing, an empty owner, a lone surrogate or a noncharacter; and, since
  // a class here is a string, one that is not a class
  it("influenceEntryRefusesWhatJavaRefuses", () => {
    const refused: [string, () => InfluenceEntry][] = [
      ["a lone surrogate in src", () => influenceEntry("public", "web:\uD800", "h")],
      ["a noncharacter in h", () => influenceEntry("public", "s", "\uFFFE")],
      ["a noncharacter in owner", () => influenceEntry("private", "s", "h", "\uFDD0")],
      ["a lone surrogate in cid", () => influenceEntry("public", "s", "h", undefined, "\uDC00")],
      ["an unknown class", () => influenceEntry("secret" as InfluenceClass, "s", "h")],
      ["an empty owner", () => influenceEntry("private", "s", "h", "")],
      ["no src", () => influenceEntry("public", undefined as unknown as string, "h")],
      ["a number as h", () => influenceEntry("public", "s", 7 as unknown as string)],
    ];
    for (const [name, build] of refused) expect(build, name).toThrow(Error);
    // a member that is not a string is named as such, not as text it could not carry
    for (const [name, build] of [
      ["a null owner", () => influenceEntry("private", "s", "h", null as unknown as string)],
      ["a number as cid", () => influenceEntry("public", "s", "h", undefined, 7 as unknown as string)],
    ] as [string, () => InfluenceEntry][]) {
      expect(build, name).toThrow("an influence entry's owner and cid, when given, are strings");
    }
    // a surrogate pair is well-formed text
    expect(influenceEntry("public", "web:\uD83D\uDE00", "h").src).toBe("web:\u{1F600}");
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
