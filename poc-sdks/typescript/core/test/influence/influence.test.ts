// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { encode } from "../../src/encoding/b64url.ts";
import { utf8 } from "../../src/crypto/crypto.ts";
import { writeToken } from "../../src/encoding/jcs.ts";
import { MalformedJson } from "../../src/encoding/json-rules.ts";
import {
  commitInfluence, influenceClasses, normalizeInfluence, readInfluence, type InfluenceEntry,
} from "../../src/influence/influence.ts";

/** A token holding exactly `text`'s bytes. */
const raw = (text: string): string => encode(utf8(text));

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
  it("normalizeInfluence sorts owner after cid, absent first", () => {
    const x = { cls: "private", src: "s", h: "h", cid: "c" } as const;
    const y = { ...x, owner: "bob" };
    const z = { ...x, owner: "alice" };
    expect(normalizeInfluence([y, x, z])).toEqual([x, z, y]);
  });
  it("an entry with an owner commits differently; entries without one commit as before", () => {
    const e = [{ cls: "private", src: "s", h: "h" }] as InfluenceEntry[];
    expect(commitInfluence(e)).not.toBe(commitInfluence([{ ...e[0]!, owner: "alice" }]));
  });
  it("readInfluence keeps a string owner and refuses an empty or non-string one, naming it", () => {
    expect(readInfluence(writeToken([{ cls: "private", src: "s", h: "h", owner: "alice" }]))[0]!.owner).toBe("alice");
    for (const owner of ["", 7]) {
      const token = writeToken([{ cls: "private", src: "s", h: "h", owner }]);
      expect(() => readInfluence(token), String(owner)).toThrow("owner");
    }
  });
  it("readInfluence refuses what is not a list of entries", () => {
    const bad = [
      {}, "x", [1], [[]], [{ cls: "nope", src: "s", h: "x" }], [{ src: "s", h: "x" }],
      [{ cls: "public", src: 1, h: "x" }],
      [{ cls: "public", src: "s", h: 2 }], [{ cls: "public", src: "s", h: "x", cid: 3 }],
      [{ cls: "public", src: "s", h: "x", cid: null }],
    ];
    for (const value of bad) {
      expect(() => readInfluence(writeToken(value)), JSON.stringify(value)).toThrow(Error);
    }
    const good = [{ cid: "c", cls: "private", h: "x", owner: "o", src: "s" }];
    expect(readInfluence(writeToken(good))).toEqual(good);
  });
  it("readInfluence refuses bytes that do not read, a lone surrogate or a noncharacter among them", () => {
    const tokens = [
      raw('[{"cls":"public","h":"x","src":"\\ud800"}]'), raw('[{"cls":"public","h":"x","src":"\uFDD0"}]'),
      "not*base64url", "",
    ];
    for (const token of tokens) {
      expect(() => readInfluence(token), token).toThrow(MalformedJson);
    }
  });
  it("anEntryWithAnExtraMemberIsRefused", () => {
    const token = writeToken([{ cls: "public", extra: 1, h: "x", src: "s" }]);
    expect(() => readInfluence(token)).toThrow("a member the object does not define");
  });
  it("aListInWireMemberOrderIsRefused", () => {
    expect(() => readInfluence(raw('[{"cls":"public","src":"s","h":"x"}]'))).toThrow(MalformedJson);
    expect(() => readInfluence(raw('[ {"cls":"public","h":"x","src":"s"}]'))).toThrow(MalformedJson);
    expect(readInfluence(raw('[{"cls":"public","h":"x","src":"s"}]'))).toEqual([{ cls: "public", src: "s", h: "x" }]);
  });
});
