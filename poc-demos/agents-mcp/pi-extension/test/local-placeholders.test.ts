// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decodePlaceholders, encodePlaceholders, type Places } from "../src/local/placeholders.ts";

const ws = "/Users/ann/proj";
const home = "/Users/ann";
const places: Places = { workspace: [ws, "/private/var/ws"], home: [home] };
const enc = (v: unknown) => encodePlaceholders(v, places);
const dec = (v: unknown) => decodePlaceholders(v, { workspace: ws, home });

describe("encodePlaceholders", () => {
  it("namesWholePathsOnly", () => {
    expect(enc(`${ws}/a`)).toBe("<workspace>/a");
    expect(enc(ws)).toBe("<workspace>");
    expect(enc(`${home}/other/x`)).toBe("<home>/other/x");
    // a folder whose name only starts with the workspace's is a different folder
    expect(enc(`${ws}x/y`)).toBe("<home>/projx/y");
    expect(enc(`${ws}.bak/y`)).toBe("<home>/proj.bak/y");
    // a path that only contains the workspace path partway through is left alone
    expect(enc(`/Volumes/bk${ws}/x`)).toBe(`/Volumes/bk${ws}/x`);
  });

  it("stopsAtSeparatorsAroundAPath", () => {
    expect(enc(`cat ${ws}/a ${home}/b`)).toBe("cat <workspace>/a <home>/b");
    expect(enc(`["${ws}"]`)).toBe('["<workspace>"]');
    expect(enc(`[${ws}]`)).toBe("[<workspace>]");
    expect(enc(`{${ws}}`)).toBe("{<workspace>}");
    expect(enc(`--dir=${ws}/a,x:${home}`)).toBe("--dir=<workspace>/a,x:<home>");
    expect(enc(`(${ws});`)).toBe("(<workspace>);");
  });

  it("namesEverySpellingGiven", () => {
    expect(enc("/private/var/ws/a")).toBe("<workspace>/a");
  });

  it("isReversibleWhenTheInputAlreadyHoldsAToken", () => {
    // a literal "<" is written "<<", so a single "<" only ever opens a placeholder
    expect(enc("<workspace>/x")).toBe("<<workspace>/x");
    expect(enc(`cat <${ws}/a`)).toBe("cat <<<workspace>/a");
    expect(enc("<home>")).toBe("<<home>");
    for (const s of ["<workspace>/x", `cat <${ws}/a`, "a << b", `<<${home}>>`, "<", "", "plain"]) {
      expect(dec(enc(s))).toBe(s);
    }
  });

  it("rewritesKeysAndNestedValues", () => {
    const v = { [`${ws}/k`]: [{ p: home }, 3, null, true], n: { "<x": `${ws}` } };
    const e = enc(v) as Record<string, unknown>;
    expect(e).toEqual({ "<workspace>/k": [{ p: "<home>" }, 3, null, true], n: { "<<x": "<workspace>" } });
    expect(dec(e)).toEqual(v);
  });

  it("usesAbsoluteSpellingsOnly", () => {
    expect(encodePlaceholders("/a/b", { workspace: ["/", "", "rel", "<<"], home: [] })).toBe("/a/b");
    expect(encodePlaceholders("a<<<", { workspace: ["<<"], home: [] })).toBe("a<<<<<<");
  });

  it("refusesKeysThatWouldMerge", () => {
    // two spellings of the workspace as keys would encode to one key and drop an entry from the record
    expect(() => enc({ [`${ws}`]: "A", "/private/var/ws": "B" })).toThrow(/same key/);
  });
});

describe("decodePlaceholders", () => {
  it("refusesAStrayOpener", () => {
    expect(() => dec("<other>")).toThrow(/placeholder/);
    expect(() => dec("a<")).toThrow(/placeholder/);
  });
});
