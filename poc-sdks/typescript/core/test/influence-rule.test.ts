// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { InfluenceClass } from "../src/influence.ts";
import { publicWriteRefused } from "../src/influence-rule.ts";
import { decideLocal } from "../src/local-decision.ts";
import { parseLocalRules } from "../src/local-rules.ts";

const ALL: InfluenceClass[] = ["third-party", "private", "public", "local-untrusted"];

/** Every subset of the four classes with whether a public write is refused, written out row by row. */
const TABLE: [InfluenceClass[], boolean][] = [
  [[], false],
  [["third-party"], false],
  [["private"], false],
  [["public"], false],
  [["local-untrusted"], false],
  [["third-party", "private"], true],
  [["third-party", "public"], false],
  [["third-party", "local-untrusted"], false],
  [["private", "public"], false],
  [["private", "local-untrusted"], true],
  [["public", "local-untrusted"], false],
  [["third-party", "private", "public"], true],
  [["third-party", "private", "local-untrusted"], true],
  [["third-party", "public", "local-untrusted"], false],
  [["private", "public", "local-untrusted"], true],
  [["third-party", "private", "public", "local-untrusted"], true],
];

const rules = parseLocalRules({
  v: 1,
  folders: [
    { path: ".", access: ["read"] },
    { path: "website", access: ["read", "write"], label: "public", destination: "public" },
  ],
  programs: [],
});

describe("publicWriteRefused", () => {
  it("coversEverySubsetOnce", () => {
    expect(TABLE).toHaveLength(2 ** ALL.length);
    expect(new Set(TABLE.map(([c]) => [...c].sort().join(","))).size).toBe(TABLE.length);
  });

  it.each(TABLE)("%j refused: %s", (classes, refused) => {
    expect(publicWriteRefused(new Set(classes))).toBe(refused);
  });

  it.each(TABLE)("decideLocal on a public write agrees for %j", (classes, refused) => {
    const resolved = { paths: [{ need: "write" as const, at: "website/a.md" }], programs: [], parse: "ok" as const, readOnly: false };
    expect(decideLocal({ routeAllowed: true, resolved, rules, classes: new Set(classes) })).toBe(refused ? "INFLUENCE_DENIED" : "OK");
  });
});
