// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { InfluenceClass } from "../../src/influence/influence.ts";
import { publicWriteRefused, type InfluenceFact } from "../../src/influence/influence-rule.ts";
import { decideLocal } from "../../src/influence/local-decision.ts";
import { parseLocalRules } from "../../src/policy/local-rules.ts";

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
    expect(publicWriteRefused(classes.map((cls) => ({ cls })))).toBe(refused);
  });

  it.each(TABLE)("decideLocal on a public write agrees for %j", (classes, refused) => {
    const resolved = { paths: [{ need: "write" as const, at: "website/a.md" }], programs: [], parse: "ok" as const, readOnly: false };
    expect(decideLocal({ routeAllowed: true, resolved, rules, classes: new Set(classes) })).toBe(refused ? "INFLUENCE_DENIED" : "OK");
  });

  it("without owners the rule is the class rule", () => {
    for (const [classes] of TABLE) {
      const set = new Set(classes);
      expect(publicWriteRefused(classes.map((cls) => ({ cls })))).toBe(set.has("private") && (set.has("third-party") || set.has("local-untrusted")));
    }
  });

  const TP = { cls: "third-party" } as const;
  const LU = { cls: "local-untrusted" } as const;
  const PUB = { cls: "public" } as const;
  const P = (owner?: string): InfluenceFact => (owner === undefined ? { cls: "private" } : { cls: "private", owner });
  const OWNED: [string, InfluenceFact[], string | undefined, boolean][] = [
    ["own private data, untrusted content", [TP, P("alice")], "alice", false],
    ["someone else's private data", [TP, P("bob")], "alice", true],
    ["private data with no owner", [TP, P()], "alice", true],
    ["unknown destination owner", [TP, P("alice")], undefined, true],
    ["local-untrusted counts as untrusted", [LU, P("bob")], "alice", true],
    ["no untrusted content", [P("bob")], "alice", false],
    ["no private data", [TP], "alice", false],
    ["one foreign entry is enough", [TP, P("alice"), P("bob")], "alice", true],
    ["public is not private", [TP, PUB], "alice", false],
    ["an empty owner is unknown on both sides", [TP, P("")], "", true],
    ["nothing at all", [], "alice", false],
    ["an empty private owner is unknown", [TP, P("")], "alice", true],
    ["an empty destination owner is unknown", [TP, P("alice")], "", true],
  ];
  it.each(OWNED)("%s", (_name, influence, destinationOwner, refused) => {
    expect(publicWriteRefused(influence, destinationOwner)).toBe(refused);
  });
});
