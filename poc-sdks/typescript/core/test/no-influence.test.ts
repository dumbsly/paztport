// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const src = new URL("../src/", import.meta.url);
const files = readdirSync(src, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".ts"));

/** The files that may use the extension: its own, the local steps of the MCP profile, and the package's exports. */
const allowed = (f: string): boolean =>
  f.startsWith("influence/") || f.startsWith("local/") || f === "offline/local-step.ts" || f === "index.ts";

/** The paths of the file's imports that name the influence folder. */
const influenceImports = (f: string): string[] => {
  const text = readFileSync(new URL(f, src), "utf8");
  const paths = [...text.matchAll(/\bfrom\s+"([^"]*)"|\bimport\s*\(\s*"([^"]*)"/g)].map((m) => m[1] ?? m[2]!);
  return paths.filter((p) => p.includes("influence/"));
};

describe("the core carries influence without reading it", () => {
  it("noOtherFileImportsFromTheInfluenceFolder", () => {
    // The walk must see the folder, and the pattern must find an import it allows, or the check proves nothing.
    expect(files.filter((f) => f.startsWith("influence/")).length).toBeGreaterThan(0);
    expect(influenceImports("offline/local-step.ts")).toContain("../influence/influence.ts");
    for (const f of files.filter((name) => !allowed(name))) {
      expect(influenceImports(f), f).toEqual([]);
    }
  });
});
