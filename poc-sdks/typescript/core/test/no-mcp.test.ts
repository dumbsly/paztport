// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const src = new URL("../src/", import.meta.url);
const files = readdirSync(src, { recursive: true, encoding: "utf8" }).filter((f) => f.endsWith(".ts"));

describe("core carries no MCP knowledge", () => {
  it("hasNoMetaModuleOrMetaKeys", () => {
    // Pinned: a move that drops files out of the walk must fail here, not shrink the check.
    expect(files.length).toBe(37);
    for (const f of files) {
      const text = readFileSync(new URL(f, src), "utf8");
      expect(text, f).not.toMatch(/meta\.ts/);
      // The slash form only: domain prefixes such as `paztport-session-reply` are not _meta keys.
      expect(text, f).not.toContain("paztport/");
    }
  });
});
