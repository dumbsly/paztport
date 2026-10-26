// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const src = new URL("../src/", import.meta.url);
const files = readdirSync(src).filter((f) => f.endsWith(".ts"));

describe("core carries no MCP knowledge", () => {
  it("hasNoMetaModuleOrMetaKeys", () => {
    expect(files.length).toBeGreaterThan(0);
    for (const f of files) {
      const text = readFileSync(new URL(f, src), "utf8");
      expect(text, f).not.toMatch(/meta\.ts/);
      // The slash form only: domain prefixes such as `paztport-session-reply` are not _meta keys.
      expect(text, f).not.toContain("paztport/");
    }
  });
});
