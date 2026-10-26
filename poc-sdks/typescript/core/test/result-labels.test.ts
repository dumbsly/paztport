// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { resultLabels, type Resolved } from "../src/local-decision.ts";
import { parseLocalRules } from "../src/local-rules.ts";

const rules = parseLocalRules({
  v: 1,
  folders: [
    { path: ".", access: ["read"] },
    { path: "website", access: ["read", "write"], label: "public", destination: "public" },
    { path: "priv", access: ["read"], label: "private" },
  ],
  programs: ["cat"],
});

const reads: Resolved = {
  paths: [
    { need: "read", at: "website/README.md" },
    { need: "read", at: "priv/x" },
  ],
  programs: [],
  parse: "ok",
  readOnly: true,
};

describe("resultLabels", () => {
  it("readToolsCarryTheirFoldersLabels", () => {
    for (const tool of ["read", "grep", "find", "ls"]) {
      expect(resultLabels(tool, reads, rules)).toEqual(["public", "private"]);
    }
  });
  it("bashAddsLocalUntrusted", () => {
    expect(resultLabels("bash", reads, rules)).toEqual(["public", "private", "local-untrusted"]);
  });
  it("writeAndEditCarryNothing", () => {
    expect(resultLabels("write", reads, rules)).toEqual([]);
    expect(resultLabels("edit", reads, rules)).toEqual([]);
  });
  it("anyOtherToolIsLocalUntrusted", () => {
    expect(resultLabels("some_extension_tool", reads, rules)).toEqual(["local-untrusted"]);
  });
});
