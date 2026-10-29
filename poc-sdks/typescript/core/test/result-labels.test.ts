// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { resultLabels, type Resolved } from "../src/influence/local-decision.ts";
import { parseLocalRules } from "../src/policy/local-rules.ts";

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
  it("aReadCarriesItsFoldersLabels", () => {
    expect(resultLabels("read", reads, rules)).toEqual(["public", "private"]);
  });
  it("anExecAddsLocalUntrusted", () => {
    expect(resultLabels("exec", reads, rules)).toEqual(["public", "private", "local-untrusted"]);
    // read-only resolution doesn't change that: a program's output is not fully known
    expect(resultLabels("exec", { ...reads, readOnly: true }, rules)).toEqual(["public", "private", "local-untrusted"]);
  });
  it("aWriteCarriesNothing", () => {
    expect(resultLabels("write", reads, rules)).toEqual([]);
  });
  it("anyOtherToolIsLocalUntrusted", () => {
    expect(resultLabels("other", reads, rules)).toEqual(["local-untrusted"]);
  });
});
