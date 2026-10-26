// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { redactPaths } from "../src/redact.ts";

describe("redactPaths", () => {
  const rules = [
    { path: "/Users/ann", placeholder: "<home>" },
    { path: "/Users/ann/dev/paztport/agents", placeholder: "<agents>" },
    { path: "/Users/ann/dev/paztport/agents/.demo/results/r/runs/on-001", placeholder: "<run-dir>" },
    { path: "/Users/ann/dev/paztport/agents/.demo/results/r/runs/on-001/workspace", placeholder: "<workspace>" },
  ];
  it("replaces the longest path first", () => {
    const text = '{"cwd":"/Users/ann/dev/paztport/agents/.demo/results/r/runs/on-001/workspace","f":"/Users/ann/dev/paztport/agents/.demo/results/r/runs/on-001/run.json","g":"/Users/ann/dev/paztport/agents/eval","h":"/Users/ann/.pi"}';
    expect(redactPaths(text, rules)).toBe('{"cwd":"<workspace>","f":"<run-dir>/run.json","g":"<agents>/eval","h":"<home>/.pi"}');
  });
  it("does not cut into a longer name", () => {
    expect(redactPaths("/Users/anna/x and /Users/ann-2 and /Users/ann", rules)).toBe("/Users/anna/x and /Users/ann-2 and <home>");
  });
  it("ignores empty and root paths", () => {
    expect(redactPaths("/a/b", [{ path: "/", placeholder: "<root>" }, { path: "", placeholder: "<e>" }])).toBe("/a/b");
  });
  it("also replaces the JSON-escaped form of a path", () => {
    expect(redactPaths('"C:\\\\Users\\\\ann\\\\x"', [{ path: "C:\\Users\\ann", placeholder: "<home>" }])).toBe('"<home>\\\\x"');
  });
});
