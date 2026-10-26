// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { bindLocalTool } from "../src/binding.ts";

describe("bindLocalTool", () => {
  it("isStableForTheSameInput", () => {
    expect(bindLocalTool("read", { path: "a" }, { paths: [] })).toBe(bindLocalTool("read", { path: "a" }, { paths: [] }));
  });

  it("changesWhenResolvedChanges", () => {
    expect(bindLocalTool("read", { path: "a" }, { paths: [] })).not.toBe(bindLocalTool("read", { path: "a" }, { paths: ["/x"] }));
  });

  it("rejectsNewlineInToolName", () => {
    expect(() => bindLocalTool("re\nad", {}, {})).toThrow();
  });

  it("matchesThePinnedVector", () => {
    const expected = createHash("sha256")
      .update('tool\nread\n{"input":{"path":"a"},"resolved":{"paths":[]}}', "utf8")
      .digest("base64url");
    expect(bindLocalTool("read", { path: "a" }, { paths: [] })).toBe(expected);
  });
});
