// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { bindResponse } from "../../src/session/attestation.ts";
import { bindLocalTool, bindPrompt } from "../../src/stamp/binding.ts";

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

  it("bindPromptRefusesALoneSurrogate", () => {
    expect(() => bindPrompt("a\ud800b")).toThrow(TypeError);
    expect(() => bindPrompt("a\udc00")).toThrow(TypeError);
    expect(bindPrompt("a\ud83d\ude00")).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("bindLocalToolRefusesALoneSurrogateInTheName", () => {
    expect(() => bindLocalTool("re\ud800ad", {}, {})).toThrow(TypeError);
  });

  it("bindResponseRefusesALoneSurrogateInTheCallId", () => {
    expect(() => bindResponse("h", "call\ud800", [])).toThrow(TypeError);
  });

  it("matchesThePinnedVector", () => {
    const expected = createHash("sha256")
      .update('tool\nread\n{"input":{"path":"a"},"resolved":{"paths":[]}}', "utf8")
      .digest("base64url");
    expect(bindLocalTool("read", { path: "a" }, { paths: [] })).toBe(expected);
  });
});
