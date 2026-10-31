// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindPrompt } from "@paztport/core";
import { bindMcpCall } from "../src/index.ts";

describe("bindMcpCall", () => {
  it("bindMcpCallRejectsNewlines", () => {
    expect(() => bindMcpCall("a\nb", "c", {})).toThrow();
    expect(() => bindMcpCall("a", "b\nc", {})).toThrow();
  });
  it("bindMcpCallRefusesALoneSurrogate", () => {
    expect(() => bindMcpCall("t\ud800", "c1", {})).toThrow(TypeError);
    expect(() => bindMcpCall("t", "c\ud800", {})).toThrow(TypeError);
    expect(() => bindMcpCall("t", "c1", { a: "\ud800" })).toThrow();
  });
  it("bindPromptNotEqualBindMcpCall", () => {
    expect(bindPrompt("tools/call\nt\nc1\n{}")).not.toBe(bindMcpCall("t", "c1", {}));
  });
});
