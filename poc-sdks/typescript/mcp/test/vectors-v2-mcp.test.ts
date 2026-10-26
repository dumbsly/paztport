// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned bytes for cross-implementation conformance: the MCP tools/call binding. Change only with a
// protocol change.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { bindMcpCall } from "../src/index.ts";

const v = JSON.parse(readFileSync(new URL("../../../spec/vectors/v2.json", import.meta.url), "utf8"));

describe("v2 MCP known-answer vectors", () => {
  it("bindMcpCall", () => {
    const c = v.bindMcpCall;
    expect(bindMcpCall(c.tool, c.callId, c.args)).toBe(c.expected);
  });
});
