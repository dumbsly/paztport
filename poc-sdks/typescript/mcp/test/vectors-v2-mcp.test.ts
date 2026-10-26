// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned bytes for cross-implementation conformance: the MCP tools/call binding. Change only with a
// protocol change.

import { describe, expect, it } from "vitest";
import { bindMcpCall } from "../src/index.ts";

describe("v2 MCP known-answer vectors", () => {
  it("bindMcpCall", () => {
    const args = { title: "t", body: "b", draft: false, n: [1, 2.5] };
    expect(bindMcpCall("create_pull_request", "call-1", args)).toBe("1dK9R69lTXmP45Z9HIVEmO9EtY_bRq68vJvEO_tdZv8");
  });
});
