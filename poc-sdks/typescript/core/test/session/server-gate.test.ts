// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decideServerCall } from "../../src/session/server-gate.ts";

const DISABLED = ["create_branch", "create_or_update_file", "push_files", "create_pull_request", "add_issue_comment"];

describe("decideServerCall", () => {
  const gate = (tool: string, attested: boolean, disabledWhenUnsafe = DISABLED) =>
    decideServerCall({ tool, attested, disabledWhenUnsafe });
  it("anAttestedSessionIgnoresTheUnsafeGate", () => {
    expect(DISABLED).toContain("create_branch");
    expect(gate("create_branch", true)).toBe("OK");
  });
  it("theUnsafeGateRefusesListedTools", () => {
    expect(gate("create_branch", false)).toBe("UNSAFE_SESSION");
    expect(gate("list_issues", false)).toBe("OK");
  });
  it("aWriteLeftOutOfTheUnsafeListIsUngated", () => {
    const disabledWhenUnsafe = ["create_pull_request"];
    expect(gate("create_branch", false, disabledWhenUnsafe)).toBe("OK");
    expect(gate("create_pull_request", false, disabledWhenUnsafe)).toBe("UNSAFE_SESSION");
  });
});
