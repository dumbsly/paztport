// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { BUILTIN_LOCAL_TOOLS, toolKind } from "../src/local/tools.ts";

describe("toolKind", () => {
  it("mapsEveryBuiltinAndCallsTheRestOther", () => {
    expect(Object.fromEntries(BUILTIN_LOCAL_TOOLS.map((t) => [t, toolKind(t)]))).toEqual({
      read: "read",
      write: "write",
      edit: "write",
      bash: "exec",
      grep: "read",
      find: "read",
      ls: "read",
      powershell: "exec",
    });
    expect(toolKind("some_extension_tool")).toBe("other");
    expect(toolKind("toString")).toBe("other");
  });
});
