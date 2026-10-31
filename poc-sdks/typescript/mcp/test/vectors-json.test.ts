// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The tools/call binding's cases of spec/vectors/json.json, whose file core's tests also replay. They are replayed
// here because @paztport/core does not import this package. The file's own structure is read with the platform's
// parser, as its about says.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { bindMcpCall } from "../src/index.ts";

type BindingCase = { name: string; binding: string; inputs: { tool: string; toolCallId: string; arguments: unknown }; expected: null };

const v = JSON.parse(readFileSync(new URL("../../../spec/vectors/json.json", import.meta.url), "utf8"));
const cases = (v.bindings as BindingCase[]).filter((c) => c.binding === "toolsCall");

describe("json.json bindings", () => {
  it("theFileHoldsToolsCallCases", () => {
    expect(cases.length).toBeGreaterThan(0);
  });

  it.each(cases)("$name", (c) => {
    expect(c.expected).toBeNull();
    expect(() => bindMcpCall(c.inputs.tool, c.inputs.toolCallId, c.inputs.arguments)).toThrow();
  });
});
