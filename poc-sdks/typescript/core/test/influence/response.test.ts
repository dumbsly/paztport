// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { ContentLabel } from "../../src/influence/label.ts";
import { readResponseLabels } from "../../src/influence/response.ts";

const third: ContentLabel = { cls: "third-party", cid: "c1" };
const mine: ContentLabel = { cls: "private", cid: "c2", owner: "alice" };

describe("readResponseLabels", () => {
  it("everyBlockNamesItAndEachItemIsALabel", () => {
    expect(readResponseLabels([{ svc: "mcp-entry", items: [third] }, { svc: "tools", items: [mine] }])).toEqual([
      third, mine,
    ]);
  });

  it("aBlockThatDoesNotNameItIsASilentResponse", () => {
    expect(readResponseLabels([{ svc: "mcp-entry", items: null }, { svc: "tools", items: [third] }])).toBeNull();
  });

  it("anItemThatIsNotALabelTakesNoLabel", () => {
    const entry = { cls: "third-party", h: "x", src: "s" };
    expect(readResponseLabels([{ svc: "mcp-entry", items: [] }, { svc: "tools", items: [third, entry] }])).toBeNull();
    // null and an array are not labels either
    for (const item of [null, [[]]]) {
      const stamps = [{ svc: "mcp-entry", items: [] }, { svc: "tools", items: [third, item] }];
      expect(readResponseLabels(stamps), JSON.stringify(item)).toBeNull();
    }
  });

  it("everyBlockNamingItWithNothingIsNoLabels", () => {
    expect(readResponseLabels([{ svc: "mcp-entry", items: [] }, { svc: "tools", items: [] }])).toEqual([]);
  });
});
