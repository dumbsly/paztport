// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { ContentLabel } from "../../src/influence/label.ts";
import { readResponseLabels, responseEntries, responseLabels } from "../../src/influence/response.ts";

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

describe("responseLabels", () => {
  const stamps = [{ svc: "mcp-entry", items: [third] }, { svc: "tools", items: [mine] }];
  it("aResponseThatVerifiedGivesItsLabels", () => {
    expect(responseLabels("OK", stamps)).toEqual([third, mine]);
  });
  it("theStampsOfAResponseThatDidNotVerifyAreNotRead", () => {
    for (const reason of ["EXTENSION_REQUIRED", "BAD_SIGNATURE", "EXTENSION_MISMATCH"] as const) {
      expect(responseLabels(reason, stamps), reason).toBeNull();
    }
  });
  it("noHandOverIsNoLabel", () => {
    expect(responseLabels("OK", undefined)).toBeNull();
  });
});

describe("responseEntries", () => {
  const stamps = [{ svc: "mcp-entry", items: [] }, { svc: "tools", items: [third, mine] }];
  const untrusted = [{ cls: "local-untrusted", src: "server:github", h: "rh" }];
  it("oneEntryPerLabelWithTheCallersSourceAndTheResultHash", () => {
    expect(responseEntries("OK", stamps, "server:github", "rh")).toEqual([
      { cls: "third-party", src: "server:github", h: "rh", cid: "c1" },
      { cls: "private", src: "server:github", h: "rh", cid: "c2", owner: "alice" },
    ]);
  });
  it("noLabelsAtAllIsNoEntry", () => {
    expect(responseEntries("OK", [{ svc: "mcp-entry", items: [] }], "server:github", "rh")).toEqual([]);
  });
  it("anyOtherResponseIsExactlyOneUntrustedEntry", () => {
    expect(responseEntries("BAD_SIGNATURE", stamps, "server:github", "rh")).toEqual(untrusted);
    expect(responseEntries("OK", [{ svc: "mcp-entry", items: null }], "server:github", "rh")).toEqual(untrusted);
    expect(responseEntries("OK", [{ svc: "tools", items: [third, { cls: "public" }] }], "server:github", "rh"))
      .toEqual(untrusted);
    expect(responseEntries("OK", undefined, "http:orders", "rh"))
      .toEqual([{ cls: "local-untrusted", src: "http:orders", h: "rh" }]);
  });
});
