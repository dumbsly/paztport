// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { labelToEntry } from "../../src/influence/label-entry.ts";

describe("labelToEntry", () => {
  it("makesTheEntryTheSpecNames", () => {
    expect(labelToEntry({ cls: "third-party", cid: "c1" }, "server:github", "h1")).toEqual({ cls: "third-party", src: "server:github", h: "h1", cid: "c1" });
  });
  it("carriesTheOwnerOnlyWhenTheLabelHasOne", () => {
    const owned = labelToEntry({ cls: "private", cid: "c2", owner: "alice" }, "http:orders", "h2");
    expect(owned).toEqual({ cls: "private", src: "http:orders", h: "h2", cid: "c2", owner: "alice" });
    expect(Object.keys(labelToEntry({ cls: "private", cid: "c2" }, "http:orders", "h2"))).toEqual(["cls", "src", "h", "cid"]);
  });
});
