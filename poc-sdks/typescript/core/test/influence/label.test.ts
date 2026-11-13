// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import type { JsonValue } from "../../src/encoding/json.ts";
import { labelOf, newContentId } from "../../src/influence/label.ts";

describe("labelOf", () => {
  it("readsALabelWithAndWithoutAnOwner", () => {
    expect(labelOf({ cid: "c", cls: "third-party" })).toEqual({ cls: "third-party", cid: "c" });
    expect(labelOf({ cid: "c", cls: "private", owner: "alice" })).toEqual({ cls: "private", cid: "c", owner: "alice" });
  });

  it.each([
    ["a string", "x"],
    ["an entry", { cls: "public", h: "x", src: "s" }],
    ["another member", { cid: "c", cls: "public", extra: 1 }],
    ["an unknown cls", { cid: "c", cls: "nope" }],
    ["a number as cid", { cid: 3, cls: "public" }],
    ["an empty owner", { cid: "c", cls: "private", owner: "" }],
  ])("refuses %s", (_name, item) => {
    expect(() => labelOf(item as JsonValue)).toThrow(Error);
  });
});

describe("newContentId", () => {
  it("isSixteenRandomBytesInBase64url", () => {
    const cid = newContentId();
    expect(cid).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(newContentId()).not.toBe(cid);
  });
});
