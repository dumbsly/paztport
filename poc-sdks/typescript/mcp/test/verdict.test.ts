// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { MalformedJson, writeToken } from "@paztport/core";
import { readVerdict } from "../src/index.ts";
import { tokenOf } from "./helpers/client.ts";

describe("readVerdict", () => {
  it("readsAReasonAndAnAuditNote", () => {
    expect(readVerdict(writeToken({ reason: "INFLUENCE_DENIED" }))).toEqual({ reason: "INFLUENCE_DENIED" });
    expect(readVerdict(writeToken({ reason: "INFLUENCE_DENIED", audit: true }))).toEqual({ reason: "INFLUENCE_DENIED", audit: true });
    // the reason is server data: any string reads, and a client shows only a code it knows
    expect(readVerdict(writeToken({ reason: "<b>trust me</b>" }))).toEqual({ reason: "<b>trust me</b>" });
  });

  it("refusesAnythingButExactlyAReasonAndATrueAudit", () => {
    const refusals: [unknown, string][] = [
      [null, "not an object"],
      [["INFLUENCE_DENIED"], "not an object"],
      [{}, "no member reason"],
      [{ audit: true }, "no member reason"],
      [{ reason: "INFLUENCE_DENIED", extra: 1 }, "a member the object does not define"],
      [{ reason: 5 }, "member reason is not a string"],
      [{ reason: null }, "member reason is not a string"],
      [{ reason: "INFLUENCE_DENIED", audit: false }, "member audit is not true"],
      [{ reason: "INFLUENCE_DENIED", audit: "true" }, "member audit is not true"],
    ];
    for (const [value, message] of refusals) {
      expect(() => readVerdict(tokenOf(value)), JSON.stringify(value)).toThrow(new Error(message));
    }
  });

  it("bytesThatDoNotReadAreMalformedJson", () => {
    for (const token of ["", "not a token", tokenOf({ reason: "X", n: 1.5 }), tokenOf({ reason: "X" }).slice(1)]) {
      expect(() => readVerdict(token), token).toThrow(MalformedJson);
    }
  });
});
