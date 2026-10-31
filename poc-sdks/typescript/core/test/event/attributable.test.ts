// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { isAttributable } from "../../src/event/attributable.ts";
import type { ResponderEvent } from "../../src/event/verifier.ts";

const event = (over: Partial<ResponderEvent> = {}): ResponderEvent => ({
  reason: "PATH_NOT_ALLOWED",
  suspectSvc: "search",
  suspectInst: "search-1",
  rid: "r",
  audit: false,
  ts: 1,
  eventId: "e",
  ...over,
});

const ALLOWED = [
  "CHAIN_MISSING", "BAD_ORIGIN", "BAD_SIGNATURE", "BROKEN_LINK", "EXPIRED", "RID_MISMATCH", "BINDING_MISMATCH",
  "REPLAY", "PATH_NOT_ALLOWED", "SESSION_UNKNOWN", "CLIENT_PATH_NOT_ALLOWED", "INFLUENCE_MISMATCH", "PEER_MISMATCH",
];
const EXCLUDED = [
  "OK", "INFLUENCE_DENIED", "UNSAFE_SESSION", "POLICY_EXPIRED", "SCOPE_DENIED", "UNCHECKABLE", "TIME_MISMATCH",
  "OUTSIDE_SESSION", "NOT_A_CODE", "",
];

describe("isAttributable", () => {
  it.each(ALLOWED)("%s is attributable", (reason) => {
    expect(isAttributable(event({ reason }))).toBe(true);
  });

  it.each(EXCLUDED)("%j is not attributable", (reason) => {
    expect(isAttributable(event({ reason }))).toBe(false);
  });

  it("an audit event is not attributable", () => {
    expect(isAttributable(event({ audit: true }))).toBe(false);
  });

  it("an event naming no service or no instance is not attributable", () => {
    expect(isAttributable(event({ suspectSvc: "" }))).toBe(false);
    expect(isAttributable(event({ suspectInst: "" }))).toBe(false);
  });

  it("the reason is matched exactly", () => {
    expect(isAttributable(event({ reason: "path_not_allowed" }))).toBe(false);
    expect(isAttributable(event({ reason: "PATH_NOT_ALLOWED " }))).toBe(false);
  });
});
