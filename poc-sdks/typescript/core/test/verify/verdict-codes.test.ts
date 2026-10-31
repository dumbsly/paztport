// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { sanitiseVerdictReason } from "../../src/verify/verdict-codes.ts";

describe("sanitiseVerdictReason", () => {
  it("keepsEveryCodeALiveVerifierGives", () => {
    for (const code of [
      "CHAIN_MISSING", "BAD_ORIGIN", "BAD_SIGNATURE", "BROKEN_LINK", "EXPIRED", "RID_MISMATCH", "BINDING_MISMATCH", "REPLAY", "PATH_NOT_ALLOWED",
      "SESSION_UNKNOWN", "CLIENT_PATH_NOT_ALLOWED", "INFLUENCE_MISMATCH", "INFLUENCE_DENIED", "UNSAFE_SESSION", "SCOPE_DENIED", "UNCHECKABLE",
      "PEER_MISMATCH", "POLICY_EXPIRED",
    ]) {
      expect(sanitiseVerdictReason(code)).toBe(code);
    }
  });
  it("makesAnythingElseUnknown", () => {
    for (const reason of ["OK", "<b>trust me</b>", "", "toString", "__proto__", 5, null, undefined, {}, ["BAD_ORIGIN"]]) {
      expect(sanitiseVerdictReason(reason)).toBe("UNKNOWN");
    }
  });
  it("refusesTheOfflineOnlyCodes", () => {
    for (const reason of ["TIME_MISMATCH", "PROMPT_MISMATCH", "OUTSIDE_SESSION", "PROOF_MISMATCH", "RULES_MISMATCH", "VERDICT_MISMATCH"]) {
      expect(sanitiseVerdictReason(reason)).toBe("UNKNOWN");
    }
  });
});
