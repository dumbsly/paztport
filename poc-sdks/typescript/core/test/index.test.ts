// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import * as core from "../src/index.ts";

describe("core exports", () => {
  it("the v2 live verifier is gone", () => {
    expect("verifyChainV2" in core).toBe(false);
    expect("parseStampsV2" in core).toBe(false);
  });
  it("the v3 verifiers and the response checks are exported", () => {
    for (const name of ["verifyChainV3", "verifyChainAcceptingLegacy", "verifyResponse", "recheckResponse", "signStampV2", "signingBytesV2"]) {
      expect(name in core, name).toBe(true);
    }
  });
});
