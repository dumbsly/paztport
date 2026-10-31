// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import * as core from "../src/index.ts";

describe("core exports", () => {
  it("the v3 verifiers, the response check and the stamp signer are exported", () => {
    for (const name of ["verifyChainV3", "verifyResponse", "signStampV3", "signingBytesV3"]) {
      expect(name in core, name).toBe(true);
    }
  });
});
