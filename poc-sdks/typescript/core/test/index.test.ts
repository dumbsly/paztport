// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import * as core from "../src/index.ts";

describe("core exports", () => {
  it("the chain verifiers, the response check and the stamp signer are exported", () => {
    for (const name of ["verifyChain", "verifyResponse", "signStamp", "signingBytes"]) {
      expect(name in core, name).toBe(true);
    }
  });
});
