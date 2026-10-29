// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import { decode, encode } from "../../src/encoding/b64url.ts";
import { utf8 } from "../../src/crypto/crypto.ts";

describe("b64url", () => {
  it("roundTripsArbitraryBytes", () => {
    for (let n = 0; n <= 64; n++) {
      const bytes = new Uint8Array(randomBytes(n));
      const text = encode(bytes);
      expect(text).not.toMatch(/[=+/]/);
      expect(decode(text)).toEqual(bytes);
    }
  });
  it("knownValue", () => {
    expect(encode(utf8("hi?>"))).toBe("aGk_Pg");
  });
  it("rejectsInvalidCharacters", () => {
    for (const bad of ["ab+c", "ab/c", "a b", "a"]) {
      expect(() => decode(bad)).toThrow();
    }
  });
  it("acceptsTrailingPadding", () => {
    expect(decode("aGk_Pg==")).toEqual(decode("aGk_Pg"));
  });
});
