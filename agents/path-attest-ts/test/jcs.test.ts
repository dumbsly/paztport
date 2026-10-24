// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/jcs.ts";

describe("jcs", () => {
  it("sortsKeysByUtf16", () => {
    expect(canonicalize({ "€": 1, "\r": 2, "1": 3, "ö": 4, "😀": 5 })).toBe(
      '{"\\r":2,"1":3,"ö":4,"€":1,"😀":5}',
    );
  });

  it("numbers", () => {
    expect(canonicalize([0, -0, 1e21, 1e-7, 333333333.33333329, 4.5, 2e-3])).toBe(
      "[0,0,1e+21,1e-7,333333333.3333333,4.5,0.002]",
    );
  });

  it("nested", () => {
    expect(canonicalize({ b: [{ z: 1, a: null }], a: "x" })).toBe('{"a":"x","b":[{"a":null,"z":1}]}');
  });

  it("stringEscapes", () => {
    const s = "\u0000\u001f\"\\/é";
    expect(canonicalize(s)).toBe(JSON.stringify(s));
  });

  it("rejectsNonJson", () => {
    for (const v of [undefined, () => 1, NaN, Infinity, 10n, { a: undefined }]) {
      expect(() => canonicalize(v)).toThrow();
    }
  });

  it("rejectsNonPlainObjects", () => {
    for (const v of [new Date(0), new Map(), new String("a"), new Uint8Array(1)]) {
      expect(() => canonicalize(v)).toThrow();
    }
  });

  it("rejectsSparseArray", () => {
    // eslint-disable-next-line no-sparse-arrays
    expect(() => canonicalize([, 1])).toThrow();
  });

  it("rejectsLoneSurrogateValueAndKey", () => {
    expect(() => canonicalize("\ud800")).toThrow();
    expect(() => canonicalize({ "\ud800": 1 })).toThrow();
  });
});
