// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { decode, encode } from "../../src/encoding/b64url.ts";
import { keyFileText } from "../../src/encoding/key-file.ts";

const KEY = encode(new Uint8Array(32).fill(7));
const NOT_JSON_WHITESPACE = ["\u00a0", "\u000b", "\u000c", "\u0085", "\ufeff", "\u3000"];

describe("keyFileText", () => {
  it("removes exactly the space, tab, line feed and carriage return around the text", () => {
    expect(keyFileText(` \t\r\n${KEY}\n\r\t `)).toBe(KEY);
    expect(keyFileText("")).toBe("");
    expect(keyFileText(" \r\n")).toBe("");
  });

  it("keeps every other character, so a key surrounded by one does not decode", () => {
    for (const c of NOT_JSON_WHITESPACE) {
      expect(keyFileText(`${c}${KEY}${c}`), c.codePointAt(0)!.toString(16)).toBe(`${c}${KEY}${c}`);
      expect(() => decode(keyFileText(`${c}${KEY}`))).toThrow();
      expect(() => decode(keyFileText(`${KEY}${c}`))).toThrow();
    }
  });

  it("keeps whitespace inside the text", () => {
    expect(keyFileText(" a b\n")).toBe("a b");
  });
});
