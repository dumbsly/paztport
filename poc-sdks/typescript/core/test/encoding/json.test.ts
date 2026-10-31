// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { utf8 } from "../../src/crypto/crypto.ts";
import { encode } from "../../src/encoding/b64url.ts";
import { writeToken } from "../../src/encoding/jcs.ts";
import { printFile } from "../../src/encoding/json-file.ts";
import { MalformedJson, readFile, readToken, readWireBytes, type JsonValue } from "../../src/encoding/json.ts";

/** The error `read` throws, which must be a MalformedJson. */
function refusal(read: () => unknown): MalformedJson {
  try {
    read();
  } catch (e) {
    expect(e).toBeInstanceOf(MalformedJson);
    return e as MalformedJson;
  }
  throw new Error("expected a refusal");
}

function nested(levels: number): JsonValue {
  let value: JsonValue = [];
  for (let i = 1; i < levels; i++) value = [value];
  return value;
}

describe("json", () => {
  it("readsWhatItWrites", () => {
    const value = {
      array: [null, true, false, 0, 9007199254740991, "", []],
      empty: {},
      nested: { b: { a: [{}] } },
      text: "é€😀\n\"\\\u001f\u007f ",
      "😀": "names sort by UTF-16 code units",
      "דּ": 1,
    };
    expect(readToken(writeToken(value))).toEqual(value);
  });

  it("aProtoNameIsAnOrdinaryMember", () => {
    const token = encode(utf8('{"__proto__":1,"constructor":2,"toString":3}'));
    const value = readToken(token) as Record<string, JsonValue>;
    expect(Object.getPrototypeOf(value)).toBeNull();
    expect(Object.keys(value)).toEqual(["__proto__", "constructor", "toString"]);
    expect([value["__proto__"], value["constructor"], value["toString"]]).toEqual([1, 2, 3]);
    expect(writeToken(value)).toBe(token);
  });

  it("refusesHostileSizesAtTheirLimit", () => {
    // Not even base64url, so a reader that decoded it before checking its length would refuse it at another step.
    expect(refusal(() => readToken("A".repeat(10 * 1024 * 1024 - 1) + "!")).step).toBe("size");
    // Zero bytes, which a reader that parsed them before checking their length would refuse at another step.
    expect(refusal(() => readWireBytes(new Uint8Array(262_145))).step).toBe("size");
    expect(refusal(() => readFile(new Uint8Array(1_048_577))).step).toBe("size");

    for (const read of [readWireBytes, readFile]) {
      const deep = refusal(() => read(utf8("[".repeat(100_000))));
      expect(deep.step).toBe("parse");
      expect(deep.message).toMatch(/deeper than 32/);

      const long = refusal(() => read(utf8("9".repeat(100_000))));
      expect(long.step).toBe("parse");
      expect(long.message).toMatch(/more than 16 digits/);
    }
  });

  it("refusesEachEncodingFaultAtTheParse", () => {
    // On the wire the canonical-bytes check would refuse these too, so each is checked at its own step.
    const faults: [string, string][] = [
      ["a lone low surrogate escaped", '"\\udc00"'],
      ["a lone high surrogate escaped, then x", '"\\ud800x"'],
      ["the overlong form e0 80 80", "22e0808022"],
      ["the overlong form e0 9f bf", "22e09fbf22"],
      ["the overlong form f0 8f bf bf", "22f08fbfbf22"],
      ["a raw U+0000", "220022"],
      ["a raw U+001F", "221f22"],
    ];
    for (const [name, input] of faults) {
      const bytes = input.startsWith('"') ? utf8(input) : new Uint8Array(Buffer.from(input, "hex"));
      for (const read of [readWireBytes, readFile]) expect(refusal(() => read(bytes)).step, name).toBe("parse");
    }
  });

  it("theWriterRefusesWhatTheReaderRefuses", () => {
    class Point {
      x = 1;
    }
    const refused: [string, unknown][] = [
      ["a lone surrogate", "a\ud800b"],
      ["a lone surrogate as a name", { "\ud800": 1 }],
      ["the noncharacter U+FFFF", "a\uffffb"],
      ["the noncharacter U+10FFFF as a pair", "\u{10ffff}"],
      ["1.5", 1.5],
      ["-1", -1],
      ["-0", -0],
      ["2 ** 53", 2 ** 53],
      ["33 nested arrays", nested(33)],
      ["a Map", new Map()],
      ["a class instance", new Point()],
    ];
    for (const write of [writeToken, printFile]) {
      for (const [name, value] of refused) {
        expect(refusal(() => write(value as JsonValue)).step, name).toBe("write");
      }
      expect(() => write(nested(32))).not.toThrow();
    }
    // Each writer's own limit, one past it and at it: 262 145 wire bytes, its quotes included, and a file of
    // 1 048 577 bytes, its final newline included.
    expect(refusal(() => writeToken("a".repeat(262_143))).step).toBe("write");
    expect(() => writeToken("a".repeat(262_142))).not.toThrow();
    expect(refusal(() => printFile("a".repeat(1_048_574))).step).toBe("write");
    expect(() => printFile("a".repeat(1_048_573))).not.toThrow();
  });

  it("printFileWritesTheFileFormat", () => {
    expect(printFile({ b: [1, {}], a: "é" })).toBe('{\n  "a": "é",\n  "b": [\n    1,\n    {}\n  ]\n}\n');
  });
});
