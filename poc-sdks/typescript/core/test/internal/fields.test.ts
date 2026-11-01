// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// The same cases as the Java SDK's JsonFieldsTest, so both refuse the same objects.

import { describe, expect, it } from "vitest";
import { utf8 } from "../../src/crypto/crypto.ts";
import { readFile, type JsonValue } from "../../src/encoding/json.ts";
import { bool, exactly, int, object, str, stringMap } from "../../src/internal/fields.ts";

const REQUIRED = ["one", "two"];
const OPTIONAL = ["three"];

const read = (json: string): JsonValue => readFile(utf8(json));
const obj = (json: string) => object(read(json));

describe("fields", () => {
  it("anObjectIsAnObjectAndNothingElseIs", () => {
    expect(Object.keys(obj("{}"))).toEqual([]);
    for (const json of ["[]", '"a"', "1", "null", "true"]) {
      expect(() => object(read(json)), json).toThrow();
    }
  });

  it("exactlyTakesTheRequiredMembersAndTheOptionalOnes", () => {
    for (const json of ['{"one":1,"two":2}', '{"one":1,"three":3,"two":2}', '{"one":null,"two":2}']) {
      expect(() => exactly(obj(json), REQUIRED, OPTIONAL), json).not.toThrow();
    }
  });

  it("exactlyRefusesAMissingMemberByName", () => {
    expect(() => exactly(obj('{"one":1,"three":3}'), REQUIRED, OPTIONAL)).toThrow(/two/);
  });

  it("exactlyRefusesAMemberTheSchemaDoesNotDefineWithoutEchoingIt", () => {
    for (const json of ['{"evil":3,"one":1,"two":2}', '{"__proto__":{},"one":1,"two":2}']) {
      expect(() => exactly(obj(json), REQUIRED, OPTIONAL), json).toThrow();
      expect(() => exactly(obj(json), REQUIRED, OPTIONAL), json).not.toThrow(/evil|proto/);
    }
    expect(() => exactly(obj('{"one":1}'), [])).toThrow();
  });

  it("eachMemberIsReadAsItsTypeOnly", () => {
    const o = obj('{"count":9007199254740991,"flag":true,"nothing":null,"text":"x"}');
    expect(str(o, "text")).toBe("x");
    expect(int(o, "count")).toBe(Number.MAX_SAFE_INTEGER);
    expect(bool(o, "flag")).toBe(true);
    for (const name of ["flag", "count", "nothing", "absent"]) expect(() => str(o, name)).toThrow(name);
    for (const name of ["flag", "text", "nothing", "absent"]) expect(() => int(o, name)).toThrow(name);
    for (const name of ["count", "text", "nothing", "absent"]) expect(() => bool(o, name)).toThrow(name);
    // An inherited name is not a member.
    expect(() => str(obj("{}"), "toString")).toThrow("toString");
  });

  it("aStringMapHoldsStringsOnly", () => {
    expect(stringMap(read('{"y":"2","x":"1"}'))).toEqual({ y: "2", x: "1" });
    expect(stringMap(read("{}"))).toEqual({});
    expect(Object.getPrototypeOf(stringMap(read('{"__proto__":"p"}')))).toBeNull();
    for (const json of ['{"x":1}', '{"x":null}', '{"x":{}}', "[]", '"x"']) {
      expect(() => stringMap(read(json)), json).toThrow();
    }
  });
});
