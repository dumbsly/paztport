// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { encode } from "../../src/encoding/b64url.ts";
import { sha256, utf8 } from "../../src/crypto/crypto.ts";
import { writeToken } from "../../src/encoding/jcs.ts";
import { readToken, type JsonValue } from "../../src/encoding/json.ts";
import { MalformedJson } from "../../src/encoding/json-rules.ts";
import {
  blockOf, commitBlock, EMPTY_BLOCK, isExtensionName, itemsUnder, makeBlock, readBlocks, writeBlocks, type Block,
} from "../../src/stamp/block.ts";

const commitOf = (text: string): string => encode(sha256(utf8(text)));

/** `depth` arrays, one inside the next. */
const nested = (depth: number): JsonValue => {
  let v: JsonValue = [];
  for (let i = 1; i < depth; i++) v = [v];
  return v;
};

describe("block", () => {
  it("theEmptyBlockCommitsToTheEmptyString", () => {
    expect(commitBlock(EMPTY_BLOCK)).toBe("");
    expect(commitBlock(makeBlock({}))).toBe("");
  });

  it("aBlockThatNamesAnExtensionWithNoItemsIsNotTheEmptyBlock", () => {
    const c = commitBlock(makeBlock({ example: [] }));
    expect(c).toBe(commitOf('{"items":{"example":[]},"requires":[]}'));
    expect(c).not.toBe("");
  });

  it("aBlockThatOnlyRequiresIsNotTheEmptyBlock", () => {
    const c = commitBlock(makeBlock({}, ["example"]));
    expect(c).toBe(commitOf('{"items":{},"requires":["example"]}'));
    expect(c).not.toBe("");
  });

  it("theCommitmentIsOverTheBlockAsWritten", () => {
    expect(commitBlock(makeBlock({ example: [1, 2] }))).not.toBe(commitBlock(makeBlock({ example: [2, 1] })));
  });

  it("anExtensionNameIsOneTo32LowercaseLettersDigitsAndHyphens", () => {
    for (const ok of ["a", "influence", "x-1", "a".repeat(32)]) expect(isExtensionName(ok)).toBe(true);
    for (const no of ["", "a".repeat(33), "A", "a_b", "a.b", "é"]) expect(isExtensionName(no)).toBe(false);
  });

  it("readsABlock", () => {
    const value = { items: { example: [{ note: "n" }, 7, null] }, requires: ["example", "influence"] };
    expect(blockOf(value)).toEqual(value);
  });

  it.each<[string, JsonValue]>([
    ["an array", []],
    ["another member", { items: {}, requires: [], more: 1 }],
    ["no requires", { items: {} }],
    ["items an array", { items: [], requires: [] }],
    ["a value in items that is an object", { items: { example: {} }, requires: [] }],
    ["a name Example in items", { items: { Example: [] }, requires: [] }],
    ["a name a_b in requires", { items: {}, requires: ["a_b"] }],
    ["requires unsorted", { items: {}, requires: ["b", "a"] }],
    ["a name twice in requires", { items: {}, requires: ["a", "a"] }],
    ["a number in requires", { items: {}, requires: [1] }],
  ])("refusesWhatIsNotABlock: %s", (_name, value) => {
    expect(() => blockOf(value)).toThrow();
  });

  it("writeBlocksIsWhatReadBlocksReads", () => {
    const blocks = [EMPTY_BLOCK, makeBlock({ example: [{ note: "n" }, 7] }, ["example"])];
    const token = writeBlocks(blocks);
    // the token a client wrote by casting the blocks to a JSON value
    expect(token).toBe(writeToken(blocks as unknown as JsonValue));
    expect(readBlocks(token)).toEqual(blocks);
    expect(readBlocks(writeBlocks([]))).toEqual([]);
  });

  it("writeBlocksRefusesABlockReadBlocksWouldRefuse", () => {
    const unsorted: Block = { items: {}, requires: ["b", "a"] };
    const badName = { items: { Example: [] }, requires: [] } as Block;
    for (const block of [unsorted, badName]) {
      expect(() => readBlocks(writeToken([block] as unknown as JsonValue))).toThrow();
      expect(() => writeBlocks([EMPTY_BLOCK, block])).toThrow();
    }
  });

  it("makeBlockSortsWhatItRequires", () => {
    expect(makeBlock({}, ["b", "a", "bc"]).requires).toEqual(["a", "b", "bc"]);
  });

  it("makeBlockRefusesANameTwiceAndANameThatIsNotOne", () => {
    expect(() => makeBlock({}, ["a", "a"])).toThrow();
    expect(() => makeBlock({}, ["A"])).toThrow();
    expect(() => makeBlock({ A: [] })).toThrow();
    expect(() => makeBlock({ "a_b": [] })).toThrow();
  });

  it.each(["constructor", "toString"])("aNameOfObjectsPrototypeIsNamedOnlyWhereItIsListed: %s", (name) => {
    expect(itemsUnder(EMPTY_BLOCK, name)).toBeNull();
    expect(itemsUnder(makeBlock({}), name)).toBeNull();
    // "toString" has a capital, so it is not an extension name and no block lists it.
    if (!isExtensionName(name)) {
      expect(() => makeBlock({ [name]: [1] })).toThrow();
      expect(() => blockOf({ items: { [name]: [1] }, requires: [] })).toThrow();
      return;
    }
    const built = makeBlock({ [name]: [1] });
    expect(itemsUnder(built, name)).toEqual([1]);
    const read = blockOf(readToken(writeToken(built as unknown as JsonValue)));
    expect(itemsUnder(read, name)).toEqual([1]);
    expect(itemsUnder(blockOf(readToken(writeToken(makeBlock({}) as unknown as JsonValue))), name)).toBeNull();
  });

  it("aNameOfObjectsPrototypeIsNamedOnlyWhereItIsListed: __proto__ is not an extension name", () => {
    expect(isExtensionName("__proto__")).toBe(false);
    const token = writeToken({ items: { ["__proto__"]: [] }, requires: [] });
    expect(() => blockOf(readToken(token))).toThrow();
  });

  it("anItemMayNestTo28LevelsInARequestsBlocks", () => {
    const blocks = (depth: number): string =>
      writeToken([{ items: { example: [nested(depth)] }, requires: [] }]);
    expect(readBlocks(blocks(28))).toHaveLength(1);
    expect(() => readBlocks(blocks(29))).toThrow(MalformedJson);
  });
});
