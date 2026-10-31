// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// spec/vectors/json.json is what its generator writes, and the generator holds its answers as literals: it imports
// no SDK code, so no implementation confirms its own answers. The replays read the file's own structure with the
// platform's parser, as its about says, and hand every case input to the SDK as bytes.

import { readFileSync } from "node:fs";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { canonicalize, writeWire } from "../src/encoding/jcs.ts";
import { printFile } from "../src/encoding/json-file.ts";
import { JSON_LIMITS, MalformedJson, readFile, readToken, type JsonValue } from "../src/encoding/json.ts";
import { vectorsJsonText } from "./vectors-json-export.ts";

type Build = { head: string; repeat: string; times: number; tail: string };
type Input = { utf8: string } | { hex: string } | { build: Build };
type ReadCase = { name: string } & Input & { expected: "OK" | "REFUSED"; value?: unknown };
type FileFormatCase = { name: string; kind: string | null; value: unknown; file: string };
type JcsCase = { name: string } & ({ binary64: string } | { value: unknown }) & { expected: string | null };

const v = JSON.parse(readFileSync(new URL("../../../spec/vectors/json.json", import.meta.url), "utf8"));

function bytesOf(input: Input): Uint8Array {
  if ("hex" in input) return new Uint8Array(Buffer.from(input.hex, "hex"));
  if ("utf8" in input) return new Uint8Array(Buffer.from(input.utf8, "utf8"));
  const { head, repeat, times, tail } = input.build;
  return new Uint8Array(Buffer.from(head + repeat.repeat(times) + tail, "utf8"));
}

/** The double whose IEEE 754 bits are `hex`, most significant first. */
function binary64(hex: string): number {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt("0x" + hex));
  return view.getFloat64(0);
}

describe("json.json", () => {
  it("theCommittedFileIsWhatTheGeneratorWrites", () => {
    const committed = readFileSync(new URL("../../../spec/vectors/json.json", import.meta.url), "utf8");
    expect(committed).toBe(vectorsJsonText());
  });

  it("theGeneratorImportsNoSdkCode", () => {
    const source = readFileSync(new URL("./vectors-json-export.ts", import.meta.url), "utf8");
    // static, dynamic and require imports alike
    const imported = ts.preProcessFile(source, true, true).importedFiles.map((f) => f.fileName);
    expect(imported.length).toBeGreaterThan(0);
    expect(imported.filter((name) => !name.startsWith("node:"))).toEqual([]);
  });

  it("theLimitsAreTheFilesLimits", () => {
    expect(JSON_LIMITS).toEqual(v.limits);
  });

  describe("wire", () => {
    it.each(v.wire as ReadCase[])("$name", (c) => {
      const bytes = bytesOf(c);
      const token = Buffer.from(bytes).toString("base64url");
      if (c.expected === "REFUSED") {
        expect(() => readToken(token)).toThrow(MalformedJson);
        return;
      }
      const value = readToken(token);
      if ("value" in c) expect(value).toEqual(c.value);
      expect(writeWire(value)).toEqual(bytes);
    });
  });

  describe("file", () => {
    it.each(v.file as ReadCase[])("$name", (c) => {
      const bytes = bytesOf(c);
      if (c.expected === "REFUSED") {
        expect(() => readFile(bytes)).toThrow(MalformedJson);
        return;
      }
      const value = readFile(bytes);
      if ("value" in c) expect(value).toEqual(c.value);
    });
  });

  describe("fileFormat", () => {
    it.each(v.fileFormat as FileFormatCase[])("$name", (c) => {
      expect(printFile(c.value as JsonValue)).toBe(c.file);
      expect(readFile(new Uint8Array(Buffer.from(c.file, "utf8")))).toEqual(c.value);
    });
  });

  describe("jcs", () => {
    it.each(v.jcs as JcsCase[])("$name", (c) => {
      const value = "binary64" in c ? binary64(c.binary64) : c.value;
      if (c.expected === null) expect(() => canonicalize(value)).toThrow();
      else expect(canonicalize(value)).toBe(c.expected);
    });
  });
});
