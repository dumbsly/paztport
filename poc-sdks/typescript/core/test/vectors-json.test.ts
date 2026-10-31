// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// spec/vectors/json.json is what its generator writes, and the generator holds its answers as literals: it imports
// no SDK code, so no implementation confirms its own answers. The replays read the file's own structure with the
// platform's parser, as its about says, and hand every case input to the SDK as bytes.

import { readFileSync } from "node:fs";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { decode } from "../src/encoding/b64url.ts";
import { canonicalize, writeWire } from "../src/encoding/jcs.ts";
import { printFile } from "../src/encoding/json-file.ts";
import { leafHash } from "../src/policy/merkle.ts";
import { bindResponse } from "../src/session/attestation.ts";
import { bindLocalTool, bindPrompt, bindResult } from "../src/stamp/binding.ts";
import { JSON_LIMITS, MalformedJson, readFile, readToken, type JsonValue } from "../src/encoding/json.ts";
import { vectorsJsonText } from "./vectors-json-export.ts";

type Build = { head: string; repeat: string; times: number; tail: string };
type Input = { utf8: string } | { hex: string } | { build: Build };
type ReadCase = { name: string } & Input & { expected: "OK" | "REFUSED"; value?: unknown; step?: string };
type FileFormatCase = { name: string; kind: string | null; value: unknown; file: string };
type Base64UrlCase = { name: string; text: string; expected: string | null };
type BindingCase = { name: string; binding: string; inputs: Record<string, any>; expected: null };
type JcsCase = { name: string } & ({ binary64: string } | { value: unknown }) & { expected: string | null };

const v = JSON.parse(readFileSync(new URL("../../../spec/vectors/json.json", import.meta.url), "utf8"));

function bytesOf(input: Input): Uint8Array {
  if ("hex" in input) return new Uint8Array(Buffer.from(input.hex, "hex"));
  if ("utf8" in input) return new Uint8Array(Buffer.from(input.utf8, "utf8"));
  const { head, repeat, times, tail } = input.build;
  return new Uint8Array(Buffer.from(head + repeat.repeat(times) + tail, "utf8"));
}

/** A value as plain data that keeps an object's own members, a name such as __proto__ among them. */
function own(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(own);
  if (typeof value !== "object" || value === null) return value;
  return {
    object: Object.getOwnPropertyNames(value)
      .sort()
      .map((name) => [name, own(Object.getOwnPropertyDescriptor(value, name)?.value)]),
  };
}

/** The double whose IEEE 754 bits are `hex`, most significant first. */
function binary64(hex: string): number {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, BigInt("0x" + hex));
  return view.getFloat64(0);
}

/** The reader step that refused, from what `read` throws. */
function refusal(read: () => unknown): string {
  try {
    read();
  } catch (e) {
    if (e instanceof MalformedJson) return e.step;
    throw e;
  }
  throw new Error("read without a refusal");
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
        expect(c.step).toBeDefined();
        expect(refusal(() => readToken(token))).toBe(c.step);
        return;
      }
      const value = readToken(token);
      if ("value" in c) expect(own(value)).toEqual(own(c.value));
      expect(writeWire(value)).toEqual(bytes);
    });
  });

  describe("file", () => {
    it.each(v.file as ReadCase[])("$name", (c) => {
      const bytes = bytesOf(c);
      if (c.expected === "REFUSED") {
        expect(c.step).toBeDefined();
        expect(refusal(() => readFile(bytes))).toBe(c.step);
        return;
      }
      const value = readFile(bytes);
      if ("value" in c) expect(own(value)).toEqual(own(c.value));
    });
  });

  describe("fileFormat", () => {
    it.each(v.fileFormat as FileFormatCase[])("$name", (c) => {
      expect(printFile(c.value as JsonValue)).toBe(c.file);
      expect(readFile(new Uint8Array(Buffer.from(c.file, "utf8")))).toEqual(c.value);
    });
  });

  describe("base64url", () => {
    it.each(v.base64url as Base64UrlCase[])("$name", (c) => {
      if (c.expected === null) expect(() => decode(c.text)).toThrow();
      else expect(Buffer.from(decode(c.text)).toString("hex")).toBe(c.expected);
    });
  });

  describe("jcs", () => {
    it.each(v.jcs as JcsCase[])("$name", (c) => {
      const value = "binary64" in c ? binary64(c.binary64) : c.value;
      if (c.expected === null) expect(() => canonicalize(value)).toThrow();
      else expect(canonicalize(value)).toBe(c.expected);
    });
  });

  describe("bindings", () => {
    // @paztport/mcp's tests replay toolsCall; http is Java's.
    const refusals: Record<string, (i: Record<string, any>) => unknown> = {
      prompt: (i) => bindPrompt(i.text),
      response: (i) => bindResponse(i.resultHash, i.toolCallId, i.labels),
      result: (i) => bindResult(i.result),
      localTool: (i) => bindLocalTool(i.tool, i.input, i.resolved),
      merkleLeaf: (i) => leafHash(new Uint8Array(Buffer.from(i.salt, "hex")), i.route),
    };
    const own = (v.bindings as BindingCase[]).filter((c) => c.binding in refusals);

    it("everyBindingIsPinned", () => {
      const names = new Set((v.bindings as BindingCase[]).map((c) => c.binding));
      expect([...names].sort()).toEqual(["http", "localTool", "merkleLeaf", "prompt", "response", "result", "toolsCall"]);
    });

    it.each(own)("$name", (c) => {
      expect(c.expected).toBeNull();
      expect(JSON.stringify(c.inputs)).toContain("\\ud800");
      expect(() => refusals[c.binding]!(c.inputs)).toThrow();
    });
  });
});
