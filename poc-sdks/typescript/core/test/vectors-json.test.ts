// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// spec/vectors/json.json is what its generator writes, and the generator holds its answers as literals: it imports
// no SDK code, so no implementation confirms its own answers.

import { readFileSync } from "node:fs";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { vectorsJsonText } from "./vectors-json-export.ts";

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
});
