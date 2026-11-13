// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// spec/vectors/ed25519.json is what its generator writes, and the generator works out every answer with its own
// RFC 8032 arithmetic: it imports no SDK code, so no library confirms its own answers. The replay hands each case to
// the SDK's verify, and checks that the bare library goes wrong only on cases the SDK's own checks refuse.

import { createHash, createPrivateKey, createPublicKey, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { verify } from "../src/crypto/crypto.ts";
import { strictEncodings } from "../src/crypto/ed25519-strict.ts";
import { decode } from "../src/encoding/b64url.ts";
import { vectorsEd25519Text } from "./vectors-ed25519-export.ts";

type Case = { name: string; publicKey: string; message: string; signature: string; valid: boolean };

const vectors: { smallOrderY: string[]; cases: Case[] } = JSON.parse(
  readFileSync(new URL("../../../spec/vectors/ed25519.json", import.meta.url), "utf8"),
);

const NAMES = [
  "a signature by the key",
  "the empty message",
  "a signature over another message",
  "S plus the group order",
  "S with its top bit set",
  "R the identity, made with the key",
  "R the identity, written with y = p + 1",
  "R of order 8, S made for the cofactored equation",
  "A the identity",
  "A of order 2",
  "A of order 4, x sign 0",
  "A of order 4, x sign 1",
  "A of order 8, y8, x sign 0",
  "A of order 8, y8, x sign 1",
  "A of order 8, p - y8, x sign 0",
  "A of order 8, p - y8, x sign 1",
  "A the identity with the sign bit set",
  "A of order 2 with the sign bit set",
  "A the identity, written with y = p + 1",
  "A of order 4, written with y = p",
  "A with a small-order part, k not a multiple of 8",
  "R with a small-order part, S made for the cofactored equation",
  "A with a small-order part, k a multiple of 8",
  "A whose y is on no curve point",
  "a signature of 63 bytes",
  "a signature of 65 bytes",
  "a key of 31 bytes",
  "a key under the X25519 identifier",
  "a key whose SPKI length is written in long form",
  "a key with a trailing byte",
];

describe("ed25519.json", () => {
  it("theCommittedFileIsWhatTheGeneratorWrites", () => {
    const committed = readFileSync(new URL("../../../spec/vectors/ed25519.json", import.meta.url), "utf8");
    expect(committed).toBe(vectorsEd25519Text());
  });

  it("theGeneratorImportsNoSdkCode", () => {
    const source = readFileSync(new URL("./vectors-ed25519-export.ts", import.meta.url), "utf8");
    // static, dynamic and require imports alike
    const imported = ts.preProcessFile(source, true, true).importedFiles.map((f) => f.fileName);
    expect(imported.length).toBeGreaterThan(0);
    expect(imported.filter((name) => !name.startsWith("node:"))).toEqual([]);
  });

  it("theGeneratorsSigningAgreesWithNode", () => {
    // The generator's key and signature are its own RFC 8032 arithmetic; node:crypto signing by the same seed must agree.
    const seed = createHash("sha256").update("paztport-ed25519-vector-key:signer").digest();
    const pkcs8 = Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]);
    const key = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
    const first = vectors.cases[0]!;
    expect(Buffer.from(nodeSign(null, decode(first.message), key)).toString("base64url")).toBe(first.signature);
    expect(Buffer.from(createPublicKey(key).export({ format: "der", type: "spki" })).toString("base64url")).toBe(first.publicKey);
  });

  it("smallOrderYHoldsTheKnownOrder8Values", () => {
    expect(vectors.smallOrderY).toContain("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05");
    expect(vectors.smallOrderY).toContain("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a");
    expect(vectors.smallOrderY).toHaveLength(5);
  });

  it("hasTheCasesThePlanNames", () => {
    expect(vectors.cases.map((c) => c.name)).toEqual(NAMES);
    expect(vectors.cases).toHaveLength(30);
  });

  it.each(vectors.cases)("$name", (c) => {
    expect(verify(c.publicKey, decode(c.message), decode(c.signature))).toBe(c.valid);
  });

  it("theLibraryAloneDisagreesOnlyWhereTheCheckIsNeeded", () => {
    // A library that answers otherwise after rules 1 to 4 pass (one that multiplies by the cofactor, say) is one the
    // checks in front cannot correct: the rule would then depend on the library build.
    const wrong = vectors.cases.filter((c) => bareLibrary(c) !== c.valid);
    for (const c of wrong) expect(rulesOneToFour(c), c.name).toBe(false);
    console.log("node:crypto alone answers otherwise on: " + JSON.stringify(wrong.map((c) => c.name)));
  });
});

/** node:crypto's verify with nothing in front of it; a key it cannot decode counts as not valid. */
function bareLibrary(c: Case): boolean {
  try {
    const key = createPublicKey({ key: Buffer.from(decode(c.publicKey)), format: "der", type: "spki" });
    return nodeVerify(null, decode(c.message), key, decode(c.signature));
  } catch {
    return false;
  }
}

function rulesOneToFour(c: Case): boolean {
  const spki = decode(c.publicKey);
  const signature = decode(c.signature);
  if (spki.length !== 44 || Buffer.from(spki.subarray(0, 12)).toString("hex") !== "302a300506032b6570032100") return false;
  return strictEncodings(spki.subarray(12), signature);
}

