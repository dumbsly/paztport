// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { concat, randomBytes, utf8 } from "../src/crypto.ts";
import { decode, encode } from "../src/b64url.ts";
import { buildTree, decodeProof, encodeProof, leafHash, nodeHash, verifyProof } from "../src/merkle.ts";

const paths = ["a/b", "a/c", "a/d"];
const leaves = () => paths.map((path) => ({ salt: randomBytes(16), path }));

describe("merkle", () => {
  it("everyLeafProofVerifies", () => {
    const t = buildTree(leaves(), 8, "v1");
    for (const p of paths) {
      const proof = t.proofFor(p);
      expect(proof.siblings).toHaveLength(8);
      expect(proof.dirs).toHaveLength(8);
      expect(proof.rootId).toBe("v1");
      expect(verifyProof(proof, p, t.root)).toBe(true);
    }
  });
  it("proofFailsForOtherPath", () => {
    const t = buildTree(leaves(), 8, "v1");
    expect(verifyProof(t.proofFor("a/b"), "a/c", t.root)).toBe(false);
  });
  it("proofFailsForTamperedSibling", () => {
    const t = buildTree(leaves(), 8, "v1");
    const proof = t.proofFor("a/b");
    const sib = decode(proof.siblings[0]!);
    sib[0] = sib[0]! ^ 1;
    const bad = { ...proof, siblings: [encode(sib), ...proof.siblings.slice(1)] };
    expect(verifyProof(bad, "a/b", t.root)).toBe(false);
  });
  it("proofFailsWhenDirsLengthDiffers", () => {
    const t = buildTree(leaves(), 8, "v1");
    const proof = t.proofFor("a/b");
    expect(verifyProof({ ...proof, dirs: proof.dirs.slice(1) }, "a/b", t.root)).toBe(false);
  });
  it("proofFailsOnUndecodableSibling", () => {
    const t = buildTree(leaves(), 8, "v1");
    const proof = t.proofFor("a/b");
    expect(verifyProof({ ...proof, siblings: ["!!", ...proof.siblings.slice(1)] }, "a/b", t.root)).toBe(false);
  });
  it("tooManyLeavesThrows", () => {
    expect(() => buildTree(leaves(), 1, "v1")).toThrow();
  });
  it("encodeDecodeRoundTrip", () => {
    const t = buildTree(leaves(), 8, "v1");
    const proof = t.proofFor("a/c");
    const decoded = decodeProof(encodeProof(proof));
    expect(decoded).toEqual(proof);
    expect(Object.keys(JSON.parse(Buffer.from(decode(encodeProof(proof))).toString()))).toEqual([
      "leafSalt",
      "siblings",
      "dirs",
      "rootId",
    ]);
  });
  it("decodeRejectsGarbage", () => {
    expect(() => decodeProof("!!!")).toThrow();
    expect(() => decodeProof(encode(utf8("not json")))).toThrow();
    expect(() => decodeProof(encode(utf8('{"leafSalt":1}')))).toThrow();
  });
  it("leafAndNodeAreDomainSeparated", () => {
    const salt = randomBytes(16);
    const p = "x/y";
    const l = leafHash(salt, p);
    expect(Buffer.from(l)).not.toEqual(Buffer.from(nodeHash(salt, utf8(p))));
    expect(Buffer.from(leafHash(salt, p))).toEqual(Buffer.from(l));
    expect(concat(salt, utf8(p)).length).toBe(16 + 3);
  });
});
