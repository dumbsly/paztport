// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { concat, randomBytes, utf8 } from "../../src/crypto/crypto.ts";
import { decode, encode } from "../../src/encoding/b64url.ts";
import { canonicalize, writeToken } from "../../src/encoding/jcs.ts";
import type { JsonValue } from "../../src/encoding/json.ts";
import { MalformedJson } from "../../src/encoding/json-rules.ts";
import {
  buildTree, encodeProof, leafHash, nodeHash, parseProof, provesPath, readProof, verifyProof,
} from "../../src/policy/merkle.ts";

const paths = ["a/b", "a/c", "a/d"];
const leaves = () => paths.map((path) => ({ salt: randomBytes(16), path }));

describe("merkle", () => {
  it("leafHashRefusesALoneSurrogate", () => {
    expect(() => leafHash(randomBytes(16), "a/\ud800")).toThrow(TypeError);
    expect(leafHash(randomBytes(16), "a/\ud83d\ude00")).toHaveLength(32);
  });
  it("aLoneSurrogateRouteDoesNotVerifyAndDoesNotThrow", () => {
    const t = buildTree(leaves(), 8, "v1");
    expect(verifyProof(t.proofFor("a/b"), "a/\ud800", t.root)).toBe(false);
  });
  it("explicitSlotsProveAndPlace", () => {
    const two = leaves().slice(0, 2);
    const t = buildTree(two, 8, "v1", [5, 200]);
    for (const l of two) expect(verifyProof(t.proofFor(l.path), l.path, t.root)).toBe(true);
    // Slot 5 is binary 00000101, least significant bit first.
    expect(t.proofFor(two[0]!.path).dirs).toBe("RLRLLLLL");
  });
  it("duplicateOrOutOfRangeSlotsRefused", () => {
    expect(() => buildTree(leaves().slice(0, 2), 8, "v1", [3, 3])).toThrow();
    expect(() => buildTree(leaves().slice(0, 1), 8, "v1", [256])).toThrow();
    expect(() => buildTree(leaves().slice(0, 1), 8, "v1", [-1])).toThrow();
    expect(() => buildTree(leaves().slice(0, 2), 8, "v1", [1])).toThrow();
  });
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
    const decoded = readProof(encodeProof(proof));
    expect(decoded).toEqual(proof);
    expect(Buffer.from(decode(encodeProof(proof))).toString()).toBe(canonicalize(proof));
    expect(Object.keys(JSON.parse(Buffer.from(decode(encodeProof(proof))).toString()))).toEqual([
      "dirs",
      "leafSalt",
      "rootId",
      "siblings",
    ]);
  });
  it("readProofRefusesGarbage", () => {
    expect(() => readProof("!!!")).toThrow(MalformedJson);
    expect(() => readProof(encode(utf8("not json")))).toThrow(MalformedJson);
    expect(() => readProof(writeToken({ leafSalt: 1 }))).toThrow("no member dirs");
  });
  it("readProofTakesExactlyTheProofsMembersFromItsBytes", () => {
    const proof = buildTree(leaves(), 8, "v1").proofFor("a/b");
    expect(() => readProof(writeToken({ ...proof, extra: "x" }))).toThrow("a member the object does not define");
    expect(() => readProof(writeToken({ ...proof, siblings: [1] }))).toThrow("siblings");
    expect(() => readProof(writeToken({ ...proof, siblings: "x" }))).toThrow("member siblings");
    const wireOrder =
      `{"leafSalt":"${proof.leafSalt}","siblings":${canonicalize(proof.siblings)},"dirs":"${proof.dirs}",` +
      `"rootId":"${proof.rootId}"}`;
    expect(() => readProof(encode(utf8(wireOrder)))).toThrow(MalformedJson);
    expect(readProof(encode(utf8(canonicalize(proof))))).toEqual(proof);
  });
  it("leafAndNodeAreDomainSeparated", () => {
    const salt = randomBytes(16);
    const p = "x/y";
    const l = leafHash(salt, p);
    expect(Buffer.from(l)).not.toEqual(Buffer.from(nodeHash(salt, utf8(p))));
    expect(Buffer.from(leafHash(salt, p))).toEqual(Buffer.from(l));
    expect(concat(salt, utf8(p)).length).toBe(16 + 3);
  });
  it("resaltedSuffixRouteRejected", () => {
    const full = "session/pi/mcp:github.create_pull_request";
    const salt = randomBytes(16);
    const t = buildTree([{ salt, path: full }], 8, "v1");
    const proof = t.proofFor(full);
    // SHA-256(0x00||salt||"session/"||suffix) == leaf of `full`: a longer salt re-splits the path.
    const resalted = { ...proof, leafSalt: encode(concat(salt, utf8("session/"))) };
    expect(verifyProof(resalted, "pi/mcp:github.create_pull_request", t.root)).toBe(false);
    expect(verifyProof(proof, full, t.root)).toBe(true);
  });
  it("shortSaltRejected", () => {
    const t = buildTree([{ salt: randomBytes(8), path: "a/b" }], 8, "v1");
    expect(verifyProof(t.proofFor("a/b"), "a/b", t.root)).toBe(false);
  });
  it("siblingWrongLengthRejected", () => {
    const t = buildTree(leaves(), 8, "v1");
    const proof = t.proofFor("a/b");
    for (const n of [31, 33, 0]) {
      const bad = { ...proof, siblings: [encode(randomBytes(n)), ...proof.siblings.slice(1)] };
      expect(verifyProof(bad, "a/b", t.root)).toBe(false);
    }
  });
  it("dirsWithXRejected", () => {
    const t = buildTree(leaves(), 8, "v1");
    const proof = t.proofFor("a/c"); // index 1: first direction is "R"
    expect(proof.dirs[0]).toBe("R");
    const bad = { ...proof, dirs: "X" + proof.dirs.slice(1) };
    expect(verifyProof(bad, "a/c", t.root)).toBe(false);
    expect(() => parseProof(bad)).toThrow();
    expect(() => parseProof({ ...proof, dirs: proof.dirs.toLowerCase() })).toThrow();
    expect(parseProof(proof)).toEqual(proof);
  });
  it("aProofsLengthsAreCheckedWhenItIsRead", () => {
    // the checks Java's MerkleProof.parse makes, in its order, so both SDKs refuse the same proofs
    const proof = buildTree(leaves(), 8, "v1").proofFor("a/b");
    const read = (p: unknown) => () => readProof(writeToken(p as JsonValue));
    expect(read({ ...proof, dirs: proof.dirs.slice(1) })).toThrow("member dirs is not one L or R per sibling");
    expect(read({ ...proof, siblings: proof.siblings.slice(1) })).toThrow("member dirs is not one L or R per sibling");
    const shortSalt = encode(randomBytes(8));
    expect(read({ ...proof, leafSalt: shortSalt })).toThrow("member leafSalt is not 16 bytes of base64url");
    expect(read({ ...proof, leafSalt: proof.leafSalt + "A" })).toThrow("member leafSalt");
    for (const n of [31, 33]) {
      const siblings = [encode(randomBytes(n)), ...proof.siblings.slice(1)];
      expect(read({ ...proof, siblings })).toThrow("member siblings holds a value that is not 32 bytes of base64url");
    }
    expect(read({ ...proof, siblings: ["!!", ...proof.siblings.slice(1)] })).toThrow("member siblings");
    expect(read(proof)()).toEqual(proof);
  });
  it("provesPathChecksTheRootId", () => {
    const t = buildTree(leaves(), 8, "v1");
    const proof = t.proofFor("a/b");
    expect(provesPath(proof, "a/b", t.root, "v1")).toBe(true);
    expect(provesPath(proof, "a/c", t.root, "v1")).toBe(false);
    expect(provesPath(proof, "a/b", t.root, "v2")).toBe(false);
    expect(provesPath({ ...proof, dirs: "X" }, "a/b", t.root, "v1")).toBe(false);
  });
});
