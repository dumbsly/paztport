// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Pinned bytes for cross-implementation conformance: the session id, the prompt and response bindings, the influence
// commitment and the Merkle primitives, from v3.json. Change only with a protocol change.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  bindPrompt, bindResponse, commitInfluence, decode, deriveSessionId, encode, encodeProof, leafHash, nodeHash,
  readProof, verifyProof,
} from "../src/index.ts";

const v = JSON.parse(readFileSync(new URL("../../../spec/vectors/v3.json", import.meta.url), "utf8"));

/** n consecutive bytes starting at `start`, base64url. */
const seq = (start: number, n: number) => encode(Uint8Array.from({ length: n }, (_, i) => start + i));

const fixed = v.fixedInputs as Record<string, { start: number; length: number; encoded: string }>;
const input = (name: string) => seq(fixed[name]!.start, fixed[name]!.length);

describe("v3 known-answer vectors: the shared primitives", () => {
  it("fixed inputs encode as expected", () => {
    for (const [name, f] of Object.entries(fixed)) {
      expect(input(name), name).toBe(f.encoded);
    }
  });

  it.each((v.deriveSessionId.cases as any[]).map((c): [string, any] => [c.name, c]))("deriveSessionId: %s", (_name, c) => {
    const clientSig = c.clientRootSig === null ? null : input(c.clientRootSig);
    const serverSig = c.serverRootSig === null ? null : input(c.serverRootSig);
    expect(deriveSessionId(clientSig, serverSig, input("clientNonce"), input("serverNonce"), v.deriveSessionId.keys)).toBe(c.expected);
  });

  it("bindResponse", () => {
    expect(bindResponse(v.bindResponse.resultHash, v.bindResponse.callId, v.bindResponse.labels)).toBe(v.bindResponse.expected);
  });

  it("bindPrompt", () => {
    expect(bindPrompt(v.bindPrompt.prompt)).toBe(v.bindPrompt.expected);
  });

  it("commitInfluence", () => {
    expect(commitInfluence(v.commitInfluence.entries)).toBe(v.commitInfluence.expected);
  });

  it("merkle leaves, nodes and proofs", () => {
    const m = v.merkle;
    for (const l of m.leaves) {
      expect(encode(leafHash(decode(l.salt), l.path))).toBe(l.hash);
    }
    for (const n of m.nodes) {
      expect(encode(nodeHash(decode(n.left), decode(n.right)))).toBe(n.hash);
    }
    const root = decode(m.root);
    for (const p of Object.keys(m.proofs)) {
      expect(verifyProof(m.proofs[p], p, root)).toBe(true);
      expect(readProof(m.proofHeaders[p])).toEqual(m.proofs[p]);
      expect(encodeProof(m.proofs[p])).toBe(m.proofHeaders[p]);
    }
  });
});
