// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  NonceCache, bindHttp, decode, decodeChainV1, decodeProof, encode, encodeChainV1, leafHash, nodeHash,
  sign, signingBytesV1, verifyProof, verifyRoot, verifyV1,
} from "../src/index.ts";
import type { ReasonCode } from "../src/index.ts";

type Keys = Record<string, { pub: string; priv: string }>;
const v = JSON.parse(readFileSync(new URL("./vectors/v1.json", import.meta.url), "utf8"));
const keys: Keys = v.keys;

describe("Java-exported v1 vectors", () => {
  it.each((v.stamps as any[]).map((s, i): [number, any] => [i, s]))("stamp %i signing bytes and signature", (_i: number, s: any) => {
    const bytes = signingBytesV1(s.fields);
    expect(encode(bytes)).toBe(s.signingBytes);
    expect(encode(sign(keys[s.key]!.priv, bytes))).toBe(s.sig);
  });

  it.each((v.chains as any[]).map((c, i): [number, any] => [i, c]))("chain %i round-trips", (_i: number, c: any) => {
    expect(decodeChainV1(c.header)).toEqual(c.stamps);
    expect(decodeChainV1(encodeChainV1(c.stamps))).toEqual(c.stamps);
  });

  it.each((v.bindings as any[]).map((b, i): [number, any] => [i, b]))("binding %i", (_i: number, b: any) => {
    expect(bindHttp(b.method, b.path, decode(b.body))).toBe(b.bind);
  });

  it("merkle leaves, nodes, proofs and signed root", () => {
    const m = v.merkle;
    for (const l of m.leaves) {
      expect(encode(leafHash(decode(l.salt), l.path))).toBe(l.hash);
    }
    for (const n of m.nodes) {
      expect(encode(nodeHash(decode(n.left), decode(n.right)))).toBe(n.hash);
    }
    const root = decode(m.root);
    expect(m.signedRoot.root).toBe(m.root);
    expect(verifyRoot(m.signedRoot, keys[m.policyKey]!.pub)).toBe(true);
    for (const p of Object.keys(m.proofs)) {
      expect(verifyProof(m.proofs[p], p, root)).toBe(true);
      expect(decodeProof(m.proofHeaders[p])).toEqual(m.proofs[p]);
    }
  });

  it.each((v.verify as any[]).map((c): [string, any] => [c.name, c]))("verify case %s", (_n: string, c: any) => {
    const ring: Record<string, string> = {};
    for (const [svc, name] of Object.entries(c.keyring as Record<string, string>)) {
      ring[svc] = keys[name]!.pub;
    }
    const nonces = new NonceCache(c.maxAgeMs);
    let last: ReasonCode | undefined;
    for (let i = 0; i < c.uses; i++) {
      last = verifyV1(
        {
          chainHeader: c.chainHeader ?? undefined,
          proofHeader: c.proofHeader ?? undefined,
          method: c.method,
          path: c.path,
          body: decode(c.body),
        },
        {
          keyring: ring,
          root: decode(v.merkle.root),
          rootId: v.merkle.rootId,
          allowedOrigins: c.allowedOrigins,
          maxAgeMs: c.maxAgeMs,
          receivingService: c.receivingService,
          nonces,
          now: c.now,
        },
      ).reason;
    }
    expect(last).toBe(c.expected);
  });
});
