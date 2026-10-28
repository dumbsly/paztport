// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../src/crypto.ts";
import { verifyProof } from "../src/merkle.ts";
import { buildPolicy } from "../src/policy.ts";
import { verifyRoot } from "../src/root.ts";
import { decode } from "../src/b64url.ts";

const demo = [["gateway", "orders", "payment"], ["gateway", "orders"], ["gateway", "search"]];

describe("policy", () => {
  it("bundlesGoToSecondToLastHop", () => {
    const { bundles, signedRoot } = buildPolicy(demo, 8, generateKeyPair().privateKey);
    expect(Object.keys(bundles.orders!.proofs)).toEqual(["gateway/orders/payment"]);
    expect(Object.keys(bundles.gateway!.proofs).sort()).toEqual(["gateway/orders", "gateway/search"]);
    expect(bundles.search!.proofs).toEqual({});
    expect(bundles.payment!.proofs).toEqual({});
    expect(Object.keys(bundles.orders!)).toEqual(["service", "rootId", "proofs"]);
    expect(bundles.orders!.service).toBe("orders");
    const p = bundles.orders!.proofs["gateway/orders/payment"]!;
    expect(verifyProof(p, "gateway/orders/payment", decode(signedRoot.root))).toBe(true);
  });
  it("rejectsRouteWithOneNode", () => {
    expect(() => buildPolicy([["solo"]], 8, generateKeyPair().privateKey)).toThrow();
  });
  it("signedRootVerifies", () => {
    const kp = generateKeyPair();
    const { signedRoot } = buildPolicy(demo, 8, kp.privateKey);
    expect(Object.keys(signedRoot)).toEqual(["rootId", "root", "sig"]);
    expect(verifyRoot(signedRoot, kp.publicKey)).toBe(true);
    expect(verifyRoot({ ...signedRoot, rootId: "vother" }, kp.publicKey)).toBe(false);
    expect(verifyRoot(signedRoot, generateKeyPair().publicKey)).toBe(false);
  });
  it("rootIdIsRandomPerBuild", () => {
    const k = generateKeyPair().privateKey;
    const a = buildPolicy(demo, 8, k).signedRoot;
    const b = buildPolicy(demo, 8, k).signedRoot;
    expect(a.rootId).not.toBe(b.rootId);
    expect(a.rootId).toMatch(/^v[0-9a-f]{12}$/);
    expect(b.rootId).toMatch(/^v[0-9a-f]{12}$/);
    expect(a.root).not.toBe(b.root);
  });
  it("slotsAreNotPolicyOrder", () => {
    const k = generateKeyPair().privateKey;
    let moved = false;
    for (let i = 0; i < 20 && !moved; i++) {
      const dirs = buildPolicy(demo, 8, k).bundles.orders!.proofs["gateway/orders/payment"]!.dirs;
      moved = dirs !== "LLLLLLLL";
    }
    expect(moved).toBe(true);
  });
});
