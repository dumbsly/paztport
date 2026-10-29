// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { generateKeyPair } from "../../src/crypto/crypto.ts";
import { verifyProof } from "../../src/policy/merkle.ts";
import { buildPolicy } from "../../src/policy/policy.ts";
import { verifyRoot } from "../../src/policy/root.ts";
import { decode } from "../../src/encoding/b64url.ts";

const demo = [["gateway", "orders", "payment"], ["gateway", "orders"], ["gateway", "search"]];
const NOT_AFTER = 4_102_444_800_000;

describe("policy", () => {
  it("bundlesGoToSecondToLastHop", () => {
    const { bundles, signedRoot } = buildPolicy(demo, 8, generateKeyPair().privateKey, NOT_AFTER);
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
    expect(() => buildPolicy([["solo"]], 8, generateKeyPair().privateKey, NOT_AFTER)).toThrow();
  });
  it("signedRootVerifies", () => {
    const kp = generateKeyPair();
    const { signedRoot } = buildPolicy(demo, 8, kp.privateKey, NOT_AFTER);
    // the new form, until the given notAfter, with nothing else to fill in
    expect(Object.keys(signedRoot)).toEqual(["rootId", "root", "sig", "notAfter"]);
    expect(signedRoot.notAfter).toBe(NOT_AFTER);
    expect(verifyRoot(signedRoot, kp.publicKey)).toBe(true);
    expect(verifyRoot({ ...signedRoot, notAfter: NOT_AFTER + 1 }, kp.publicKey)).toBe(false);
    expect(verifyRoot({ ...signedRoot, rootId: "vother" }, kp.publicKey)).toBe(false);
    expect(verifyRoot(signedRoot, generateKeyPair().publicKey)).toBe(false);
  });
  it("refusesAMissingOrBadNotAfter", () => {
    for (const bad of [undefined, 1.5, -1, 2 ** 53]) {
      expect(() => buildPolicy(demo, 8, generateKeyPair().privateKey, bad as unknown as number), String(bad)).toThrow(TypeError);
    }
  });
  it("rootIdIsRandomPerBuild", () => {
    const k = generateKeyPair().privateKey;
    const a = buildPolicy(demo, 8, k, NOT_AFTER).signedRoot;
    const b = buildPolicy(demo, 8, k, NOT_AFTER).signedRoot;
    expect(a.rootId).not.toBe(b.rootId);
    expect(a.rootId).toMatch(/^v[0-9a-f]{12}$/);
    expect(b.rootId).toMatch(/^v[0-9a-f]{12}$/);
    expect(a.root).not.toBe(b.root);
  });
  it("slotsAreNotPolicyOrder", () => {
    const k = generateKeyPair().privateKey;
    let moved = false;
    for (let i = 0; i < 20 && !moved; i++) {
      const dirs = buildPolicy(demo, 8, k, NOT_AFTER).bundles.orders!.proofs["gateway/orders/payment"]!.dirs;
      moved = dirs !== "LLLLLLLL";
    }
    expect(moved).toBe(true);
  });
});
