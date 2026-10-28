// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { encode } from "../src/b64url.ts";
import { decodeChainV1, encodeChainV1 } from "../src/chain.ts";
import { concat, generateKeyPair, randomBytes, sha256, utf8 } from "../src/crypto.ts";
import { buildTree, encodeProof } from "../src/merkle.ts";
import { NonceCache } from "../src/nonce.ts";
import { signRootOldForm } from "../src/root.ts";
import { signStampV1, type StampV1 } from "../src/stamp.ts";
import { verifyV1, type V1Config } from "../src/verify-v1.ts";
import { decode } from "../src/b64url.ts";
import { verifyRoot } from "../src/root.ts";

const NOW = 1_000_000;

// Core takes the expected binding as an input, so the test builds it independently of any transport package.
function bindHttp(method: string, path: string, body: Uint8Array): string {
  return encode(sha256(concat(utf8(method), new Uint8Array([0x0a]), utf8(path), new Uint8Array([0x0a]), body)));
}
const routes = ["gateway/orders/payment", "gateway/orders", "gateway/search"];

function world() {
  const gateway = generateKeyPair();
  const orders = generateKeyPair();
  const search = generateKeyPair();
  const policy = generateKeyPair();
  const tree = buildTree(routes.map((path) => ({ salt: randomBytes(16), path })), 8, "v1");
  const signedRoot = signRootOldForm(tree.root, "v1", policy.privateKey);
  if (!verifyRoot(signedRoot, policy.publicKey)) throw new Error("bad root");
  const body = utf8('{"amount":100}');
  const bindToPayment = bindHttp("POST", "/pay", body);
  const gatewayStamp = (): StampV1 =>
    signStampV1({ svc: "gateway", inst: "gw-1", rid: "rid-1", ts: NOW, bind: "bindGatewayToOrders", prev: "" }, gateway.privateKey);
  const validChain = (): StampV1[] => {
    const s0 = gatewayStamp();
    return [s0, signStampV1({ svc: "orders", inst: "ord-1", rid: "rid-1", ts: NOW, bind: bindToPayment, prev: s0.sig }, orders.privateKey)];
  };
  const cfg = (): V1Config => ({
    keyring: { gateway: gateway.publicKey, orders: orders.publicKey, search: search.publicKey },
    root: decode(signedRoot.root),
    rootId: signedRoot.rootId,
    allowedOrigins: ["gateway"],
    maxAgeMs: 5000,
    nonces: new NonceCache(60_000),
    now: NOW,
  });
  const proof = encodeProof(tree.proofFor("gateway/orders/payment"));
  const req = (chain: StampV1[] | undefined, over: { chainHeader?: string; proofHeader?: string; body?: Uint8Array } = {}) => ({
    chainHeader: chain ? encodeChainV1(chain) : undefined,
    proofHeader: proof,
    expectedBind: bindHttp("POST", "/pay", over.body ?? body),
    receiver: "payment",
    ...Object.fromEntries(Object.entries(over).filter(([k]) => k !== "body")),
  });
  return { gateway, orders, search, tree, body, bindToPayment, gatewayStamp, validChain, cfg, proof, req };
}

describe("verifyV1", () => {
  it("validPasses", () => {
    const w = world();
    expect(verifyV1(w.req(w.validChain()), w.cfg()).reason).toBe("OK");
  });
  it("missingChain", () => {
    const w = world();
    expect(verifyV1(w.req(undefined), w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("emptyChain", () => {
    const w = world();
    expect(verifyV1(w.req([]), w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("unparseableChain", () => {
    const w = world();
    expect(verifyV1(w.req(undefined, { chainHeader: "!!!garbage!!!" }), w.cfg()).reason).toBe("CHAIN_MISSING");
    expect(verifyV1(w.req(undefined, { chainHeader: encode(utf8('[{"svc":1}]')) }), w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("nonOriginFirst", () => {
    const w = world();
    const s = signStampV1({ svc: "search", inst: "s-1", rid: "rid-1", ts: NOW, bind: "b", prev: "" }, w.search.privateKey);
    expect(verifyV1(w.req([s]), w.cfg()).reason).toBe("BAD_ORIGIN");
  });
  it("forgedGatewayStamp", () => {
    const w = world();
    const f = signStampV1({ svc: "gateway", inst: "evil", rid: "rid-1", ts: NOW, bind: w.bindToPayment, prev: "" }, w.search.privateKey);
    expect(verifyV1(w.req([f]), w.cfg()).reason).toBe("BAD_SIGNATURE");
  });
  it("unknownService", () => {
    const w = world();
    const s0 = w.gatewayStamp();
    const s1 = signStampV1({ svc: "payment", inst: "p", rid: "rid-1", ts: NOW, bind: w.bindToPayment, prev: s0.sig }, w.orders.privateKey);
    expect(verifyV1(w.req([s0, s1]), w.cfg()).reason).toBe("BAD_SIGNATURE");
  });
  it("brokenPrevLink", () => {
    const w = world();
    const s0 = w.gatewayStamp();
    const s1 = signStampV1({ svc: "orders", inst: "ord-1", rid: "rid-1", ts: NOW, bind: w.bindToPayment, prev: encode(utf8("not-s0-sig")) }, w.orders.privateKey);
    expect(verifyV1(w.req([s0, s1]), w.cfg()).reason).toBe("BROKEN_LINK");
  });
  it("ridMismatch", () => {
    const w = world();
    const s0 = w.gatewayStamp();
    const s1 = signStampV1({ svc: "orders", inst: "ord-1", rid: "rid-DIFFERENT", ts: NOW, bind: w.bindToPayment, prev: s0.sig }, w.orders.privateKey);
    expect(verifyV1(w.req([s0, s1]), w.cfg()).reason).toBe("RID_MISMATCH");
  });
  it("olderThanMaxAge", () => {
    const w = world();
    const s0 = signStampV1({ svc: "gateway", inst: "gw-1", rid: "rid-1", ts: NOW - 6000, bind: "bGW", prev: "" }, w.gateway.privateKey);
    const s1 = signStampV1({ svc: "orders", inst: "ord-1", rid: "rid-1", ts: NOW - 6000, bind: w.bindToPayment, prev: s0.sig }, w.orders.privateKey);
    expect(verifyV1(w.req([s0, s1]), w.cfg()).reason).toBe("EXPIRED");
  });
  it("bodyChanged", () => {
    const w = world();
    expect(verifyV1(w.req(w.validChain(), { body: utf8('{"amount":999}') }), w.cfg()).reason).toBe("BINDING_MISMATCH");
  });
  it("secondUse", () => {
    const w = world();
    const cfg = w.cfg();
    expect(verifyV1(w.req(w.validChain()), cfg).ok).toBe(true);
    expect(verifyV1(w.req(w.validChain()), cfg).reason).toBe("REPLAY");
  });
  it("forwardedGatewaySearchChain", () => {
    const w = world();
    const s0 = w.gatewayStamp();
    const s1 = signStampV1({ svc: "search", inst: "s-1", rid: "rid-1", ts: NOW, bind: w.bindToPayment, prev: s0.sig }, w.search.privateKey);
    const proof = encodeProof(w.tree.proofFor("gateway/search"));
    expect(verifyV1(w.req([s0, s1], { proofHeader: proof }), w.cfg()).reason).toBe("PATH_NOT_ALLOWED");
  });
  it("missingProof", () => {
    const w = world();
    expect(verifyV1(w.req(w.validChain(), { proofHeader: undefined }), w.cfg()).reason).toBe("PATH_NOT_ALLOWED");
  });
  it("garbageProof", () => {
    const w = world();
    expect(verifyV1(w.req(w.validChain(), { proofHeader: "!!!" }), w.cfg()).reason).toBe("PATH_NOT_ALLOWED");
  });
  it("proofForWrongRootId", () => {
    const w = world();
    const p = { ...w.tree.proofFor("gateway/orders/payment"), rootId: "v-OLD" };
    expect(verifyV1(w.req(w.validChain(), { proofHeader: encodeProof(p) }), w.cfg()).reason).toBe("PATH_NOT_ALLOWED");
  });
  it("suspectIsLastStamp", () => {
    const w = world();
    const r = verifyV1(w.req(w.validChain(), { body: utf8("x") }), w.cfg());
    expect(r).toEqual({ ok: false, reason: "BINDING_MISMATCH", suspectSvc: "", suspectInst: "" });
    const ok = verifyV1(w.req(w.validChain()), w.cfg());
    expect([ok.suspectSvc, ok.suspectInst]).toEqual(["orders", "ord-1"]);
    const denied = verifyV1(w.req(w.validChain(), { proofHeader: "!!!" }), w.cfg());
    expect(denied).toEqual({ ok: false, reason: "PATH_NOT_ALLOWED", suspectSvc: "orders", suspectInst: "ord-1" });
  });
  it("suspectIsEmptyForEveryOtherRejection", () => {
    const w = world();
    const cases: [string, ReturnType<typeof verifyV1>][] = [
      ["CHAIN_MISSING", verifyV1(w.req(undefined), w.cfg())],
      ["BAD_ORIGIN", verifyV1(w.req(w.validChain()), { ...w.cfg(), allowedOrigins: ["other"] })],
      ["BAD_SIGNATURE", verifyV1(w.req(w.validChain()), { ...w.cfg(), keyring: { ...w.cfg().keyring, orders: w.search.publicKey } })],
      ["BROKEN_LINK", verifyV1(w.req([w.gatewayStamp(), signStampV1({ svc: "orders", inst: "ord-1", rid: "rid-1", ts: NOW, bind: w.bindToPayment, prev: "x" }, w.orders.privateKey)]), w.cfg())],
      ["RID_MISMATCH", verifyV1(w.req([w.gatewayStamp(), signStampV1({ svc: "orders", inst: "ord-1", rid: "rid-2", ts: NOW, bind: w.bindToPayment, prev: w.gatewayStamp().sig }, w.orders.privateKey)]), w.cfg())],
      ["EXPIRED", verifyV1(w.req(w.validChain()), { ...w.cfg(), now: NOW + 5001 })],
      ["BINDING_MISMATCH", verifyV1(w.req(w.validChain(), { body: utf8("x") }), w.cfg())],
    ];
    const cfg = w.cfg();
    verifyV1(w.req(w.validChain()), cfg);
    cases.push(["REPLAY", verifyV1(w.req(w.validChain()), cfg)]);
    for (const [reason, r] of cases) {
      expect(r.reason).toBe(reason);
      expect([reason, r.suspectSvc, r.suspectInst]).toEqual([reason, "", ""]);
    }
  });
  it.each(["svc", "inst", "rid", "ts", "bind", "prev", "sig"] as const)("tampering %s is rejected", (field) => {
    const w = world();
    const [s0, good] = w.validChain() as [StampV1, StampV1];
    const t = { ...good } as Record<string, string | number>;
    t[field] = field === "ts" ? good.ts + 1 : field === "sig" ? encode(randomBytes(64)) : field === "svc" ? "payment" : "tampered";
    expect(verifyV1(w.req([s0, t as unknown as StampV1]), w.cfg()).ok).toBe(false);
  });
  it("chainRoundTripsInJavaFieldOrder", () => {
    const w = world();
    const chain = w.validChain();
    expect(decodeChainV1(encodeChainV1(chain))).toEqual(chain);
    expect(Buffer.from(decode(encodeChainV1(chain))).toString().startsWith('[{"svc":"gateway","inst":"gw-1","rid":"rid-1","ts":1000000,"bind"')).toBe(true);
  });
});
