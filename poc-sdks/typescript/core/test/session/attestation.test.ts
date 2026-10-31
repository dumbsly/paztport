// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindResponse, newContentId, verifyResponse, type ContentLabel } from "../../src/session/attestation.ts";
import { bindResult } from "../../src/stamp/binding.ts";
import { generateKeyPair, randomBytes } from "../../src/crypto/crypto.ts";
import { buildTree } from "../../src/policy/merkle.ts";
import { NonceCache } from "../../src/verify/nonce.ts";
import { signStampV3 } from "../../src/stamp/stamp.ts";
import type { V3Config } from "../../src/verify/verify-v3.ts";

const NOW = 10_000_000;
const SESS = "sess-1";
const CALL = { rid: "rid-1", toolCallId: "call-1", receiver: "pi" };
const ROUTE = "mcp-entry/github-tools";

function world() {
  const keys = generateKeyPair();
  const tree = buildTree(
    [ROUTE, "mcp-entry/other"].map((path) => ({ salt: randomBytes(16), path })),
    8,
    "v1",
  );
  const cfg = (over: Partial<Omit<V3Config, "nonceKey">> = {}): Omit<V3Config, "nonceKey"> => ({
    keyring: { "mcp-entry": keys.publicKey, "github-tools": keys.publicKey },
    root: tree.root,
    rootId: tree.rootId,
    allowedOrigins: ["mcp-entry"],
    sess: SESS,
    nonces: new NonceCache(60_000),
    now: NOW,
    policyNotAfter: 4_102_444_800_000,
    ...over,
  });
  const labels: ContentLabel[] = [{ cls: "third-party", cid: newContentId() }];
  /** A response as the server signs it, its stamps naming github-tools and then the calling client. */
  const response = (withLabels: unknown[] = labels): { body: Record<string, unknown>; att: unknown } => {
    const body: Record<string, unknown> = { content: [{ type: "text", text: "hello" }] };
    const resultHash = bindResult(body);
    const mk = (svc: string, rcv: string, bind: string, prev: string) =>
      signStampV3({ svc, inst: svc + "-1", rid: "rid-1", ts: NOW, sess: SESS, rcv, bind, infl: "", prev }, keys.privateKey);
    const s0 = mk("mcp-entry", "github-tools", "b0", "");
    const s1 = mk("github-tools", "pi", bindResponse(resultHash, "call-1", withLabels as ContentLabel[]), s0.sig);
    return { body, att: { chain: [s0, s1], proof: tree.proofFor(ROUTE), labels: withLabels, resultHash } };
  };
  return { keys, tree, cfg, labels, response };
}

describe("verifyResponse", () => {
  it("takesTheAttestationObjectDirectly", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse(att, body, CALL, w.cfg());
    expect(r.result.ok).toBe(true);
    expect(r.labels).toEqual(w.labels);
  });
  it("neverReadsMetaFromTheResult", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse(undefined, { ...body, _meta: { "paztport/attestation": att } }, CALL, w.cfg());
    expect(r.result.reason).toBe("CHAIN_MISSING");
    expect(r.labels).toEqual([]);
  });
  it("malformedAttestationIsChainMissing", () => {
    const w = world();
    for (const v of [null, "x", [], { chain: {} }]) {
      expect(verifyResponse(v, { content: [] }, CALL, w.cfg()).result.reason).toBe("CHAIN_MISSING");
    }
  });
  it("aV3ResponseVerifiesForTheClientItEndsAt", () => {
    const w = world();
    const { body, att } = w.response();
    expect(verifyResponse(att, body, { ...CALL, receiver: "pi" }, w.cfg()).result).toEqual({ ok: true, reason: "OK", suspectSvc: "github-tools", suspectInst: "github-tools-1" });
  });
  it("aResponseForAnotherReceiverIsBindingMismatch", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse(att, body, { ...CALL, receiver: "search" }, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    expect(r.labels).toEqual([]);
  });
  it("aNonStringReceiverIsChainMissing", () => {
    const w = world();
    const { body, att } = w.response();
    expect(verifyResponse(att, body, { ...CALL, receiver: 1 as unknown as string }, w.cfg()).result.reason).toBe("CHAIN_MISSING");
  });
  it("aStampWhoseVersionIsNotThreeIsChainMissing", () => {
    const w = world();
    for (const v of [1, 2, 4]) {
      for (const at of [0, 1]) {
        const { body, att } = w.response();
        (att as { chain: Record<string, unknown>[] }).chain[at]!.v = v;
        const r = verifyResponse(att, body, CALL, w.cfg());
        expect(r.result.reason, `v ${v} at ${at}`).toBe("CHAIN_MISSING");
        expect(r.labels).toEqual([]);
      }
    }
  });
});
