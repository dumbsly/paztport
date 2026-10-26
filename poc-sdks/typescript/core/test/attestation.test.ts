// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindResponse, newContentId, verifyResponse, type ContentLabel } from "../src/attestation.ts";
import { bindResult } from "../src/binding.ts";
import { generateKeyPair, randomBytes } from "../src/crypto.ts";
import { buildTree } from "../src/merkle.ts";
import { NonceCache } from "../src/nonce.ts";
import { signStampV2 } from "../src/stamp.ts";
import type { V2Config } from "../src/verify-v2.ts";

const NOW = 10_000_000;
const SESS = "sess-1";
const CALL = { rid: "rid-1", toolCallId: "call-1" };
const ROUTE = "mcp-entry/github-tools";

function world() {
  const keys = generateKeyPair();
  const tree = buildTree(
    [ROUTE, "mcp-entry/other"].map((path) => ({ salt: randomBytes(16), path })),
    8,
    "v1",
  );
  const cfg = (over: Partial<Omit<V2Config, "nonceKey">> = {}): Omit<V2Config, "nonceKey"> => ({
    keyring: { "mcp-entry": keys.publicKey, "github-tools": keys.publicKey },
    root: tree.root,
    rootId: tree.rootId,
    allowedOrigins: ["mcp-entry"],
    sess: SESS,
    nonces: new NonceCache(60_000),
    now: NOW,
    ...over,
  });
  const labels: ContentLabel[] = [{ cls: "third-party", cid: newContentId() }];
  const response = (): { body: Record<string, unknown>; att: unknown } => {
    const body: Record<string, unknown> = { content: [{ type: "text", text: "hello" }] };
    const resultHash = bindResult(body);
    const mk = (svc: string, bind: string, prev: string) =>
      signStampV2({ svc, inst: svc + "-1", rid: "rid-1", ts: NOW, sess: SESS, bind, infl: "", prev }, keys.privateKey);
    const s0 = mk("mcp-entry", "b0", "");
    const s1 = mk("github-tools", bindResponse(resultHash, "call-1", labels), s0.sig);
    return { body, att: { chain: [s0, s1], proof: tree.proofFor(ROUTE), labels, resultHash } };
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
    const r = verifyResponse(undefined, { ...body, _meta: { attestation: att } }, CALL, w.cfg());
    expect(r.result.reason).toBe("CHAIN_MISSING");
    expect(r.labels).toEqual([]);
  });
  it("malformedAttestationIsChainMissing", () => {
    const w = world();
    for (const v of [null, "x", [], { chain: {} }]) {
      expect(verifyResponse(v, { content: [] }, CALL, w.cfg()).result.reason).toBe("CHAIN_MISSING");
    }
  });
});

describe("response binding", () => {
  it("metaExcludedFromHash", () => {
    const body = { content: [{ type: "text", text: "x" }] };
    expect(bindResult({ ...body, _meta: { a: 1 } })).toBe(bindResult({ ...body, _meta: { b: [2] } }));
    expect(bindResult({ ...body, _meta: { a: 1 } })).toBe(bindResult(body));
  });
});
