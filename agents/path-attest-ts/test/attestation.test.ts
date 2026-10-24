// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindResponse, newContentId, verifyResponse, type ContentLabel } from "../src/attestation.ts";
import { bindResult } from "../src/binding.ts";
import { generateKeyPair, randomBytes } from "../src/crypto.ts";
import { buildTree } from "../src/merkle.ts";
import { NonceCache } from "../src/nonce.ts";
import { META_ATTESTATION } from "../src/meta.ts";
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
  const response = (): Record<string, unknown> => {
    const body: Record<string, unknown> = { content: [{ type: "text", text: "hello" }] };
    const resultHash = bindResult(body);
    const mk = (svc: string, bind: string, prev: string) =>
      signStampV2({ svc, inst: svc + "-1", rid: "rid-1", ts: NOW, sess: SESS, bind, infl: "", prev }, keys.privateKey);
    const s0 = mk("mcp-entry", "b0", "");
    const s1 = mk("github-tools", bindResponse(resultHash, "call-1", labels), s0.sig);
    return {
      ...body,
      _meta: { [META_ATTESTATION]: { chain: [s0, s1], proof: tree.proofFor(ROUTE), labels, resultHash } },
    };
  };
  return { keys, tree, cfg, labels, response };
}

describe("verifyResponse", () => {
  it("validResponseReturnsLabels", () => {
    const w = world();
    const r = verifyResponse(w.response(), CALL, w.cfg());
    expect(r.result.ok).toBe(true);
    expect(r.result.reason).toBe("OK");
    expect(r.labels).toEqual(w.labels);
  });
  it("resultBodyEdited", () => {
    const w = world();
    const resp = w.response();
    resp.content = [{ type: "text", text: "evil" }];
    const r = verifyResponse(resp, CALL, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    expect(r.labels).toEqual([]);
  });
  it("labelsStrippedIsBindingMismatch", () => {
    const w = world();
    const resp = w.response();
    (resp._meta as any)[META_ATTESTATION].labels = [];
    const r = verifyResponse(resp, CALL, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    expect(r.labels).toEqual([]);
  });
  it("missingAttestation", () => {
    const w = world();
    expect(verifyResponse({ content: [] }, CALL, w.cfg()).result.reason).toBe("CHAIN_MISSING");
    expect(verifyResponse({ content: [], _meta: {} }, CALL, w.cfg()).result.reason).toBe("CHAIN_MISSING");
  });
  it("malformedAttestationFields", () => {
    const w = world();
    const good = (w.response()._meta as any)[META_ATTESTATION];
    const variants: unknown[] = [
      null,
      "x",
      { ...good, chain: {} },
      { ...good, labels: "x" },
      { ...good, labels: [{ cls: "bogus", cid: "c" }] },
      { ...good, labels: [{ cls: "public", cid: 1 }] },
      { ...good, labels: [null] },
      { ...good, resultHash: 5 },
    ];
    for (const v of variants) {
      const r = verifyResponse({ content: [], _meta: { [META_ATTESTATION]: v } }, CALL, w.cfg());
      expect(r.result.reason).toBe("CHAIN_MISSING");
      expect(r.labels).toEqual([]);
    }
    expect(verifyResponse({ _meta: "x" }, CALL, w.cfg()).result.reason).toBe("CHAIN_MISSING");
  });
  it("labelsDroppedOnFailure", () => {
    const w = world();
    const r = verifyResponse(w.response(), CALL, w.cfg({ sess: "other" }));
    expect(r.result.ok).toBe(false);
    expect(r.labels).toEqual([]);
  });
  it("responseForOtherCallRejected", () => {
    const w = world();
    const wrongRid = verifyResponse(w.response(), { rid: "rid-2", toolCallId: "call-1" }, w.cfg());
    expect(wrongRid.result.reason).toBe("RID_MISMATCH");
    expect(wrongRid.labels).toEqual([]);
    const wrongCall = verifyResponse(w.response(), { rid: "rid-1", toolCallId: "call-2" }, w.cfg());
    expect(wrongCall.result.reason).toBe("BINDING_MISMATCH");
    expect(wrongCall.labels).toEqual([]);
  });
  it("responseReplayRejected", () => {
    const w = world();
    const cfg = w.cfg();
    const resp = w.response();
    expect(verifyResponse(resp, CALL, cfg).result.ok).toBe(true);
    const again = verifyResponse(resp, CALL, cfg);
    expect(again.result.reason).toBe("REPLAY");
    expect(again.labels).toEqual([]);
  });
  it("responseShortTtlIsReplay", () => {
    const w = world();
    const nonces = new NonceCache(1000);
    const r = verifyResponse(w.response(), CALL, w.cfg({ nonces }));
    expect(r.result.reason).toBe("REPLAY");
    expect(r.labels).toEqual([]);
    expect(nonces.size).toBe(0);
  });
  it("invalidCallFieldsChainMissing", () => {
    const w = world();
    expect(verifyResponse(w.response(), { rid: "rid-1", toolCallId: "a\nb" }, w.cfg()).result.reason).toBe("CHAIN_MISSING");
    expect(verifyResponse(w.response(), { rid: 1 as unknown as string, toolCallId: "c" }, w.cfg()).result.reason).toBe("CHAIN_MISSING");
  });
  it("metaExcludedFromHash", () => {
    const body = { content: [{ type: "text", text: "x" }] };
    expect(bindResult({ ...body, _meta: { a: 1 } })).toBe(bindResult({ ...body, _meta: { b: [2] } }));
    expect(bindResult({ ...body, _meta: { a: 1 } })).toBe(bindResult(body));
  });
});
