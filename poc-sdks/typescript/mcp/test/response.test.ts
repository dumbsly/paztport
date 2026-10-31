// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  NonceCache, bindResponse, bindResult, buildTree, generateKeyPair, newContentId, randomBytes, signStampV3,
} from "@paztport/core";
import type { ContentLabel, V3Config } from "@paztport/core";
import { META_ATTESTATION, verifyMcpResponse } from "../src/index.ts";

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
  const response = (): Record<string, unknown> => {
    const body: Record<string, unknown> = { content: [{ type: "text", text: "hello" }] };
    const resultHash = bindResult(body);
    const mk = (svc: string, rcv: string, bind: string, prev: string) =>
      signStampV3({ svc, inst: svc + "-1", rid: "rid-1", ts: NOW, sess: SESS, rcv, bind, infl: "", prev }, keys.privateKey);
    const s0 = mk("mcp-entry", "github-tools", "b0", "");
    const s1 = mk("github-tools", "pi", bindResponse(resultHash, "call-1", labels), s0.sig);
    return {
      ...body,
      _meta: { [META_ATTESTATION]: { chain: [s0, s1], proof: tree.proofFor(ROUTE), labels, resultHash } },
    };
  };
  return { keys, tree, cfg, labels, response };
}

describe("verifyMcpResponse", () => {
  it("validResponseReturnsLabels", () => {
    const w = world();
    const r = verifyMcpResponse(w.response(), CALL, w.cfg());
    expect(r.result.ok).toBe(true);
    expect(r.result.reason).toBe("OK");
    expect(r.labels).toEqual(w.labels);
  });
  it("resultBodyEdited", () => {
    const w = world();
    const resp = w.response();
    resp.content = [{ type: "text", text: "evil" }];
    const r = verifyMcpResponse(resp, CALL, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    expect(r.labels).toEqual([]);
  });
  it("labelsStrippedIsBindingMismatch", () => {
    const w = world();
    const resp = w.response();
    (resp._meta as any)[META_ATTESTATION].labels = [];
    const r = verifyMcpResponse(resp, CALL, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    expect(r.labels).toEqual([]);
  });
  it("missingAttestation", () => {
    const w = world();
    expect(verifyMcpResponse({ content: [] }, CALL, w.cfg()).result.reason).toBe("CHAIN_MISSING");
    expect(verifyMcpResponse({ content: [], _meta: {} }, CALL, w.cfg()).result.reason).toBe("CHAIN_MISSING");
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
      const r = verifyMcpResponse({ content: [], _meta: { [META_ATTESTATION]: v } }, CALL, w.cfg());
      expect(r.result.reason).toBe("CHAIN_MISSING");
      expect(r.labels).toEqual([]);
    }
    expect(verifyMcpResponse({ _meta: "x" }, CALL, w.cfg()).result.reason).toBe("CHAIN_MISSING");
  });
  it("labelsDroppedOnFailure", () => {
    const w = world();
    const r = verifyMcpResponse(w.response(), CALL, w.cfg({ sess: "other" }));
    expect(r.result.ok).toBe(false);
    expect(r.labels).toEqual([]);
  });
  it("responseForOtherCallRejected", () => {
    const w = world();
    const wrongRid = verifyMcpResponse(w.response(), { ...CALL, rid: "rid-2" }, w.cfg());
    expect(wrongRid.result.reason).toBe("RID_MISMATCH");
    expect(wrongRid.labels).toEqual([]);
    const wrongCall = verifyMcpResponse(w.response(), { ...CALL, toolCallId: "call-2" }, w.cfg());
    expect(wrongCall.result.reason).toBe("BINDING_MISMATCH");
    expect(wrongCall.labels).toEqual([]);
  });
  it("responseReplayRejected", () => {
    const w = world();
    const cfg = w.cfg();
    const resp = w.response();
    expect(verifyMcpResponse(resp, CALL, cfg).result.ok).toBe(true);
    const again = verifyMcpResponse(resp, CALL, cfg);
    expect(again.result.reason).toBe("REPLAY");
    expect(again.labels).toEqual([]);
  });
  it("responseShortTtlIsReplay", () => {
    const w = world();
    const nonces = new NonceCache(1000);
    const r = verifyMcpResponse(w.response(), CALL, w.cfg({ nonces }));
    expect(r.result.reason).toBe("REPLAY");
    expect(r.labels).toEqual([]);
    expect(nonces.size).toBe(0);
  });
  it("invalidCallFieldsChainMissing", () => {
    const w = world();
    expect(verifyMcpResponse(w.response(), { ...CALL, toolCallId: "a\nb" }, w.cfg()).result.reason).toBe("CHAIN_MISSING");
    expect(verifyMcpResponse(w.response(), { ...CALL, rid: 1 as unknown as string, toolCallId: "c" }, w.cfg()).result.reason).toBe("CHAIN_MISSING");
  });
  it("aStampWhoseVersionIsNotThreeIsChainMissing", () => {
    const w = world();
    for (const v of [1, 2, 4]) {
      for (const at of [0, 1]) {
        const resp = w.response();
        ((resp._meta as any)[META_ATTESTATION].chain as Record<string, unknown>[])[at]!.v = v;
        const r = verifyMcpResponse(resp, CALL, w.cfg());
        expect(r.result.reason, `v ${v} at ${at}`).toBe("CHAIN_MISSING");
        expect(r.labels).toEqual([]);
      }
    }
  });
});
