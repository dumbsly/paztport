// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  INFLUENCE, NonceCache, bindResponse, bindResult, buildTree, commitBlock, extensionSettings, generateKeyPair,
  influenceBlock, newContentId, randomBytes, readAttestation, signStamp, writeToken,
} from "@paztport/core";
import type { ContentLabel, JsonValue, VerifierConfig } from "@paztport/core";
import { META_ATTESTATION, verifyMcpResponse } from "../src/index.ts";
import { retoken, tokenOf } from "./helpers/client.ts";

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
  const cfg = (over: Partial<Omit<VerifierConfig, "nonceKey">> = {}): Omit<VerifierConfig, "nonceKey"> => ({
    keyrings: [{ keys: { "mcp-entry": keys.publicKey, "github-tools": keys.publicKey }, notAfter: 4_102_444_800_000 }],
    roots: [{ root: tree.root, rootId: tree.rootId, notAfter: 4_102_444_800_000 }],
    allowedOrigins: ["mcp-entry"],
    sess: SESS,
    nonces: new NonceCache(60_000),
    now: NOW,
    policyNotAfter: 4_102_444_800_000,
    extensions: extensionSettings([INFLUENCE]),
    ...over,
  });
  const labels: ContentLabel[] = [{ cls: "third-party", cid: newContentId() }];
  // as a server that acts on influence attests: both blocks name it, the last holds the label and requires it
  const blocks = [influenceBlock([]), influenceBlock(labels, [INFLUENCE])];
  const response = (): Record<string, unknown> => {
    const body: Record<string, unknown> = { content: [{ type: "text", text: "hello" }] };
    const resultHash = bindResult(body);
    const mk = (svc: string, rcv: string, bind: string, ext: string, prev: string) =>
      signStamp({ svc, inst: svc + "-1", rid: "rid-1", ts: NOW, sess: SESS, rcv, bind, ext, prev }, keys.privateKey);
    const s0 = mk("mcp-entry", "github-tools", "b0", commitBlock(blocks[0]!), "");
    const s1 = mk("github-tools", "pi", bindResponse(resultHash, "call-1"), commitBlock(blocks[1]!), s0.sig);
    const attestation = { blocks, chain: [s0, s1], proof: tree.proofFor(ROUTE), resultHash };
    return { ...body, _meta: { [META_ATTESTATION]: writeToken(attestation as unknown as JsonValue) } };
  };
  return { keys, tree, cfg, labels, response };
}

describe("verifyMcpResponse", () => {
  it("aValidResponseHandsOverItsBlocksItems", () => {
    const w = world();
    const r = verifyMcpResponse(w.response(), CALL, w.cfg());
    expect(r).toEqual({
      ok: true, reason: "OK", suspectSvc: "github-tools", suspectInst: "github-tools-1",
      handOver: new Map([[INFLUENCE, [{ svc: "mcp-entry", items: [] }, { svc: "github-tools", items: w.labels }]]]),
    });
  });
  it("resultBodyEdited", () => {
    const w = world();
    const resp = w.response();
    resp.content = [{ type: "text", text: "evil" }];
    const r = verifyMcpResponse(resp, CALL, w.cfg());
    expect(r).toMatchObject({ reason: "BINDING_MISMATCH", handOver: null });
  });
  it("aLabelStrippedIsExtensionMismatch", () => {
    const w = world();
    const resp = w.response();
    const meta = resp._meta as Record<string, string>;
    meta[META_ATTESTATION] = retoken(meta[META_ATTESTATION]!, (att) => ({
      ...att, blocks: [att.blocks[0], { ...att.blocks[1], items: { influence: [] } }],
    }));
    const r = verifyMcpResponse(resp, CALL, w.cfg());
    expect(r).toMatchObject({ reason: "EXTENSION_MISMATCH", handOver: null });
  });
  it("aClientThatDoesNotActOnInfluenceRefusesTheLabelledResponse", () => {
    const w = world();
    const r = verifyMcpResponse(w.response(), CALL, w.cfg({ extensions: extensionSettings([]) }));
    expect(r).toMatchObject({ reason: "EXTENSION_REQUIRED", handOver: null });
  });
  it("missingAttestation", () => {
    const w = world();
    expect(verifyMcpResponse({ content: [] }, CALL, w.cfg())).toEqual({
      ok: false, reason: "CHAIN_MISSING", suspectSvc: "", suspectInst: "", handOver: null,
    });
    expect(verifyMcpResponse({ content: [], _meta: {} }, CALL, w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("malformedAttestationFields", () => {
    const w = world();
    const good: any = readAttestation((w.response()._meta as Record<string, string>)[META_ATTESTATION]!);
    const values: unknown[] = [
      null,
      "x",
      { ...good, chain: {} },
      { ...good, blocks: "x" },
      { ...good, blocks: null },
      { ...good, blocks: [null, good.blocks[1]] },
      { ...good, blocks: [good.blocks[0], { ...good.blocks[1], requires: ["b", "a"] }] },
      { ...good, resultHash: 5 },
      { ...good, extra: 1 },
      { ...good, proof: { ...good.proof, dirs: "X" } },
      { ...good, extra: 1.5 },
    ];
    // the token of each, and the attestation itself, which is not a token
    for (const v of [...values.map(tokenOf), "", "not a token", good, 5]) {
      const r = verifyMcpResponse({ content: [], _meta: { [META_ATTESTATION]: v } }, CALL, w.cfg());
      expect(r).toMatchObject({ reason: "CHAIN_MISSING", handOver: null });
    }
    expect(verifyMcpResponse({ _meta: "x" }, CALL, w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("nothingIsHandedOverOnFailure", () => {
    const w = world();
    const r = verifyMcpResponse(w.response(), CALL, w.cfg({ sess: "other" }));
    expect(r).toMatchObject({ ok: false, handOver: null });
  });
  it("responseForOtherCallRejected", () => {
    const w = world();
    const wrongRid = verifyMcpResponse(w.response(), { ...CALL, rid: "rid-2" }, w.cfg());
    expect(wrongRid).toMatchObject({ reason: "RID_MISMATCH", handOver: null });
    const wrongCall = verifyMcpResponse(w.response(), { ...CALL, toolCallId: "call-2" }, w.cfg());
    expect(wrongCall).toMatchObject({ reason: "BINDING_MISMATCH", handOver: null });
  });
  it("responseReplayRejected", () => {
    const w = world();
    const cfg = w.cfg();
    const resp = w.response();
    expect(verifyMcpResponse(resp, CALL, cfg).ok).toBe(true);
    const again = verifyMcpResponse(resp, CALL, cfg);
    expect(again).toMatchObject({ reason: "REPLAY", handOver: null });
  });
  it("responseShortTtlIsReplay", () => {
    const w = world();
    const nonces = new NonceCache(1000);
    const r = verifyMcpResponse(w.response(), CALL, w.cfg({ nonces }));
    expect(r).toMatchObject({ reason: "REPLAY", handOver: null });
    expect(nonces.size).toBe(0);
  });
  it("invalidCallFieldsChainMissing", () => {
    const w = world();
    expect(verifyMcpResponse(w.response(), { ...CALL, toolCallId: "a\nb" }, w.cfg()).reason).toBe("CHAIN_MISSING");
    expect(verifyMcpResponse(w.response(), { ...CALL, rid: 1 as unknown as string, toolCallId: "c" }, w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("aStampWhoseVersionIsNotFourIsChainMissing", () => {
    const w = world();
    for (const v of [1, 2, 3, 5]) {
      for (const at of [0, 1]) {
        const resp = w.response();
        const meta = resp._meta as Record<string, string>;
        meta[META_ATTESTATION] = retoken(meta[META_ATTESTATION]!, (att) => {
          att.chain[at].v = v;
          return att;
        });
        const r = verifyMcpResponse(resp, CALL, w.cfg());
        expect(r.reason, `v ${v} at ${at}`).toBe("CHAIN_MISSING");
        expect(r.handOver).toBeNull();
      }
    }
  });
});
