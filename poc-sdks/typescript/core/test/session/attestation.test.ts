// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  bindResponse, newContentId, readAttestation, verifyResponse, type ContentLabel,
} from "../../src/session/attestation.ts";
import { bindResult } from "../../src/stamp/binding.ts";
import { encode } from "../../src/encoding/b64url.ts";
import { generateKeyPair, randomBytes, utf8 } from "../../src/crypto/crypto.ts";
import { buildTree } from "../../src/policy/merkle.ts";
import { NonceCache } from "../../src/verify/nonce.ts";
import { canonicalize, writeToken } from "../../src/encoding/jcs.ts";
import { signStamp } from "../../src/stamp/stamp.ts";
import type { JsonValue } from "../../src/encoding/json.ts";
import type { VerifierConfig } from "../../src/verify/verify-chain.ts";

const tok = (value: unknown): string => writeToken(value as JsonValue);

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
    ...over,
  });
  const labels: ContentLabel[] = [{ cls: "third-party", cid: newContentId() }];
  /** A response as the server signs it, its stamps naming github-tools and then the calling client. */
  const response = (withLabels: unknown[] = labels): { body: Record<string, unknown>; att: unknown } => {
    const body: Record<string, unknown> = { content: [{ type: "text", text: "hello" }] };
    const resultHash = bindResult(body);
    const mk = (svc: string, rcv: string, bind: string, prev: string) =>
      signStamp({ svc, inst: svc + "-1", rid: "rid-1", ts: NOW, sess: SESS, rcv, bind, infl: "", prev }, keys.privateKey);
    const s0 = mk("mcp-entry", "github-tools", "b0", "");
    const s1 = mk("github-tools", "pi", bindResponse(resultHash, "call-1", withLabels as ContentLabel[]), s0.sig);
    return { body, att: { chain: [s0, s1], proof: tree.proofFor(ROUTE), labels: withLabels, resultHash } };
  };
  return { keys, tree, cfg, labels, response };
}

describe("verifyResponse", () => {
  it("takesTheAttestationAsAToken", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse(tok(att), body, CALL, w.cfg());
    expect(r.result.ok).toBe(true);
    expect(r.labels).toEqual(w.labels);
  });
  it("neverReadsMetaFromTheResult", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse("", { ...body, _meta: { "paztport/attestation": att } }, CALL, w.cfg());
    expect(r.result.reason).toBe("CHAIN_MISSING");
    expect(r.labels).toEqual([]);
  });
  it("aCallIdWithALoneSurrogateIsBindingMismatchAndDoesNotThrow", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse(tok(att), body, { ...CALL, toolCallId: "call-1\ud800" }, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    expect(r.labels).toEqual([]);
  });
  it("malformedAttestationIsChainMissing", () => {
    const w = world();
    for (const v of [null, "x", [], { chain: {} }]) {
      expect(verifyResponse(tok(v), { content: [] }, CALL, w.cfg()).result.reason).toBe("CHAIN_MISSING");
    }
  });
  it("aResponseVerifiesForTheClientItEndsAt", () => {
    const w = world();
    const { body, att } = w.response();
    expect(verifyResponse(tok(att), body, { ...CALL, receiver: "pi" }, w.cfg()).result).toEqual({
      ok: true, reason: "OK", suspectSvc: "github-tools", suspectInst: "github-tools-1",
    });
  });
  it("aResponseForAnotherReceiverIsBindingMismatch", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse(tok(att), body, { ...CALL, receiver: "search" }, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    expect(r.labels).toEqual([]);
  });
  it("aResultHoldingALoneSurrogateIsBindingMismatch", () => {
    const w = world();
    const { att } = w.response();
    const r = verifyResponse(tok(att), { content: [{ type: "text", text: "\ud800" }] }, CALL, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    expect(r.labels).toEqual([]);
  });
  it("aNonStringReceiverIsChainMissing", () => {
    const w = world();
    const { body, att } = w.response();
    const call = { ...CALL, receiver: 1 as unknown as string };
    expect(verifyResponse(tok(att), body, call, w.cfg()).result.reason).toBe("CHAIN_MISSING");
  });
  it("aStampWhoseVersionIsNotThreeIsChainMissing", () => {
    const w = world();
    for (const v of [1, 2, 4]) {
      for (const at of [0, 1]) {
        const { body, att } = w.response();
        (att as { chain: Record<string, unknown>[] }).chain[at]!.v = v;
        const r = verifyResponse(tok(att), body, CALL, w.cfg());
        expect(r.result.reason, `v ${v} at ${at}`).toBe("CHAIN_MISSING");
        expect(r.labels).toEqual([]);
      }
    }
  });

  it("anAttestationWithAMemberItDoesNotHaveIsChainMissing", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse(tok({ ...(att as object), extra: 1 }), body, CALL, w.cfg());
    expect(r.result.reason).toBe("CHAIN_MISSING");
    expect(r.labels).toEqual([]);
    expect(() => readAttestation(tok({ ...(att as object), extra: 1 }))).toThrow("a member the object does not define");
  });
  it("aLabelWithAMemberLabelsDoNotHaveIsChainMissing", () => {
    const w = world();
    const { body, att } = w.response([{ cls: "third-party", cid: "c", extra: 1 }]);
    expect(verifyResponse(tok(att), body, CALL, w.cfg()).result.reason).toBe("CHAIN_MISSING");
  });
  it("anAttestationInWireMemberOrderIsChainMissing", () => {
    const w = world();
    const { body, att } = w.response();
    const a = att as { chain: unknown; proof: unknown; labels: unknown; resultHash: string };
    const wire =
      `{"chain":${canonicalize(a.chain)},"proof":${canonicalize(a.proof)},"labels":${canonicalize(a.labels)},` +
      `"resultHash":${canonicalize(a.resultHash)}}`;
    const r = verifyResponse(encode(utf8(wire)), body, CALL, w.cfg());
    expect(r.result.reason).toBe("CHAIN_MISSING");
    expect(r.labels).toEqual([]);
    expect(verifyResponse(tok(att), body, CALL, w.cfg()).result.ok).toBe(true);
  });
  it("aProofThatDoesNotReadIsChainMissing", () => {
    const w = world();
    const { body, att } = w.response();
    const bad = { ...(att as { proof: object }).proof, dirs: "X" };
    const r = verifyResponse(tok({ ...(att as object), proof: bad }), body, CALL, w.cfg());
    expect(r.result.reason).toBe("CHAIN_MISSING");
    expect(r.labels).toEqual([]);
  });
  it("aStampThatDoesNotReadIsChainMissingBeforeRidMismatch", () => {
    const w = world();
    const { body, att } = w.response();
    const chain = (att as { chain: Record<string, unknown>[] }).chain;
    const unread = [{ ...chain[0]!, extra: 1 }, chain[1]];
    const wrongRid = { ...CALL, rid: "rid-2" };
    expect(verifyResponse(tok({ ...(att as object), chain: unread }), body, wrongRid, w.cfg()).result.reason)
      .toBe("CHAIN_MISSING");
    expect(verifyResponse(tok(att), body, wrongRid, w.cfg()).result.reason).toBe("RID_MISMATCH");
    const expired = w.cfg({ policyNotAfter: NOW - 1 });
    expect(verifyResponse(tok({ ...(att as object), chain: unread }), body, CALL, expired).result.reason)
      .toBe("CHAIN_MISSING");
  });
  it("readsAnAttestationFromItsToken", () => {
    const w = world();
    const { att } = w.response();
    expect(readAttestation(tok(att)).labels).toEqual(w.labels);
    expect(() => readAttestation("!")).toThrow();
  });
});
