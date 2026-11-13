// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindResponse, readAttestation, verifyResponse } from "../../src/session/attestation.ts";
import { bindResult } from "../../src/stamp/binding.ts";
import { commitBlock, EMPTY_BLOCK, makeBlock, type Block } from "../../src/stamp/block.ts";
import { encode } from "../../src/encoding/b64url.ts";
import { generateKeyPair, randomBytes, sha256, utf8 } from "../../src/crypto/crypto.ts";
import { buildTree } from "../../src/policy/merkle.ts";
import { NonceCache } from "../../src/verify/nonce.ts";
import { canonicalize, writeToken } from "../../src/encoding/jcs.ts";
import { signStamp } from "../../src/stamp/stamp.ts";
import type { JsonValue } from "../../src/encoding/json.ts";
import { extensionSettings, recordExtensionSettings } from "../../src/verify/extensions.ts";
import type { VerifierConfig } from "../../src/verify/verify-chain.ts";

const tok = (value: unknown): string => writeToken(value as JsonValue);

const NOW = 10_000_000;
const SESS = "sess-1";
const CALL = { rid: "rid-1", toolCallId: "call-1", receiver: "pi" };
const ROUTE = "mcp-entry/github-tools";
/** The blocks a response carries by default: the entry hop adds nothing, the tool hop one `example` item. */
const NOTE = { note: "n" };
const BLOCKS: Block[] = [EMPTY_BLOCK, makeBlock({ example: [NOTE] })];

type Att = { blocks: unknown[]; chain: Record<string, unknown>[]; proof: object; resultHash: string };

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
    extensions: extensionSettings(["example"]),
    ...over,
  });
  /** A response as the server signs it, its stamps naming github-tools and then the calling client. */
  const response = (
    blocks: readonly Block[] = BLOCKS,
    callId = "call-1",
  ): { body: Record<string, unknown>; att: Att } => {
    const body: Record<string, unknown> = { content: [{ type: "text", text: "hello" }] };
    const resultHash = bindResult(body);
    const mk = (svc: string, rcv: string, bind: string, ext: string, prev: string) =>
      signStamp({ svc, inst: svc + "-1", rid: "rid-1", ts: NOW, sess: SESS, rcv, bind, ext, prev }, keys.privateKey);
    const s0 = mk("mcp-entry", "github-tools", "b0", commitBlock(blocks[0]!), "");
    const s1 = mk("github-tools", "pi", bindResponse(resultHash, callId), commitBlock(blocks[1]!), s0.sig);
    const att = { blocks: [...blocks], chain: [s0, s1], proof: tree.proofFor(ROUTE), resultHash };
    return { body, att: JSON.parse(JSON.stringify(att)) as Att };
  };
  return { keys, tree, cfg, response };
}

describe("bindResponse", () => {
  it("isTheHashOfTheResultHashAndTheCallId", () => {
    expect(bindResponse("h", "c")).toBe(encode(sha256(utf8("h\nc"))));
  });
  it("refusesACallIdWithANewlineAndALoneSurrogate", () => {
    expect(() => bindResponse("h", "c\nd")).toThrow();
    expect(() => bindResponse("h", "c\ud800")).toThrow();
    expect(() => bindResponse("h\ud800", "c")).toThrow();
  });
});

describe("readAttestation", () => {
  it("readsAnAttestationFromItsToken", () => {
    const w = world();
    const { att } = w.response();
    const read = readAttestation(tok(att));
    expect(read.blocks).toHaveLength(2);
    expect(read.chain).toHaveLength(2);
    expect(read.resultHash).toBe(att.resultHash);
    expect(() => readAttestation("!")).toThrow();
  });
  it("refusesALabelsMember", () => {
    const w = world();
    const { att } = w.response();
    expect(() => readAttestation(tok({ ...att, labels: [] }))).toThrow("a member the object does not define");
  });
  it("refusesBlocksThatAreAnObject", () => {
    const w = world();
    const { att } = w.response();
    expect(() => readAttestation(tok({ ...att, blocks: { items: {}, requires: [] } }))).toThrow();
  });
  it("refusesABlockWithAnotherMember", () => {
    const w = world();
    const { att } = w.response();
    expect(() => readAttestation(tok({ ...att, blocks: [{ extra: 1, items: {}, requires: [] }, att.blocks[1]] })))
      .toThrow("a member the object does not define");
  });
  it("readsOneWhoseBlocksCountDiffersFromTheChains", () => {
    const w = world();
    const { att } = w.response();
    expect(readAttestation(tok({ ...att, blocks: [att.blocks[0]] })).blocks).toHaveLength(1);
  });
});

describe("verifyResponse", () => {
  it("aGoodResponseIsOkWithTheHandOver", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse(tok(att), body, CALL, w.cfg());
    expect(r).toEqual({
      ok: true, reason: "OK", suspectSvc: "github-tools", suspectInst: "github-tools-1",
      handOver: new Map([["example", [{ svc: "mcp-entry", items: null }, { svc: "github-tools", items: [NOTE] }]]]),
    });
  });
  it("aWrongCountOfBlocksIsExtensionMismatch", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse(tok({ ...att, blocks: [att.blocks[1]] }), body, CALL, w.cfg());
    expect(r.reason).toBe("EXTENSION_MISMATCH");
    expect(r.handOver).toBeNull();
  });
  it("anAlteredBlockIsExtensionMismatch", () => {
    const w = world();
    const { body, att } = w.response();
    const altered = { items: { example: [{ note: "m" }] }, requires: [] };
    expect(verifyResponse(tok({ ...att, blocks: [att.blocks[0], altered] }), body, CALL, w.cfg()).reason)
      .toBe("EXTENSION_MISMATCH");
  });
  it("blocksOfJsonNullAreChainMissingNotAbsent", () => {
    // every block empty, so an absent token would read; the attestation's blocks are never absent
    const w = world();
    const { body, att } = w.response([EMPTY_BLOCK, EMPTY_BLOCK]);
    expect(verifyResponse(tok(att), body, CALL, w.cfg()).reason).toBe("OK");
    const r = verifyResponse(tok({ ...att, blocks: null }), body, CALL, w.cfg());
    expect(r.reason).toBe("CHAIN_MISSING");
    expect(() => readAttestation(tok({ ...att, blocks: null }))).toThrow();
  });
  it("aLastBlockRequiringAnExtensionTheClientDoesNotActOnIsExtensionRequired", () => {
    const w = world();
    const { body, att } = w.response([EMPTY_BLOCK, makeBlock({}, ["example"])]);
    expect(verifyResponse(tok(att), body, CALL, w.cfg({ extensions: extensionSettings([]) })).reason)
      .toBe("EXTENSION_REQUIRED");
    // a recorded response was held to the caller's actsOn live: no check 9c
    expect(verifyResponse(tok(att), body, CALL, w.cfg({ extensions: recordExtensionSettings([]) })).reason)
      .toBe("OK");
  });
  it("aResponseSeenTwiceIsReplay", () => {
    const w = world();
    const { body, att } = w.response();
    const cfg = w.cfg();
    expect(verifyResponse(tok(att), body, CALL, cfg).reason).toBe("OK");
    expect(verifyResponse(tok(att), body, CALL, cfg).reason).toBe("REPLAY");
  });
  it("neverReadsMetaFromTheResult", () => {
    const w = world();
    const { body, att } = w.response();
    const r = verifyResponse("", { ...body, _meta: { "paztport/attestation": att } }, CALL, w.cfg());
    expect(r.reason).toBe("CHAIN_MISSING");
    expect(r.handOver).toBeNull();
  });
  it("aCallIdWithALoneSurrogateIsBindingMismatchAndDoesNotThrow", () => {
    const w = world();
    const { body, att } = w.response();
    expect(verifyResponse(tok(att), body, { ...CALL, toolCallId: "call-1\ud800" }, w.cfg()).reason)
      .toBe("BINDING_MISMATCH");
  });
  it("aCallIdHoldingANoncharacterVerifies", () => {
    // the nonce key is the verifier's own text, written as hashed content is, so it can be formed
    const w = world();
    const { body, att } = w.response(BLOCKS, "call-1\ufffe");
    expect(verifyResponse(tok(att), body, { ...CALL, toolCallId: "call-1\ufffe" }, w.cfg()).reason).toBe("OK");
  });
  it("malformedAttestationIsChainMissing", () => {
    const w = world();
    for (const v of [null, "x", [], { chain: {} }]) {
      expect(verifyResponse(tok(v), { content: [] }, CALL, w.cfg()).reason).toBe("CHAIN_MISSING");
    }
  });
  it("aResponseForAnotherReceiverIsBindingMismatch", () => {
    const w = world();
    const { body, att } = w.response();
    expect(verifyResponse(tok(att), body, { ...CALL, receiver: "search" }, w.cfg()).reason).toBe("BINDING_MISMATCH");
  });
  it("aResultHoldingALoneSurrogateIsBindingMismatch", () => {
    const w = world();
    const { att } = w.response();
    const r = verifyResponse(tok(att), { content: [{ type: "text", text: "\ud800" }] }, CALL, w.cfg());
    expect(r.reason).toBe("BINDING_MISMATCH");
  });
  it("aNonStringReceiverIsChainMissing", () => {
    const w = world();
    const { body, att } = w.response();
    const call = { ...CALL, receiver: 1 as unknown as string };
    expect(verifyResponse(tok(att), body, call, w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("aStampWhoseVersionIsNotFourIsChainMissing", () => {
    const w = world();
    for (const v of [1, 2, 3, 5]) {
      for (const at of [0, 1]) {
        const { body, att } = w.response();
        att.chain[at]!.v = v;
        expect(verifyResponse(tok(att), body, CALL, w.cfg()).reason, `v ${v} at ${at}`).toBe("CHAIN_MISSING");
      }
    }
  });
  it("anAttestationWithAMemberItDoesNotHaveIsChainMissing", () => {
    const w = world();
    const { body, att } = w.response();
    expect(verifyResponse(tok({ ...att, extra: 1 }), body, CALL, w.cfg()).reason).toBe("CHAIN_MISSING");
    expect(verifyResponse(tok({ ...att, labels: [] }), body, CALL, w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("anAttestationInWireMemberOrderIsChainMissing", () => {
    const w = world();
    const { body, att } = w.response();
    const wire =
      `{"chain":${canonicalize(att.chain)},"blocks":${canonicalize(att.blocks)},"proof":${canonicalize(att.proof)},` +
      `"resultHash":${canonicalize(att.resultHash)}}`;
    expect(verifyResponse(encode(utf8(wire)), body, CALL, w.cfg()).reason).toBe("CHAIN_MISSING");
    expect(verifyResponse(tok(att), body, CALL, w.cfg()).ok).toBe(true);
  });
  it("aProofThatDoesNotReadIsChainMissing", () => {
    const w = world();
    const { body, att } = w.response();
    const bad = { ...att.proof, dirs: "X" };
    expect(verifyResponse(tok({ ...att, proof: bad }), body, CALL, w.cfg()).reason).toBe("CHAIN_MISSING");
  });
  it("aStampThatDoesNotReadIsChainMissingBeforeRidMismatch", () => {
    const w = world();
    const { body, att } = w.response();
    const unread = [{ ...att.chain[0]!, extra: 1 }, att.chain[1]];
    const wrongRid = { ...CALL, rid: "rid-2" };
    expect(verifyResponse(tok({ ...att, chain: unread }), body, wrongRid, w.cfg()).reason).toBe("CHAIN_MISSING");
    expect(verifyResponse(tok(att), body, wrongRid, w.cfg()).reason).toBe("RID_MISMATCH");
    const expired = w.cfg({ policyNotAfter: NOW - 1 });
    expect(verifyResponse(tok({ ...att, chain: unread }), body, CALL, expired).reason).toBe("CHAIN_MISSING");
  });
});
