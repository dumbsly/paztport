// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  EMPTY_BLOCK, INFLUENCE, NONCE_TTL_MS, NonceCache, buildTree, commitBlock, extensionSettings, generateKeyPair,
  influenceBlock, makeBlock, nonceKey, randomBytes, readChain, readProof, signStamp, writeToken,
} from "@paztport/core";
import type { Block, InfluenceEntry, JsonValue, VerifierConfig } from "@paztport/core";
import { META_CALL_ID, META_CHAIN, META_EXTENSIONS, META_PROOF, bindMcpCall, verifyCall } from "../src/index.ts";
import { tokenOf } from "./helpers/client.ts";

const NOW = 10_000_000;
const SESS = "sess-1";
const SERVER = { serverId: "github" };
const TOOL = "create_pull_request";
const ROUTE = `session/pi/mcp:github.${TOOL}`;
const entries: InfluenceEntry[] = [{ cls: "third-party", src: "web:example.com", h: "h1" }];
/** The blocks a call carries by default: the origin names influence with nothing, the hop holds `entries`. */
const BLOCKS: readonly [Block, Block] = [influenceBlock([]), influenceBlock(entries)];
/** A server that acts on influence. */
const ACTS = extensionSettings([INFLUENCE]);
const blocksToken = (blocks: readonly Block[]): string => writeToken(blocks as unknown as JsonValue);

function world(extraRoutes: string[] = []) {
  const harness = generateKeyPair();
  const tree = buildTree(
    [ROUTE, "session/pi/mcp:github.get_issue", ...extraRoutes].map((path) => ({ salt: randomBytes(16), path })),
    8,
    "v1",
  );
  const cfg = (over: Partial<Omit<VerifierConfig, "nonceKey">> = {}): Omit<VerifierConfig, "nonceKey"> => ({
    keyrings: [{ keys: { session: harness.publicKey, pi: harness.publicKey }, notAfter: 4_102_444_800_000 }],
    roots: [{ root: tree.root, rootId: tree.rootId, notAfter: 4_102_444_800_000 }],
    allowedOrigins: ["session"],
    sess: SESS,
    nonces: new NonceCache(NONCE_TTL_MS),
    now: NOW,
    policyNotAfter: 4_102_444_800_000,
    extensions: ACTS,
    ...over,
  });
  /**
   * A tools/call params object whose chain binds (name, callId, args), names `rcv`, `mcp:github.<name>` by default,
   * and commits to `blocks`; `send` overrides what is sent.
   */
  const params = (
    signed: {
      name?: string; callId?: string; args?: Record<string, unknown>; route?: string; rcv?: string; blocks?: readonly Block[];
    } = {},
    send: { name?: string; callId?: unknown; args?: Record<string, unknown> } = {},
  ): Record<string, unknown> => {
    const name = signed.name ?? TOOL;
    const callId = signed.callId ?? "call-1";
    const args = signed.args ?? { title: "t" };
    const blocks = signed.blocks ?? BLOCKS;
    const mk = (svc: string, rcv: string, bind: string, ext: string, prev: string) => {
      return signStamp({ svc, inst: `${svc}-1`, rid: "rid-1", ts: NOW, sess: SESS, rcv, bind, ext, prev }, harness.privateKey);
    };
    const s0 = mk("session", "pi", "b0", commitBlock(blocks[0]!), "");
    const s1 = mk("pi", signed.rcv ?? `mcp:github.${name}`, bindMcpCall(name, callId, args), commitBlock(blocks[1]!), s0.sig);
    return {
      name: send.name ?? name,
      arguments: send.args ?? args,
      _meta: {
        [META_CHAIN]: writeToken([s0, s1]),
        [META_PROOF]: writeToken(tree.proofFor(signed.route ?? ROUTE)),
        [META_EXTENSIONS]: blocksToken(blocks),
        [META_CALL_ID]: "callId" in send ? send.callId : callId,
      },
    };
  };
  return { cfg, params };
}

describe("verifyCall", () => {
  it("validCallPassesWithItsHandOver", () => {
    const w = world();
    const r = verifyCall(w.params(), SERVER, w.cfg());
    expect(r.result).toEqual({
      ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi-1",
      handOver: new Map([[INFLUENCE, [{ svc: "session", items: [] }, { svc: "pi", items: entries }]]]),
    });
    expect(r.rid).toBe("rid-1");
    expect(r.callId).toBe("call-1");
  });
  it("theNonceKeyIsTheJcsArrayOfRidCallIdAndReq", () => {
    const w = world();
    const cfg = w.cfg();
    expect(verifyCall(w.params(), SERVER, cfg).result.ok).toBe(true);
    expect(nonceKey(["rid-1", "call-1", "req"])).toBe('["rid-1","call-1","req"]');
    expect(cfg.nonces.seenBefore('["rid-1","call-1","req"]', NOW)).toBe(true);
  });
  it("noExtensionsMemberIsEveryBlockEmpty", () => {
    const w = world();
    const empty = [EMPTY_BLOCK, EMPTY_BLOCK];
    const p = w.params({ blocks: empty });
    const { [META_EXTENSIONS]: _gone, ...meta } = p._meta as Record<string, unknown>;
    const r = verifyCall({ ...p, _meta: meta }, SERVER, w.cfg());
    expect(r.result).toMatchObject({ reason: "OK", handOver: new Map([[INFLUENCE, [{ svc: "session", items: null }, { svc: "pi", items: null }]]]) });
    // the same blocks sent read alike
    expect(verifyCall(w.params({ blocks: empty }), SERVER, w.cfg()).result.reason).toBe("OK");
    // and a chain whose blocks were not all empty is refused without them
    const { [META_EXTENSIONS]: _also, ...stripped } = w.params()._meta as Record<string, unknown>;
    expect(verifyCall({ ...w.params(), _meta: stripped }, SERVER, w.cfg()).result.reason).toBe("EXTENSION_MISMATCH");
  });
  it("anExtensionsMemberThatIsNotATokenIsExtensionMismatch", () => {
    const w = world();
    const p = w.params();
    for (const value of [5, null, [], BLOCKS]) {
      const r = verifyCall({ ...p, _meta: { ...(p._meta as object), [META_EXTENSIONS]: value } }, SERVER, w.cfg());
      expect(r.result, JSON.stringify(value)).toMatchObject({ reason: "EXTENSION_MISMATCH", handOver: null });
    }
  });
  it("aCallWhoseLastBlockRequiresWhatTheServerDoesNotActOnIsExtensionRequired", () => {
    const w = world();
    const blocks = [BLOCKS[0], makeBlock({ [INFLUENCE]: [] }, ["example"])];
    expect(verifyCall(w.params({ blocks }), SERVER, w.cfg()).result).toMatchObject({ reason: "EXTENSION_REQUIRED", handOver: null });
  });
  it("aCallStampedForAnotherReceiverIsBindingMismatch", () => {
    const w = world();
    // signed and bound for create_pull_request, but the hop names mcp:github.other as its receiver
    const r = verifyCall(w.params({ rcv: "mcp:github.other" }), SERVER, w.cfg());
    expect(r.result).toMatchObject({ reason: "BINDING_MISMATCH", handOver: null });
  });
  it("eachCallGetsItsOwnVerdict", () => {
    const w = world();
    const cfg = w.cfg();
    const p = w.params();
    const results = [
      verifyCall(p, SERVER, cfg),
      verifyCall(p, SERVER, cfg),
      verifyCall(w.params({ rcv: "mcp:github.other" }), SERVER, w.cfg()),
      verifyCall(null, SERVER, w.cfg()),
    ];
    expect(results.map((r) => r.result.reason)).toEqual(["OK", "REPLAY", "BINDING_MISMATCH", "CHAIN_MISSING"]);
  });
  it("replayedCallIsReplay", () => {
    const w = world();
    const cfg = w.cfg();
    const p = w.params();
    expect(verifyCall(p, SERVER, cfg).result.ok).toBe(true);
    const again = verifyCall(p, SERVER, cfg);
    expect(again.result).toMatchObject({ reason: "REPLAY", handOver: null });
    // the nonce is keyed on the chain's rid and the call id, not on anything the caller supplies
    expect(cfg.nonces.seenBefore(nonceKey(["rid-1", "call-1", "req"]), NOW)).toBe(true);
  });
  it("argumentsChangedIsBindingMismatch", () => {
    const w = world();
    const r = verifyCall(w.params({}, { args: { title: "evil" } }), SERVER, w.cfg());
    expect(r.result).toMatchObject({ reason: "BINDING_MISMATCH", handOver: null });
  });
  it("callIdChangedIsBindingMismatch", () => {
    const w = world();
    const r = verifyCall(w.params({}, { callId: "call-2" }), SERVER, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    expect(r.callId).toBe("call-2");
  });
  it("newlineInNameIsBindingMismatch", () => {
    const w = world();
    const r = verifyCall(w.params({}, { name: "create_pull_request\nx" }), SERVER, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    const c = verifyCall(w.params({}, { callId: "call\n1" }), SERVER, w.cfg());
    expect(c.result.reason).toBe("BINDING_MISMATCH");
  });
  it("wrongToolIsPathNotAllowed", () => {
    const w = world();
    // correctly signed and bound for delete_repo, but session/pi/mcp:github.delete_repo is not in the client root
    expect(verifyCall(w.params({ name: "delete_repo" }), SERVER, w.cfg()).result.reason).toBe("PATH_NOT_ALLOWED");
    // the receiver names the verifying server: the same call presented to another server names the wrong receiver
    expect(verifyCall(w.params(), { serverId: "gitlab" }, w.cfg()).result.reason).toBe("BINDING_MISMATCH");
    // and one stamped for that server is not on the route
    expect(verifyCall(w.params({ rcv: `mcp:gitlab.${TOOL}` }), { serverId: "gitlab" }, w.cfg()).result.reason).toBe("PATH_NOT_ALLOWED");
  });
  it("malformedParamsChainMissing", () => {
    const w = world();
    const good = w.params();
    const variants: unknown[] = [
      null,
      undefined,
      "x",
      [],
      { name: TOOL, arguments: {} },
      { ...good, _meta: null },
      { ...good, _meta: [] },
      { ...good, name: 5 },
      { ...good, _meta: { ...(good._meta as object), [META_CALL_ID]: 7 } },
      { ...good, _meta: { ...(good._meta as object), [META_CHAIN]: [] } },
      { ...good, _meta: { ...(good._meta as object), [META_CHAIN]: tokenOf([]) } },
      { ...good, _meta: { ...(good._meta as object), [META_CHAIN]: "junk" } },
    ];
    for (const v of variants) {
      const r = verifyCall(v, SERVER, w.cfg());
      expect(r.result.reason, JSON.stringify(v)).toBe("CHAIN_MISSING");
      expect(r.result.ok).toBe(false);
      expect(r.result.handOver).toBeNull();
    }
  });
  it("shortTtlCacheIsReplay", () => {
    const w = world();
    const nonces = new NonceCache(1000);
    const r = verifyCall(w.params(), SERVER, w.cfg({ nonces }));
    expect(r.result.reason).toBe("REPLAY");
    expect(nonces.size).toBe(0); // checked before the nonce is spent
    expect(verifyCall(w.params(), SERVER, w.cfg({ nonces: new NonceCache(2 * 5000) })).result.ok).toBe(true);
    expect(verifyCall(w.params(), SERVER, w.cfg({ nonces: new NonceCache(NaN) })).result.reason).toBe("REPLAY");
  });
  it("slashInToolNameIsChainMissing", () => {
    // the client root holds a route built from the nodes [session, pi, mcp:github.a, b]; "a/b" must not reach it
    const route = ["session", "pi", "mcp:github.a", "b"].join("/");
    expect(route).toBe("session/pi/mcp:github.a/b");
    const w = world([route]);
    const r = verifyCall(w.params({ name: "a/b", route }), SERVER, w.cfg());
    expect(r.result).toMatchObject({ reason: "CHAIN_MISSING", ok: false, handOver: null });
  });
  it("aPipeInAToolNameIsChainMissingSinceNoRouteNodeHoldsOne", () => {
    const w = world(["session/pi/mcp:github.a|b"]);
    // the receiver mcp:github.a|b is no route node, so no stamp can name it: the name is refused before the chain
    const r = verifyCall(w.params({ name: "a|b", route: "session/pi/mcp:github.a|b", rcv: "mcp:github.a" }), SERVER, w.cfg());
    expect(r.result.reason).toBe("CHAIN_MISSING");
  });
  it("slashPipeOrDotInServerIdIsChainMissing", () => {
    const w = world();
    for (const serverId of ["git/hub", "git|hub", "git.hub"]) {
      const r = verifyCall(w.params(), { serverId }, w.cfg());
      expect(r.result.reason, serverId).toBe("CHAIN_MISSING");
    }
  });
  it("dotInToolNameStillVerifies", () => {
    const name = "repo.create";
    const w = world([`session/pi/mcp:github.${name}`]);
    const r = verifyCall(w.params({ name, route: `session/pi/mcp:github.${name}` }), SERVER, w.cfg());
    expect(r.result.reason).toBe("OK");
  });
  it("parsesChainOnce", () => {
    const w = world();
    const p = w.params();
    const meta = p._meta as Record<string, unknown>;
    const reads: Record<string, number> = {};
    const counted = new Proxy(meta, {
      get(t, k, r) {
        if (typeof k === "string") reads[k] = (reads[k] ?? 0) + 1;
        return Reflect.get(t, k, r);
      },
    });
    const r = verifyCall({ ...p, _meta: counted }, SERVER, w.cfg());
    expect(r.result.ok).toBe(true);
    expect(r.result.handOver?.get(INFLUENCE)?.[1]?.items).toEqual(entries);
    expect(reads[META_CHAIN]).toBe(1);
    expect(reads[META_EXTENSIONS]).toBe(1);
  });
  it("aMetaMemberThatDoesNotReadGetsItsReadersRefusal", () => {
    const w = world();
    const p = w.params();
    const meta = p._meta as Record<string, string>;
    const [s0, s1] = readChain(meta[META_CHAIN]!);
    const proof = readProof(meta[META_PROOF]!);
    const withMeta = (m: Record<string, unknown>) =>
      verifyCall({ ...p, _meta: { ...meta, ...m } }, SERVER, w.cfg()).result.reason;
    // a token whose value its reader refuses
    expect(withMeta({ [META_CHAIN]: tokenOf([s0, { ...s1, ts: -1 }]) })).toBe("CHAIN_MISSING");
    expect(withMeta({ [META_CHAIN]: tokenOf([s0, { ...s1, inst: "pi-\uFDD0" }]) })).toBe("CHAIN_MISSING");
    expect(withMeta({ [META_CHAIN]: tokenOf([s0, { ...s1, extra: true }]) })).toBe("CHAIN_MISSING");
    expect(withMeta({ [META_EXTENSIONS]: tokenOf([{ items: {}, requires: [] }, { items: { influence: ["\uFFFE"] }, requires: [] }]) }))
      .toBe("EXTENSION_MISMATCH");
    expect(withMeta({ [META_PROOF]: tokenOf({ ...proof, rootId: 1.5 }) })).toBe("PATH_NOT_ALLOWED");
    // a member that is not a string: the value a token would hold, or none
    expect(withMeta({ [META_CHAIN]: [s0, s1] })).toBe("CHAIN_MISSING");
    expect(withMeta({ [META_EXTENSIONS]: BLOCKS })).toBe("EXTENSION_MISMATCH");
    expect(withMeta({ [META_EXTENSIONS]: undefined })).toBe("EXTENSION_MISMATCH");
    expect(withMeta({ [META_PROOF]: proof })).toBe("PATH_NOT_ALLOWED");
    expect(withMeta({ [META_PROOF]: undefined })).toBe("PATH_NOT_ALLOWED");
    expect(withMeta({})).toBe("OK");
  });
});
