// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { bindMcpCall } from "../src/binding.ts";
import { generateKeyPair, randomBytes } from "../src/crypto.ts";
import { commitInfluence, type InfluenceEntry } from "../src/influence.ts";
import { buildTree } from "../src/merkle.ts";
import { META_CALL_ID, META_CHAIN, META_INFLUENCE, META_PROOF } from "../src/meta.ts";
import { NonceCache } from "../src/nonce.ts";
import { signStampV2 } from "../src/stamp.ts";
import { verifyCall } from "../src/verify-call.ts";
import { NONCE_TTL_MS, type V2Config } from "../src/verify-v2.ts";

const NOW = 10_000_000;
const SESS = "sess-1";
const SERVER = { serverId: "github" };
const TOOL = "create_pull_request";
const ROUTE = `session/pi/mcp:github.${TOOL}`;
const infl: InfluenceEntry[] = [{ cls: "third-party", src: "web:example.com", h: "h1" }];

function world() {
  const harness = generateKeyPair();
  const tree = buildTree(
    [ROUTE, "session/pi/mcp:github.get_issue"].map((path) => ({ salt: randomBytes(16), path })),
    8,
    "v1",
  );
  const cfg = (over: Partial<Omit<V2Config, "nonceKey">> = {}): Omit<V2Config, "nonceKey"> => ({
    keyring: { session: harness.publicKey, pi: harness.publicKey },
    root: tree.root,
    rootId: tree.rootId,
    allowedOrigins: ["session"],
    sess: SESS,
    nonces: new NonceCache(NONCE_TTL_MS),
    now: NOW,
    ...over,
  });
  /** A tools/call params object whose chain binds (name, callId, args); `send` overrides what is sent. */
  const params = (
    signed: { name?: string; callId?: string; args?: Record<string, unknown> } = {},
    send: { name?: string; callId?: unknown; args?: Record<string, unknown> } = {},
  ): Record<string, unknown> => {
    const name = signed.name ?? TOOL;
    const callId = signed.callId ?? "call-1";
    const args = signed.args ?? { title: "t" };
    const mk = (svc: string, bind: string, i: string, prev: string) =>
      signStampV2({ svc, inst: `${svc}-1`, rid: "rid-1", ts: NOW, sess: SESS, bind, infl: i, prev }, harness.privateKey);
    const s0 = mk("session", "b0", "", "");
    const s1 = mk("pi", bindMcpCall(name, callId, args), commitInfluence(infl), s0.sig);
    return {
      name: send.name ?? name,
      arguments: send.args ?? args,
      _meta: {
        [META_CHAIN]: [s0, s1],
        [META_PROOF]: tree.proofFor(ROUTE),
        [META_INFLUENCE]: infl,
        [META_CALL_ID]: "callId" in send ? send.callId : callId,
      },
    };
  };
  return { cfg, params };
}

describe("verifyCall", () => {
  it("validCallPasses", () => {
    const w = world();
    const r = verifyCall(w.params(), SERVER, w.cfg());
    expect(r.result).toEqual({ ok: true, reason: "OK", suspectSvc: "pi", suspectInst: "pi-1" });
    expect(r.rid).toBe("rid-1");
    expect(r.callId).toBe("call-1");
    expect(r.influence).toEqual(infl);
  });
  it("replayedCallIsReplay", () => {
    const w = world();
    const cfg = w.cfg();
    const p = w.params();
    expect(verifyCall(p, SERVER, cfg).result.ok).toBe(true);
    const again = verifyCall(p, SERVER, cfg);
    expect(again.result.reason).toBe("REPLAY");
    expect(again.influence).toEqual([]);
    // the nonce is keyed on the chain's rid and the call id, not on anything the caller supplies
    expect(cfg.nonces.seenBefore("rid-1|call-1|req", NOW)).toBe(true);
  });
  it("argumentsChangedIsBindingMismatch", () => {
    const w = world();
    const r = verifyCall(w.params({}, { args: { title: "evil" } }), SERVER, w.cfg());
    expect(r.result.reason).toBe("BINDING_MISMATCH");
    expect(r.influence).toEqual([]);
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
    // the receiver names the verifying server: the same call presented to another server is not on the route
    expect(verifyCall(w.params(), { serverId: "gitlab" }, w.cfg()).result.reason).toBe("PATH_NOT_ALLOWED");
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
      { ...good, _meta: { ...(good._meta as object), [META_CHAIN]: "junk" } },
    ];
    for (const v of variants) {
      const r = verifyCall(v, SERVER, w.cfg());
      expect(r.result.reason, JSON.stringify(v)).toBe("CHAIN_MISSING");
      expect(r.result.ok).toBe(false);
      expect(r.influence).toEqual([]);
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
});
