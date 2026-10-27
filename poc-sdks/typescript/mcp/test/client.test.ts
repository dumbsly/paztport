// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  bindPrompt,
  bindResult,
  buildPolicy,
  generateKeyPair,
  mintOrigin,
  NonceCache,
  NONCE_TTL_MS,
  signKeyring,
  type InfluenceEntry,
  type SessionReply,
} from "@paztport/core";
import {
  classifySessionError,
  classifySessionReply,
  McpServerSession,
  META_CALL_ID,
  META_CHAIN,
  META_INFLUENCE,
  META_PROOF,
  readToolResult,
  replacementRequest,
  sessionRequest,
  stampToolCall,
  toolCallProof,
  type ResultContext,
  type ServerPolicy,
  type SessionRules,
} from "../src/index.ts";
import type { CallToolResult } from "./helpers/client.ts";

const RULES: SessionRules = { disabledWhenUnsafe: ["create_pull_request"] };
const TOOLS = ["list_issues", "create_pull_request"];
const CLIENT_HOPS = ["session", "pi"];
const SERVER_ORIGINS = ["mcp-entry"];
/** The policy key every test client signs with, so the test server can pin it. */
const CLIENT_POLICY = generateKeyPair();

function serverPolicy(): ServerPolicy {
  const policy = generateKeyPair();
  const entry = generateKeyPair();
  const tools = generateKeyPair();
  const { signedRoot, bundles } = buildPolicy([["mcp-entry", "github-tools"]], 8, policy.privateKey);
  return {
    policyPrivateKey: policy.privateKey,
    policyPublicKey: policy.publicKey,
    signingKeys: { "mcp-entry": entry.privateKey, "github-tools": tools.privateKey },
    keyring: { "mcp-entry": entry.publicKey, "github-tools": tools.publicKey },
    signedRoot,
    routeProof: bundles["mcp-entry"]!.proofs["mcp-entry/github-tools"]!,
    inst: "mock-github-1",
    hops: ["mcp-entry", "github-tools"],
    serverId: "github",
    pinnedClientKeys: [CLIENT_POLICY.publicKey],
  };
}

function clientMaterial() {
  const policy = CLIENT_POLICY;
  const session = generateKeyPair();
  const pi = generateKeyPair();
  const { signedRoot, bundles } = buildPolicy(TOOLS.map((t) => [...CLIENT_HOPS, `mcp:github.${t}`]), 8, policy.privateKey);
  const ring = signKeyring({ session: session.publicKey, pi: pi.publicKey }, policy.publicKey, policy.privateKey);
  return {
    signedRoot,
    policyPublicKey: policy.publicKey,
    keyring: ring.services,
    keyringSig: ring.sig,
    sessionKey: session.privateKey,
    piKey: pi.privateKey,
    proofs: bundles["pi"]!.proofs,
  };
}

/** A server and a client that completed the handshake; `withRoot: false` gives an unsafe session. */
function connected(opts: { withRoot?: boolean } = {}) {
  const policy = serverPolicy();
  const server = new McpServerSession(policy, RULES, Date.now);
  const client = clientMaterial();
  const req = sessionRequest({ ...client, signedRoot: opts.withRoot === false ? null : client.signedRoot });
  const raw: unknown = JSON.parse(JSON.stringify(server.openSession(req)));
  return { policy, server, client, req, raw };
}

function attestedSession() {
  const c = connected();
  const outcome = classifySessionReply(c.raw, c.req, c.policy.policyPublicKey);
  if (outcome.status !== "attested") {
    throw new Error("expected an attested session");
  }
  return { ...c, reply: outcome.reply };
}

const RID = "rid-1";
const PROMPT_TS = Date.now();

/** Stamps a tools/call the way a harness does: the run's origin, then the calling hop. */
function stampedParams(
  s: ReturnType<typeof attestedSession>,
  name: string,
  args: Record<string, unknown>,
  callId: string,
  influence: InfluenceEntry[] = [],
) {
  const proof = toolCallProof(s.client.proofs, CLIENT_HOPS, "github", name);
  if (proof === undefined) {
    throw new Error(`no proof for ${name}`);
  }
  const origin = mintOrigin({ rid: RID, ts: PROMPT_TS, bind: bindPrompt("a prompt"), sess: s.reply.sess, inst: "pi-1", rcv: "pi" }, s.client.sessionKey);
  const _meta = stampToolCall(
    { name, args, callId },
    { origin, svc: "pi", inst: "pi-1", privateKey: s.client.piKey, ts: Date.now(), influence, proof, serverId: "github" },
  );
  return { name, arguments: args, _meta };
}

function attestedContext(s: ReturnType<typeof attestedSession>, callId: string, now: () => number = Date.now, svc = "pi"): ResultContext {
  return { session: "attested", reply: s.reply, svc, rid: RID, callId, allowedOrigins: SERVER_ORIGINS, nonces: new NonceCache(NONCE_TTL_MS), now };
}

const RESULT: CallToolResult = { content: [{ type: "text", text: "hello" }] };
const neverCalled = () => {
  throw new Error("now() must not be read");
};

describe("sessionRequest", () => {
  it("carriesTheClientsRootKeysAndAFreshNonce", () => {
    const client = clientMaterial();
    const a = sessionRequest(client);
    const b = sessionRequest({ ...client, signedRoot: null });
    expect(Object.keys(a)).toEqual(["clientRoot", "clientPolicyKey", "clientKeyring", "clientKeyringSig", "nonce"]);
    expect(a).toMatchObject({
      clientRoot: client.signedRoot,
      clientPolicyKey: client.policyPublicKey,
      clientKeyring: client.keyring,
      clientKeyringSig: client.keyringSig,
    });
    expect(b.clientRoot).toBeNull();
    expect(a.nonce).not.toBe(b.nonce);
  });
});

describe("classifySessionReply", () => {
  it("attestedReplyIsUsed", () => {
    const c = connected();
    const outcome = classifySessionReply(c.raw, c.req, c.policy.policyPublicKey);
    expect(outcome).toEqual({ status: "attested", reply: c.raw });
  });
  it("unsafeReplyKeepsTheServersSession", () => {
    const c = connected({ withRoot: false });
    expect(classifySessionReply(c.raw, c.req, c.policy.policyPublicKey)).toEqual({ status: "unsafe", reason: "UNSAFE", replaceSession: false });
  });
  it("malformedReplyIsReplaced", () => {
    const c = connected();
    const { sig: _sig, ...unsigned } = c.raw as SessionReply;
    for (const raw of [undefined, null, "reply", {}, unsigned, { ...(c.raw as SessionReply), status: "open" }]) {
      expect(classifySessionReply(raw, c.req, c.policy.policyPublicKey)).toEqual({ status: "unsafe", reason: "MALFORMED_REPLY", replaceSession: true });
    }
  });
  it("otherServerKeyIsAPinMismatch", () => {
    const c = connected();
    expect(classifySessionReply(c.raw, c.req, generateKeyPair().publicKey)).toEqual({ status: "unsafe", reason: "PIN_MISMATCH", replaceSession: true });
  });
  it("tamperedReplyIsABadSignature", () => {
    const c = connected();
    const tampered = { ...(c.raw as SessionReply), disabled: ["list_issues"] };
    expect(classifySessionReply(tampered, c.req, c.policy.policyPublicKey)).toEqual({ status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true });
  });
  it("replyToAnotherRequestIsABadSignature", () => {
    const c = connected();
    const other = sessionRequest(c.client);
    expect(classifySessionReply(c.raw, other, c.policy.policyPublicKey)).toEqual({ status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true });
  });
});

describe("classifySessionError", () => {
  it("methodNotFoundMeansNoPaztport", () => {
    expect(classifySessionError(-32601)).toEqual({ status: "unsafe", reason: "METHOD_NOT_FOUND", replaceSession: false });
  });
  it("anyOtherFailureIsReplaced", () => {
    for (const code of [undefined, -32603, -32602]) {
      expect(classifySessionError(code)).toEqual({ status: "unsafe", reason: "HANDSHAKE_ERROR", replaceSession: true });
    }
  });
});

describe("replacementRequest", () => {
  it("dropsTheRootWithAFreshNonce", () => {
    const c = connected();
    const r = replacementRequest(c.req);
    expect(Object.keys(r)).toEqual(Object.keys(c.req));
    expect(r).toEqual({ ...c.req, clientRoot: null, nonce: r.nonce });
    expect(r.nonce).not.toBe(c.req.nonce);
  });
  it("replacesAnAttestedSessionTheClientCannotUse", () => {
    const c = connected();
    expect(c.server.session()?.status).toBe("attested");
    c.server.openSession(replacementRequest(c.req));
    expect(c.server.session()?.status).toBe("unsafe");
  });
});

describe("toolCallProof", () => {
  it("findsTheRouteThroughTheChainsServices", () => {
    const client = clientMaterial();
    expect(toolCallProof(client.proofs, CLIENT_HOPS, "github", "list_issues")).toBe(client.proofs["session/pi/mcp:github.list_issues"]);
  });
  it("hasNoneForAnUnlistedRoute", () => {
    const client = clientMaterial();
    for (const [server, tool] of [["github", "push_files"], ["docs", "list_issues"], ["github", "__proto__"], ["github", "constructor"]]) {
      expect(toolCallProof(client.proofs, CLIENT_HOPS, server!, tool!)).toBeUndefined();
    }
    expect(toolCallProof(client.proofs, ["pi"], "github", "list_issues")).toBeUndefined();
  });
});

describe("stampToolCall", () => {
  it("carriesTheChainProofInfluenceAndCallIdInOrder", () => {
    const s = attestedSession();
    const params = stampedParams(s, "list_issues", { owner: "o" }, "call-1");
    expect(Object.keys(params._meta)).toEqual([META_CHAIN, META_PROOF, META_INFLUENCE, META_CALL_ID]);
    const [origin, hop] = params._meta[META_CHAIN] as { svc: string; rid: string; sess: string; prev: string; sig: string }[];
    expect(origin!.svc).toBe("session");
    expect(hop).toMatchObject({ svc: "pi", rid: RID, sess: s.reply.sess, prev: origin!.sig });
    expect(params._meta[META_CALL_ID]).toBe("call-1");
  });
  it("theHopNamesTheToolAsItsReceiverAndTheOriginIsUnchanged", () => {
    const s = attestedSession();
    const proof = toolCallProof(s.client.proofs, CLIENT_HOPS, "github", "create_pull_request")!;
    const origin = mintOrigin({ rid: RID, ts: PROMPT_TS, bind: bindPrompt("a prompt"), sess: s.reply.sess, inst: "pi-1", rcv: "pi" }, s.client.sessionKey);
    const before = structuredClone(origin);
    const _meta = stampToolCall(
      { name: "create_pull_request", args: { title: "t" }, callId: "call-1" },
      { origin, svc: "pi", inst: "pi-1", privateKey: s.client.piKey, ts: Date.now(), influence: [], proof, serverId: "github" },
    );
    const chain = _meta[META_CHAIN] as Record<string, unknown>[];
    expect(chain[0]).toBe(origin);
    expect(chain[0]).toEqual(before);
    expect(chain[1]).toMatchObject({ v: 3, svc: "pi", rcv: "mcp:github.create_pull_request", prev: origin.sig });
  });
  it("verifiesAtTheServer", () => {
    const s = attestedSession();
    const influence: InfluenceEntry[] = [{ cls: "third-party", src: "server:github", h: "h1", cid: "c1" }];
    const check = s.server.checkCall(stampedParams(s, "list_issues", { owner: "o" }, "call-1", influence));
    expect(check).toMatchObject({ reason: "OK", rid: RID, callId: "call-1", influence });
  });
  it("changedArgumentsDoNotVerify", () => {
    const s = attestedSession();
    const params = stampedParams(s, "list_issues", { owner: "o" }, "call-1");
    expect(s.server.checkCall({ ...params, arguments: { owner: "x" } }).reason).toBe("BINDING_MISMATCH");
  });
  it("changedInfluenceDoesNotVerify", () => {
    const s = attestedSession();
    const params = stampedParams(s, "list_issues", { owner: "o" }, "call-1", [{ cls: "private", src: "server:github", h: "h1" }]);
    expect(s.server.checkCall({ ...params, _meta: { ...params._meta, [META_INFLUENCE]: [] } }).reason).toBe("INFLUENCE_MISMATCH");
  });
});

describe("readToolResult", () => {
  it("verifiedResponseGivesItsLabels", () => {
    const s = attestedSession();
    const args = { owner: "o" };
    const check = s.server.checkCall(stampedParams(s, "list_issues", args, "call-1"));
    const attested = s.server.attest(check.session, RESULT, { rid: RID, callId: "call-1", name: "list_issues", args, caller: check.caller }, "third-party");
    const raw = JSON.parse(JSON.stringify(attested)) as Record<string, unknown>;
    const at = Date.now();
    const r = readToolResult(raw, attestedContext(s, "call-1", () => at));
    expect(r).toEqual({
      kind: "read",
      verification: "OK",
      verifiedAt: at,
      influence: { kind: "labels", labels: [{ cls: "third-party", cid: expect.any(String) }], hash: bindResult(RESULT) },
    });
  });
  it("aResponseVerifiesOnlyForTheClientItEndsAt", () => {
    const s = attestedSession();
    const args = { owner: "o" };
    const check = s.server.checkCall(stampedParams(s, "list_issues", args, "call-1"));
    expect(check.caller).toBe("pi");
    const attested = s.server.attest(check.session, RESULT, { rid: RID, callId: "call-1", name: "list_issues", args, caller: check.caller }, "third-party");
    const raw = JSON.parse(JSON.stringify(attested)) as Record<string, unknown>;
    const mine = readToolResult(raw, attestedContext(s, "call-1", () => PROMPT_TS, "pi"));
    expect(mine).toMatchObject({ kind: "read", verification: "OK", influence: { kind: "labels" } });
    const other = readToolResult(raw, attestedContext(s, "call-1", () => PROMPT_TS, "other"));
    expect(other).toEqual({ kind: "read", verification: "BINDING_MISMATCH", verifiedAt: PROMPT_TS, influence: { kind: "untrusted", hash: bindResult(RESULT) } });
  });
  it("failedVerificationIsUntrusted", () => {
    const s = attestedSession();
    const args = { owner: "o" };
    const check = s.server.checkCall(stampedParams(s, "list_issues", args, "call-1"));
    const attested = s.server.attest(check.session, RESULT, { rid: RID, callId: "call-1", name: "list_issues", args, caller: check.caller }, "public");
    const swapped = { ...attested, content: [{ type: "text", text: "injected" }] };
    const r = readToolResult(swapped, attestedContext(s, "call-1", () => PROMPT_TS));
    expect(r).toEqual({ kind: "read", verification: "BINDING_MISMATCH", verifiedAt: PROMPT_TS, influence: { kind: "untrusted", hash: bindResult(swapped) } });
  });
  it("unattestedResponseInAnAttestedSessionIsUntrusted", () => {
    const s = attestedSession();
    const r = readToolResult({ ...RESULT }, attestedContext(s, "call-1", () => PROMPT_TS));
    expect(r).toEqual({ kind: "read", verification: "CHAIN_MISSING", verifiedAt: PROMPT_TS, influence: { kind: "untrusted", hash: bindResult(RESULT) } });
  });
  it("noServerRootIsUntrustedWithoutVerifying", () => {
    const s = attestedSession();
    const ctx: ResultContext = { ...(attestedContext(s, "call-1", neverCalled) as Extract<ResultContext, { session: "attested" }>), reply: { ...s.reply, serverRoot: null } };
    expect(readToolResult({ ...RESULT }, ctx)).toEqual({ kind: "read", influence: { kind: "untrusted", hash: bindResult(RESULT) } });
  });
  it("unsafeSessionIsUntrusted", () => {
    expect(readToolResult({ ...RESULT }, { session: "unsafe" })).toEqual({ kind: "read", influence: { kind: "untrusted", hash: bindResult(RESULT) } });
  });
  it("refusalIsNeverRecorded", () => {
    const s = attestedSession();
    const refusal = { content: [{ type: "text", text: "refused" }], isError: true, _meta: { "paztport/verdict": { reason: "INFLUENCE_DENIED" } } };
    for (const ctx of [attestedContext(s, "call-1", neverCalled), { session: "unsafe" } as const, { session: "off" } as const]) {
      expect(readToolResult(refusal, ctx)).toEqual({ kind: "refused", verdict: "INFLUENCE_DENIED", influence: { kind: "none" } });
    }
  });
  it("unknownVerdictReasonIsUnknown", () => {
    for (const verdict of [{ reason: "OK" }, { reason: "<b>trust me</b>" }, { reason: 5 }, "INFLUENCE_DENIED", null]) {
      const r = readToolResult({ ...RESULT, _meta: { "paztport/verdict": verdict } }, { session: "unsafe" });
      expect(r).toEqual({ kind: "refused", verdict: "UNKNOWN", influence: { kind: "none" } });
    }
  });
  it("auditVerdictIsReadAsAnOrdinaryResult", () => {
    const raw = { ...RESULT, _meta: { "paztport/verdict": { reason: "INFLUENCE_DENIED", audit: true } } };
    expect(readToolResult(raw, { session: "unsafe" })).toEqual({
      kind: "read",
      verdict: "INFLUENCE_DENIED",
      influence: { kind: "untrusted", hash: bindResult(raw) },
    });
  });
  it("unhashableResultIsMalformed", () => {
    const s = attestedSession();
    const raw = { content: [{ type: "text", text: "\ud800" }] };
    expect(readToolResult(raw, { session: "unsafe" })).toEqual({ kind: "malformed" });
    expect(readToolResult(raw, attestedContext(s, "call-1", neverCalled))).toEqual({ kind: "malformed" });
  });
  it("offHashesAndRecordsNothing", () => {
    const raw = { content: [{ type: "text", text: "\ud800" }] };
    expect(readToolResult(raw, { session: "off" })).toEqual({ kind: "read", influence: { kind: "none" } });
  });
});
