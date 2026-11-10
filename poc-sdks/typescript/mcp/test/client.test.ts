// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  bindPrompt,
  bindResult,
  buildPolicy,
  buildSessionReply,
  generateKeyPair,
  signReplyCert,
  mintOrigin,
  NonceCache,
  NONCE_TTL_MS,
  readChain,
  readInfluence,
  readProof,
  readSessionReply,
  readSessionRequest,
  replacementRequest,
  sessionRequest,
  signKeyring,
  signSessionReply,
  writeToken,
  type InfluenceEntry,
  type SessionRequest,
  type ReplyCert,
} from "@paztport/core";
import {
  classifySessionError,
  classifySessionReply,
  McpServerSession,
  META_CALL_ID,
  META_CHAIN,
  META_INFLUENCE,
  META_PROOF,
  openSession,
  readToolResult,
  stampToolCall,
  toolCallProof,
  type ResultContext,
  type ServerPolicy,
  type SessionRules,
} from "../src/index.ts";
import { sessionParams, tokenOf, type CallToolResult } from "./helpers/client.ts";

const RULES: SessionRules = { disabledWhenUnsafe: ["create_pull_request"] };
const TOOLS = ["list_issues", "create_pull_request"];
const CLIENT_HOPS = ["session", "pi"];
const SERVER_ORIGINS = ["mcp-entry"];
/** The policy key every test client signs with, so the test server can pin it. */
const CLIENT_POLICY = generateKeyPair();

const DAY_MS = 86_400_000;
/** When both sides' roots and keyrings stop being valid: 2100-01-01. */
const NOT_AFTER = 4_102_444_800_000;

type Certify = (p: { policy: { publicKey: string; privateKey: string }; keys: Record<string, string> }) => ReplyCert;

/** mcp-entry's certificate, valid for 30 days. */
const CERTIFY_ENTRY: Certify = ({ policy, keys }) => signReplyCert(policy.publicKey, "mcp-entry", keys["mcp-entry"]!, Date.now() + 30 * DAY_MS, policy.privateKey);

/**
 * A consistent server policy, and the certificate `certify` issues under its keys. McpServerSession refuses to start
 * with a bad certificate, so a test of a server that serves one anyway signs it into the reply itself. `windows`
 * replaces NOT_AFTER as the server root's or keyring's.
 */
function serverMaterial(
  certify: Certify = CERTIFY_ENTRY,
  windows: { rootNotAfter?: number; keyringNotAfter?: number } = {},
): { policy: ServerPolicy; served: ReplyCert } {
  const policy = generateKeyPair();
  const entry = generateKeyPair();
  const tools = generateKeyPair();
  const { signedRoot, bundles } = buildPolicy([["mcp-entry", "github-tools"]], 8, policy.privateKey, windows.rootNotAfter ?? NOT_AFTER);
  const ring = signKeyring(
    { "mcp-entry": entry.publicKey, "github-tools": tools.publicKey }, policy.publicKey, policy.privateKey, windows.keyringNotAfter ?? NOT_AFTER,
  );
  return {
    policy: {
      policyPublicKey: policy.publicKey,
      signingKeys: { "mcp-entry": entry.privateKey, "github-tools": tools.privateKey },
      keyring: ring.services,
      keyringSig: ring.sig,
      keyringNotAfter: ring.notAfter,
      replyCert: CERTIFY_ENTRY({ policy, keys: ring.services }),
      signedRoot,
      routeProof: bundles["mcp-entry"]!.proofs["mcp-entry/github-tools"]!,
      inst: "mock-github-1",
      hops: ["mcp-entry", "github-tools"],
      serverId: "github",
      pinnedClientKeys: [CLIENT_POLICY.publicKey],
      clientOrigins: ["session"],
    },
    served: certify({ policy, keys: ring.services }),
  };
}

function serverPolicy(): ServerPolicy {
  return serverMaterial().policy;
}

function clientMaterial() {
  const policy = CLIENT_POLICY;
  const session = generateKeyPair();
  const pi = generateKeyPair();
  const { signedRoot, bundles } = buildPolicy(TOOLS.map((t) => [...CLIENT_HOPS, `mcp:github.${t}`]), 8, policy.privateKey, NOT_AFTER);
  const ring = signKeyring({ session: session.publicKey, pi: pi.publicKey }, policy.publicKey, policy.privateKey, NOT_AFTER);
  return {
    signedRoot,
    policyPublicKey: policy.publicKey,
    keyring: ring.services,
    keyringSig: ring.sig,
    keyringNotAfter: ring.notAfter,
    sessionKey: session.privateKey,
    piKey: pi.privateKey,
    proofs: bundles["pi"]!.proofs,
  };
}

/**
 * A server and a client that completed the handshake; `withRoot: false` gives an unsafe session. With `served`, the
 * server is one that skipped the SDK's start-up check: its reply carries that certificate, signed by its entry key.
 */
function connected(opts: { withRoot?: boolean; policy?: ServerPolicy; served?: ReplyCert } = {}) {
  const policy = opts.policy ?? serverPolicy();
  const server = new McpServerSession(policy, RULES, Date.now, () => {});
  const client = clientMaterial();
  const req = sessionRequest({ ...client, signedRoot: opts.withRoot === false ? null : client.signedRoot });
  let token = server.openSession(sessionParams(req)).reply;
  if (opts.served !== undefined) {
    const { sig: _sig, ...body } = readSessionReply(token);
    token = writeToken(signSessionReply({ ...body, serverReplyCert: opts.served }, policy.signingKeys["mcp-entry"]!));
  }
  // the result as a client receives it, and the reply its token holds
  const result: unknown = JSON.parse(JSON.stringify({ reply: token }));
  return { policy, server, client, req, token, result, reply: readSessionReply(token) };
}

/** A paztport/session result carrying `reply`'s token, written whether or not a reply could hold it. */
const resultOf = (reply: unknown) => ({ reply: tokenOf(reply) });

function attestedSession() {
  const c = connected();
  const outcome = classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "mcp-entry", Date.now());
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
  const origin = mintOrigin({ svc: "session", rid: RID, ts: PROMPT_TS, bind: bindPrompt("a prompt"), sess: s.reply.sess, inst: "pi-1", rcv: "pi" }, s.client.sessionKey);
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

describe("classifySessionReply", () => {
  it("attestedReplyIsUsed", () => {
    const c = connected();
    const outcome = classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "mcp-entry", Date.now());
    expect(outcome).toEqual({ status: "attested", reply: c.reply });
  });
  it("unsafeReplyKeepsTheServersSession", () => {
    const c = connected({ withRoot: false });
    expect(classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "mcp-entry", Date.now())).toEqual({ status: "unsafe", reason: "UNSAFE", replaceSession: false });
  });
  it("malformedReplyIsReplaced", () => {
    const c = connected();
    const { sig: _sig, ...unsigned } = c.reply;
    const { serverKeyringNotAfter: _k, ...noRingWindow } = c.reply;
    const { notAfter: _n, ...rootWithoutWindow } = c.reply.serverRoot!;
    const bad = [
      "reply", {}, unsigned, { ...c.reply, status: "open" },
      // a new field present (even null) must be well formed
      { ...c.reply, serverKeyringSig: null }, { ...c.reply, serverReplyCert: {} },
      // so must a window, the keyring's or the root's, which neither may leave out
      noRingWindow, { ...c.reply, serverRoot: rootWithoutWindow },
      ...[1.5, -1, 2 ** 53, "x", null, true, {}, []].flatMap((bad) => [
        { ...c.reply, serverKeyringNotAfter: bad },
        { ...c.reply, serverRoot: { ...c.reply.serverRoot, notAfter: bad } },
      ]),
    ];
    // a result that is not a reply token, then reply tokens that do not read as a reply
    for (const result of [undefined, null, "reply", {}, { reply: null }, { reply: c.reply }, [c.token], ...bad.map(resultOf)]) {
      expect(classifySessionReply(result, c.req, c.policy.policyPublicKey, "mcp-entry", Date.now())).toEqual({
        status: "unsafe",
        reason: "MALFORMED_REPLY",
        replaceSession: true,
      });
    }
  });
  it("otherServerKeyIsAPinMismatch", () => {
    const c = connected();
    expect(classifySessionReply(c.result, c.req, generateKeyPair().publicKey, "mcp-entry", Date.now())).toEqual({ status: "unsafe", reason: "PIN_MISMATCH", replaceSession: true });
  });
  it("tamperedReplyIsABadSignature", () => {
    const c = connected();
    const tampered = resultOf({ ...c.reply, disabled: ["list_issues"] });
    expect(classifySessionReply(tampered, c.req, c.policy.policyPublicKey, "mcp-entry", Date.now())).toEqual({ status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true });
  });
  it("replyToAnotherRequestIsABadSignature", () => {
    const c = connected();
    const other = sessionRequest(c.client);
    expect(classifySessionReply(c.result, other, c.policy.policyPublicKey, "mcp-entry", Date.now())).toEqual({ status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true });
  });
  it("theServersReplyIsInTheEntryKeyForm", () => {
    const c = connected();
    expect(c.reply).toMatchObject({ serverKeyringSig: c.policy.keyringSig, serverReplyCert: c.policy.replyCert });
    // the client's own entry name decides; another one finds no certificate
    expect(classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "github-tools", Date.now())).toEqual({ status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true });
  });
  it("aReplyIsAcceptedUntilItsCertificatesNotAfter", () => {
    const c = connected();
    const { notAfter } = c.policy.replyCert;
    expect(classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "mcp-entry", notAfter).status).toBe("attested");
    expect(classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "mcp-entry", notAfter + 1)).toEqual({ status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true });
  });
  it("theServersKeyringAndRootWindowsAreCarried", () => {
    const c = connected();
    expect(c.reply).toMatchObject({ serverKeyringNotAfter: NOT_AFTER, serverRoot: { notAfter: NOT_AFTER } });
    const outcome = classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "mcp-entry", Date.now());
    expect(outcome.status).toBe("attested");
  });
  it("aReplyTokenHoldingANumberThatIsNotAProtocolIntegerIsMalformed", () => {
    // a reply's token holds protocol integers only
    const c = connected();
    const reply = c.reply;
    for (const raw of [
      { ...reply, serverReplyCert: { ...reply.serverReplyCert!, notAfter: reply.serverReplyCert!.notAfter + 0.5 } },
      { ...reply, serverKeyringNotAfter: NOT_AFTER + 0.5 },
      { ...reply, serverRoot: { ...reply.serverRoot!, notAfter: -1 } },
    ]) {
      expect(classifySessionReply(resultOf(raw), c.req, c.policy.policyPublicKey, "mcp-entry", Date.now())).toEqual({
        status: "unsafe",
        reason: "MALFORMED_REPLY",
        replaceSession: true,
      });
    }
  });
  it("aMovedServerKeyringNotAfterIsABadSignatureAndADroppedOneMalformed", () => {
    const c = connected();
    const { sig: _sig, ...body } = c.reply;
    const entryKey = c.policy.signingKeys["mcp-entry"]!;
    // re-signed by the entry key, so only the policy key's keyring signature can catch the move
    const moved = signSessionReply({ ...body, serverKeyringNotAfter: NOT_AFTER + 1 }, entryKey);
    expect(classifySessionReply(resultOf(moved), c.req, c.policy.policyPublicKey, "mcp-entry", Date.now())).toEqual({ status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true });
    // a keyring signature without its window is malformed, however it is signed
    const { serverKeyringNotAfter: _w, ...noWindow } = body;
    const dropped = signSessionReply(noWindow, entryKey);
    expect(classifySessionReply(resultOf(dropped), c.req, c.policy.policyPublicKey, "mcp-entry", Date.now())).toEqual({ status: "unsafe", reason: "MALFORMED_REPLY", replaceSession: true });
    // and changed in transit, the reply's own signature fails
    const tampered = resultOf({ ...c.reply, serverKeyringNotAfter: NOT_AFTER - 1 });
    expect(classifySessionReply(tampered, c.req, c.policy.policyPublicKey, "mcp-entry", Date.now()).status).toBe("unsafe");
  });
  it("aServerRootOrKeyringPastItsNotAfterIsABadSignature", () => {
    const T = Date.now() + 60_000;
    for (const [what, windows] of [["root", { rootNotAfter: T }], ["keyring", { keyringNotAfter: T }]] as const) {
      const c = connected({ policy: serverMaterial(CERTIFY_ENTRY, windows).policy });
      expect(classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "mcp-entry", T).status, `${what} at notAfter`).toBe("attested");
      expect(classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "mcp-entry", T + 1), `${what} one ms past`).toEqual({
        status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true,
      });
    }
  });
  it("aServerWithAnExpiredCertificateIsABadSignature", () => {
    const expired = serverMaterial(({ policy, keys }) => signReplyCert(policy.publicKey, "mcp-entry", keys["mcp-entry"]!, Date.now() - 1, policy.privateKey));
    const c = connected({ policy: expired.policy, served: expired.served });
    expect(classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "mcp-entry", Date.now())).toEqual({ status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true });
  });
  it("aServerWithAForgedCertificateIsABadSignature", () => {
    const forged: Record<string, Certify> = {
      "signed by another policy key": ({ policy, keys }) => signReplyCert(policy.publicKey, "mcp-entry", keys["mcp-entry"]!, Date.now() + DAY_MS, generateKeyPair().privateKey),
      "for another service": ({ policy, keys }) => signReplyCert(policy.publicKey, "github-tools", keys["mcp-entry"]!, Date.now() + DAY_MS, policy.privateKey),
      "for a key not the entry's": ({ policy, keys }) => signReplyCert(policy.publicKey, "mcp-entry", keys["github-tools"]!, Date.now() + DAY_MS, policy.privateKey),
    };
    for (const [name, certify] of Object.entries(forged)) {
      const { policy, served } = serverMaterial(certify);
      const c = connected({ policy, served });
      expect(classifySessionReply(c.result, c.req, c.policy.policyPublicKey, "mcp-entry", Date.now()), name).toEqual({ status: "unsafe", reason: "BAD_SIGNATURE", replaceSession: true });
    }
  });
});

describe("classifySessionReply: the result", () => {
  /** A result as the server's reply token arrives in it, signed as McpServerSession signs one. */
  function replyToken() {
    const { policy } = serverMaterial();
    const client = clientMaterial();
    const req = sessionRequest(client);
    const reply = buildSessionReply(
      { ...policy, entryPrivateKey: policy.signingKeys["mcp-entry"]! },
      req,
      { pinnedClientKeys: policy.pinnedClientKeys, disabledWhenUnsafe: RULES.disabledWhenUnsafe },
      Date.now(),
    );
    const classify = (result: unknown) => classifySessionReply(result, req, policy.policyPublicKey, "mcp-entry", Date.now());
    return { token: writeToken(reply), reply, classify };
  }
  it("aResultWithAReplyTokenIsAttested", () => {
    const { token, reply, classify } = replyToken();
    expect(classify({ reply: token })).toEqual({ status: "attested", reply });
    expect(classify({ reply: token, _meta: { progressToken: 1 } })).toEqual({ status: "attested", reply });
  });
  it("aResultWithAnotherMemberIsMalformed", () => {
    const { token, classify } = replyToken();
    const malformed = { status: "unsafe", reason: "MALFORMED_REPLY", replaceSession: true };
    expect(classify({ reply: token }).status).toBe("attested");
    expect(classify({ reply: token, other: 1 })).toEqual(malformed);
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
  it("replacesAnAttestedSessionTheClientCannotUse", () => {
    const c = connected();
    expect(c.server.session()?.status).toBe("attested");
    c.server.openSession(sessionParams(replacementRequest(c.req)));
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
    const [origin, hop] = readChain(params._meta[META_CHAIN]!);
    expect(origin!.svc).toBe("session");
    expect(hop).toMatchObject({ svc: "pi", rid: RID, sess: s.reply.sess, prev: origin!.sig });
    expect(readProof(params._meta[META_PROOF]!)).toEqual(toolCallProof(s.client.proofs, CLIENT_HOPS, "github", "list_issues"));
    expect(readInfluence(params._meta[META_INFLUENCE]!)).toEqual([]);
    expect(params._meta[META_CALL_ID]).toBe("call-1");
  });
  it("theHopNamesTheToolAsItsReceiverAndTheOriginIsUnchanged", () => {
    const s = attestedSession();
    const proof = toolCallProof(s.client.proofs, CLIENT_HOPS, "github", "create_pull_request")!;
    const origin = mintOrigin({ svc: "session", rid: RID, ts: PROMPT_TS, bind: bindPrompt("a prompt"), sess: s.reply.sess, inst: "pi-1", rcv: "pi" }, s.client.sessionKey);
    const before = structuredClone(origin);
    const _meta = stampToolCall(
      { name: "create_pull_request", args: { title: "t" }, callId: "call-1" },
      { origin, svc: "pi", inst: "pi-1", privateKey: s.client.piKey, ts: Date.now(), influence: [], proof, serverId: "github" },
    );
    const chain = readChain(_meta[META_CHAIN]!);
    expect(origin).toEqual(before);
    expect(chain[0]).toEqual(origin);
    expect(chain[1]).toMatchObject({ v: 3, svc: "pi", rcv: "mcp:github.create_pull_request", prev: origin.sig });
  });
  describe("refusesANameThatIsNotARouteNode", () => {
    const s = attestedSession();
    const proof = toolCallProof(s.client.proofs, CLIENT_HOPS, "github", "list_issues")!;
    const origin = mintOrigin({ svc: "session", rid: RID, ts: PROMPT_TS, bind: bindPrompt("a prompt"), sess: s.reply.sess, inst: "pi-1", rcv: "pi" }, s.client.sessionKey);
    const stamp = (svc: string, serverId: string, name = "list_issues") =>
      stampToolCall({ name, args: {}, callId: "call-1" }, { origin, svc, inst: "pi-1", privateKey: s.client.piKey, ts: Date.now(), influence: [], proof, serverId });
    it("anEmptySvc", () => expect(() => stamp("", "github")).toThrow(/^svc must be a route node/));
    it("aSvcWithASlash", () => expect(() => stamp("a/b", "github")).toThrow(/^svc must be a route node/));
    it("aServerIdWithASlash", () => expect(() => stamp("pi", "git/hub")).toThrow(/^rcv must be a route node/));
    it("aToolNameWithTheDelimiter", () => expect(() => stamp("pi", "github", "a|b")).toThrow(/^rcv must be a route node/));
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
    expect(s.server.checkCall({ ...params, _meta: { ...params._meta, [META_INFLUENCE]: writeToken([]) } }).reason).toBe("INFLUENCE_MISMATCH");
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
  it("aResponseIsPolicyExpiredOnceTheServersRootOrKeyringWindowHasPassed", () => {
    const s = attestedSession();
    const args = { owner: "o" };
    const check = s.server.checkCall(stampedParams(s, "list_issues", args, "call-1"));
    const attested = s.server.attest(check.session, RESULT, { rid: RID, callId: "call-1", name: "list_issues", args, caller: check.caller }, "third-party");
    const raw = JSON.parse(JSON.stringify(attested)) as Record<string, unknown>;
    const at = Date.now();
    // The reply was verified at the handshake; only its windows are moved here, to reach the response check.
    const read = (reply: typeof s.reply) => readToolResult(raw, { ...(attestedContext(s, "call-1", () => at) as Extract<ResultContext, { session: "attested" }>), reply });
    const expired = { kind: "read", verification: "POLICY_EXPIRED", verifiedAt: at, influence: { kind: "untrusted", hash: bindResult(RESULT) } };
    expect(read({ ...s.reply, serverRoot: { ...s.reply.serverRoot!, notAfter: at }, serverKeyringNotAfter: at })).toMatchObject({ verification: "OK" });
    expect(read({ ...s.reply, serverRoot: { ...s.reply.serverRoot!, notAfter: at - 1 } })).toEqual(expired);
    expect(read({ ...s.reply, serverKeyringNotAfter: at - 1 })).toEqual(expired);
    const { notAfter: _w, ...noWindow } = s.reply.serverRoot!;
    expect(read({ ...s.reply, serverRoot: noWindow as typeof s.reply.serverRoot }), "a root without a window fails closed").toEqual(expired);
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
    const refusal = { content: [{ type: "text", text: "refused" }], isError: true, _meta: { "paztport/verdict": writeToken({ reason: "INFLUENCE_DENIED" }) } };
    for (const ctx of [attestedContext(s, "call-1", neverCalled), { session: "unsafe" } as const, { session: "off" } as const]) {
      expect(readToolResult(refusal, ctx)).toEqual({ kind: "refused", verdict: "INFLUENCE_DENIED", influence: { kind: "none" } });
    }
  });
  it("unknownVerdictReasonIsUnknown", () => {
    // a reason that is not a refusal code, and a token that does not read as a verdict
    const tokens = [{ reason: "OK" }, { reason: "<b>trust me</b>" }, { reason: 5 }, { reason: "INFLUENCE_DENIED", audit: false }, "INFLUENCE_DENIED", null, {}].map(tokenOf);
    for (const verdict of [...tokens, "", "not a token", 5, null]) {
      const r = readToolResult({ ...RESULT, _meta: { "paztport/verdict": verdict } }, { session: "unsafe" });
      expect(r, String(verdict)).toEqual({ kind: "refused", verdict: "UNKNOWN", influence: { kind: "none" } });
    }
  });
  it("aVerdictThatIsNotATokenIsAnUnknownRefusal", () => {
    // a verdict sent as the object itself, not its token: withheld, never success or an audit note
    for (const verdict of [{ reason: "PATH_NOT_ALLOWED" }, { reason: "INFLUENCE_DENIED", audit: true }]) {
      const r = readToolResult({ ...RESULT, _meta: { "paztport/verdict": verdict } }, { session: "unsafe" });
      expect(r).toEqual({ kind: "refused", verdict: "UNKNOWN", influence: { kind: "none" } });
    }
  });
  it("offlineOnlyReasonIsNotAServerVerdict", () => {
    for (const reason of ["TIME_MISMATCH", "PROMPT_MISMATCH", "OUTSIDE_SESSION", "PROOF_MISMATCH", "RULES_MISMATCH", "VERDICT_MISMATCH"]) {
      const r = readToolResult({ ...RESULT, _meta: { "paztport/verdict": writeToken({ reason }) } }, { session: "unsafe" });
      expect(r).toEqual({ kind: "refused", verdict: "UNKNOWN", influence: { kind: "none" } });
    }
  });
  it("auditVerdictIsReadAsAnOrdinaryResult", () => {
    const raw = { ...RESULT, _meta: { "paztport/verdict": writeToken({ reason: "INFLUENCE_DENIED", audit: true }) } };
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

describe("openSession", () => {
  const opts = (c: ReturnType<typeof connected>, send: (params: { request: string }) => Promise<unknown>) => ({
    request: c.req,
    pin: c.policy.policyPublicKey,
    serverEntry: "mcp-entry",
    now: Date.now,
    send,
    rpcCode: (e: unknown) => (e as { code?: number }).code,
  });

  it("anAttestedReplyIsOneExchange", async () => {
    const c = connected();
    const sent: { request: string }[] = [];
    const opened = await openSession(opts(c, async (p) => (sent.push(p), c.result)));
    expect(opened.outcome.status).toBe("attested");
    // the params hold only the request's token
    expect(sent).toEqual([{ request: writeToken(c.req) }]);
    expect(opened.exchanges).toEqual([{ request: writeToken(c.req), reply: c.token }]);
  });

  it("anUnsafeReplyIsNotReplaced", async () => {
    const c = connected({ withRoot: false });
    const sent: { request: string }[] = [];
    const opened = await openSession(opts(c, async (p) => (sent.push(p), c.result)));
    expect(opened.outcome).toEqual({ status: "unsafe", reason: "UNSAFE", replaceSession: false });
    expect(sent.map((p) => readSessionRequest(p.request))).toEqual([c.req]);
  });

  it("methodNotFoundIsNotReplaced", async () => {
    const c = connected();
    const opened = await openSession(opts(c, async () => Promise.reject({ code: -32601 })));
    expect(opened.outcome).toMatchObject({ status: "unsafe", reason: "METHOD_NOT_FOUND" });
    expect(opened.exchanges).toEqual([{ request: writeToken(c.req), reply: null }]);
  });

  it("anUnusableReplyIsReplacedWithANullRootAndStaysUnsafeWhateverComesBack", async () => {
    const c = connected();
    const other = connected();
    const sent: SessionRequest[] = [];
    // the first reply answers another request; the replacement's reply is a genuine attested one for the first request
    const opened = await openSession(opts(c, async (p) => (sent.push(readSessionRequest(p.request)), sent.length === 1 ? other.result : c.result)));
    expect(opened.outcome).toMatchObject({ status: "unsafe", replaceSession: true });
    expect(sent).toHaveLength(2);
    expect(sent[1]).toEqual({ ...replacementRequest(c.req), nonce: sent[1]!.nonce });
    expect(sent[1]!.nonce).not.toBe(c.req.nonce);
    expect(sent[1]!.clientRoot).toBeNull();
    expect(opened.exchanges.map((e) => e.reply)).toEqual([other.token, c.token]);
  });

  it("anExchangeRecordsTheReplyOnlyWhenItIsAString", async () => {
    const c = connected();
    for (const [result, reply] of [[{ reply: 5 }, null], [{ reply: c.token, other: 1 }, c.token], ["x", null], [null, null], [undefined, null]] as const) {
      const opened = await openSession(opts(c, async () => result));
      expect(opened.outcome, String(result)).toMatchObject({ status: "unsafe", reason: "MALFORMED_REPLY" });
      expect(opened.exchanges[0]!.reply, String(result)).toBe(reply);
    }
  });

  it("onExchangeReportsTheFirstExchangeBeforeTheReplacementIsSent", async () => {
    const c = connected();
    const events: string[] = [];
    await openSession({
      ...opts(c, async () => {
        events.push("send");
        return Promise.reject({ code: -32603 });
      }),
      onExchange: (x, outcome) => events.push(`exchange:${readSessionRequest(x.request).clientRoot === null ? "replacement" : "first"}:${outcome.status}`),
    });
    expect(events).toEqual(["send", "exchange:first:unsafe", "send", "exchange:replacement:unsafe"]);
  });

  it("aFailedReplacementIsRecordedAsNoReply", async () => {
    const c = connected();
    let n = 0;
    const opened = await openSession(opts(c, async () => (++n === 1 ? Promise.reject({ code: -32603 }) : Promise.reject(new Error("closed")))));
    expect(opened.outcome).toEqual({ status: "unsafe", reason: "HANDSHAKE_ERROR", replaceSession: true });
    expect(opened.exchanges.map((e) => e.reply)).toEqual([null, null]);
  });
});
