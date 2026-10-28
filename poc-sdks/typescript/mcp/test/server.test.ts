// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  buildPolicy,
  canonicalize,
  decode,
  earliestNotAfter,
  generateKeyPair,
  issueReplyCert,
  signKeyring,
  signKeyringOldForm,
  utf8,
  verify,
  verifyRoot,
  verifySessionReply,
  type InfluenceClass,
  type InfluenceEntry,
  type SessionReply,
} from "@paztport/core";
import {
  checkServerPolicy,
  decideServerCall,
  InvalidParams,
  McpServerSession,
  META_ATTESTATION,
  verifyCall,
  type ServerPolicy,
  type Session,
  type SessionRules,
} from "../src/index.ts";
import { CLIENT_NOT_AFTER, CLIENT_POLICY, makeClient, type CallToolResult } from "./helpers/client.ts";

const RULES: SessionRules = {
  disabledWhenUnsafe: ["create_branch", "create_or_update_file", "push_files", "create_pull_request", "add_issue_comment"],
};

const DAY_MS = 86_400_000;
/** When the server's root and keyring stop being valid: 2100-01-01. */
const NOT_AFTER = 4_102_444_800_000;

/** A consistent server policy for `hops`, in the new form, with the policy key that signed it so a test can forge parts. */
function serverSetup(hops: readonly [string, string] = ["mcp-entry", "github-tools"]): { cfg: ServerPolicy; policyPrivateKey: string } {
  const [entryName, toolsName] = hops;
  const policy = generateKeyPair();
  const entry = generateKeyPair();
  const tools = generateKeyPair();
  const { signedRoot, bundles } = buildPolicy([[entryName, toolsName]], 8, policy.privateKey, NOT_AFTER);
  const ring = signKeyring({ [entryName]: entry.publicKey, [toolsName]: tools.publicKey }, policy.publicKey, policy.privateKey, NOT_AFTER);
  const cfg: ServerPolicy = {
    policyPublicKey: policy.publicKey,
    signingKeys: { [entryName]: entry.privateKey, [toolsName]: tools.privateKey },
    keyring: ring.services,
    keyringSig: ring.sig,
    keyringNotAfter: NOT_AFTER,
    replyCert: issueReplyCert(policy.publicKey, entryName, entry.publicKey, Date.now() + DAY_MS, policy.privateKey),
    signedRoot,
    routeProof: bundles[entryName]!.proofs[`${entryName}/${toolsName}`]!,
    inst: "mock-github-1",
    hops,
    serverId: "github",
    pinnedClientKeys: [CLIENT_POLICY.publicKey],
  };
  return { cfg, policyPrivateKey: policy.privateKey };
}

function serverConfig(): ServerPolicy {
  return serverSetup().cfg;
}

const RESULT: CallToolResult = { content: [{ type: "text", text: "hello" }] };
const CALL = { rid: "rid-1", callId: "call-1", name: "list_issues", args: { owner: "o", repo: "r" }, caller: "pi" };

describe("checkServerPolicy", () => {
  it("aConsistentPolicyPassesAndConstructs", () => {
    const cfg = serverConfig();
    expect(() => checkServerPolicy(cfg, Date.now())).not.toThrow();
    expect(() => checkServerPolicy(cfg, cfg.replyCert.notAfter)).not.toThrow();
    expect(() => new McpServerSession(cfg, RULES, Date.now)).not.toThrow();
  });
  it("refusesAKeyringItsPolicyKeyDidNotSign", () => {
    const { cfg } = serverSetup();
    const other = generateKeyPair();
    const bad: Record<string, ServerPolicy> = {
      tampered: { ...cfg, keyring: { ...cfg.keyring, "github-tools": generateKeyPair().publicKey } },
      unsigned: { ...cfg, keyringSig: "" },
      "signed by another key": { ...cfg, keyringSig: signKeyring(cfg.keyring, cfg.policyPublicKey, other.privateKey, NOT_AFTER).sig },
      "window moved": { ...cfg, keyringNotAfter: NOT_AFTER + 1 },
      "window dropped": { ...cfg, keyringNotAfter: undefined },
      "window not an integer": { ...cfg, keyringNotAfter: 1.5 },
    };
    for (const [name, policy] of Object.entries(bad)) {
      expect(() => checkServerPolicy(policy, Date.now()), name).toThrow("the keyring is not signed by policyPublicKey");
      expect(() => new McpServerSession(policy, RULES, Date.now), name).toThrow("the keyring is not signed by policyPublicKey");
    }
  });
  it("refusesAnEntryWithNoKeyringKeyOrAnotherSigningKey", () => {
    const { cfg, policyPrivateKey } = serverSetup();
    const { "mcp-entry": _gone, ...services } = cfg.keyring;
    const noEntry = { ...cfg, keyring: services, keyringSig: signKeyring(services, cfg.policyPublicKey, policyPrivateKey, NOT_AFTER).sig };
    expect(() => checkServerPolicy(noEntry, Date.now())).toThrow("the keyring has no key for the entry mcp-entry");
    const inherited = { ...noEntry, keyring: Object.create({ "mcp-entry": cfg.keyring["mcp-entry"] }) };
    Object.assign(inherited.keyring, services);
    expect(() => checkServerPolicy(inherited, Date.now())).toThrow(/keyring/);
    for (const key of [generateKeyPair().privateKey, cfg.signingKeys["github-tools"]!, "not-a-key"]) {
      const other = { ...cfg, signingKeys: { ...cfg.signingKeys, "mcp-entry": key } };
      expect(() => checkServerPolicy(other, Date.now())).toThrow("signingKeys[mcp-entry] is not the entry's keyring key");
      expect(() => new McpServerSession(other, RULES, Date.now)).toThrow("signingKeys[mcp-entry] is not the entry's keyring key");
    }
    const { "mcp-entry": _k, ...noSigningKey } = cfg.signingKeys;
    expect(() => checkServerPolicy({ ...cfg, signingKeys: noSigningKey }, Date.now())).toThrow("signingKeys[mcp-entry] is not the entry's keyring key");
  });
  it("refusesACertificateThatDoesNotCertifyTheEntryKey", () => {
    const { cfg, policyPrivateKey } = serverSetup();
    const later = Date.now() + DAY_MS;
    const entryKey = cfg.keyring["mcp-entry"]!;
    const another = generateKeyPair();
    const forged: Record<string, [ServerPolicy["replyCert"], string]> = {
      "for another service": [issueReplyCert(cfg.policyPublicKey, "github-tools", entryKey, later, policyPrivateKey), "replyCert is for github-tools, not the entry mcp-entry"],
      "for another key": [issueReplyCert(cfg.policyPublicKey, "mcp-entry", cfg.keyring["github-tools"]!, later, policyPrivateKey), "replyCert names a key other than the entry's keyring key"],
      "signed by another policy key": [issueReplyCert(cfg.policyPublicKey, "mcp-entry", entryKey, later, another.privateKey), "replyCert is not signed by policyPublicKey"],
      "naming another policy key": [issueReplyCert(another.publicKey, "mcp-entry", entryKey, later, another.privateKey), "replyCert is not signed by policyPublicKey"],
      expired: [issueReplyCert(cfg.policyPublicKey, "mcp-entry", entryKey, Date.now() - 1, policyPrivateKey), "replyCert expired at"],
    };
    for (const [name, [replyCert, why]] of Object.entries(forged)) {
      expect(() => checkServerPolicy({ ...cfg, replyCert }, Date.now()), name).toThrow(why);
      expect(() => new McpServerSession({ ...cfg, replyCert }, RULES, Date.now), name).toThrow(why);
    }
  });
  it("acceptsAnOldFormKeyringWithNoWindow", () => {
    // nothing is refused for being in the old form yet
    const { cfg, policyPrivateKey } = serverSetup();
    const { keyringNotAfter: _w, ...rest } = cfg;
    const old: ServerPolicy = { ...rest, keyringSig: signKeyringOldForm(cfg.keyring, cfg.policyPublicKey, policyPrivateKey).sig };
    expect(() => checkServerPolicy(old, Date.now())).not.toThrow();
  });
  it("judgesExpiryAtTheSessionsClock", () => {
    const cfg = serverConfig();
    const { notAfter } = cfg.replyCert;
    expect(() => new McpServerSession(cfg, RULES, () => notAfter)).not.toThrow();
    expect(() => new McpServerSession(cfg, RULES, () => notAfter + 1)).toThrow("replyCert expired at");
  });
});

describe("session handshake", () => {
  it("attestedWhenBothRoots", () => {
    const cfg = serverConfig();
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const reply = srv.openSession(makeClient({ withRoot: true }).request());
    expect(reply.status).toBe("attested");
    expect(reply.disabled).toEqual([]);
    expect(reply.serverRoot).toEqual(cfg.signedRoot);
    expect(reply.serverRoot!.notAfter).toBe(NOT_AFTER);
    expect(verifyRoot(reply.serverRoot!, cfg.policyPublicKey)).toBe(true);
    expect(srv.session()?.sess).toBe(reply.sess);
    expect(srv.session()?.status).toBe("attested");
  });
  it("aNewFormClientRootAndKeyringWindowSurviveParsing", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const req = makeClient().request();
    expect(req.clientRoot!.notAfter).toBe(CLIENT_NOT_AFTER);
    expect(req.clientKeyringNotAfter).toBe(CLIENT_NOT_AFTER);
    expect(srv.openSession(JSON.parse(JSON.stringify(req))).status).toBe("attested");
    expect(srv.session()!.request.clientRoot).toEqual(req.clientRoot);
    expect(srv.session()!.request.clientKeyringNotAfter).toBe(CLIENT_NOT_AFTER);
    // judged by value: an integer written with a fraction or an exponent is that integer
    const text = JSON.stringify(req).replace(`"clientKeyringNotAfter":${CLIENT_NOT_AFTER}`, `"clientKeyringNotAfter":${CLIENT_NOT_AFTER}.0`);
    expect(text).toContain(".0");
    expect(srv.openSession(JSON.parse(text)).status).toBe("attested");
  });
  it("aTamperedOrDroppedClientKeyringNotAfterIsUnsafe", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const req = makeClient().request();
    expect(srv.openSession({ ...req, clientKeyringNotAfter: CLIENT_NOT_AFTER + 1 }).status).toBe("unsafe");
    const { clientKeyringNotAfter: _w, ...dropped } = req;
    expect(srv.openSession(dropped).status).toBe("unsafe");
    expect(srv.openSession({ ...req, clientRoot: { ...req.clientRoot!, notAfter: CLIENT_NOT_AFTER + 1 } }).status).toBe("unsafe");
  });
  it("aMalformedNotAfterOpensNoSession", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const good = makeClient().request();
    expect(srv.openSession(good).status).toBe("attested");
    const current = srv.session();
    for (const bad of [1.5, -1, 2 ** 53, "x", null, true, {}, []]) {
      expect(() => srv.openSession({ ...good, clientKeyringNotAfter: bad }), `keyring ${String(bad)}`).toThrow(InvalidParams);
      expect(() => srv.openSession({ ...good, clientKeyringNotAfter: bad }), `keyring ${String(bad)}`).toThrow("clientKeyringNotAfter must be an integer in [0, 2^53 - 1]");
      expect(() => srv.openSession({ ...good, clientRoot: { ...good.clientRoot!, notAfter: bad } }), `root ${String(bad)}`).toThrow("clientRoot.notAfter must be an integer in [0, 2^53 - 1]");
    }
    // a request that opens no session leaves the current one in place
    expect(srv.session()).toBe(current);
  });
  it("anOldFormClientIsStillAttested", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const req = makeClient({ oldForm: true }).request();
    expect(Object.hasOwn(req, "clientKeyringNotAfter")).toBe(false);
    expect(Object.hasOwn(req.clientRoot!, "notAfter")).toBe(false);
    expect(srv.openSession(req).status).toBe("attested");
  });
  it("callsArePolicyExpiredOnceTheClientsRootOrKeyringWindowHasPassed", () => {
    const T = 1_900_000_000_000;
    for (const [what, opts] of [["keyring", { keyringNotAfter: T }], ["root", { rootNotAfter: T }]] as const) {
      let now = Date.now();
      const cfg = serverConfig();
      const srv = new McpServerSession(cfg, RULES, () => now);
      const client = makeClient(opts);
      const reply = srv.openSession(client.request());
      expect(reply.status, what).toBe("attested");
      expect(client.acceptReply(reply, cfg.policyPublicKey), what).toBe(true);
      now = T;
      expect(srv.checkCall(client.callParams("list_issues", { owner: "o" }, [], { now: T })).reason, `${what} at notAfter`).toBe("OK");
      now = T + 1;
      const r = srv.checkCall(client.callParams("list_issues", { owner: "o" }, [], { now: T + 1 }));
      expect({ reason: r.reason, caller: r.caller, influence: r.influence }, `${what} one ms past`).toEqual({ reason: "POLICY_EXPIRED", caller: "", influence: [] });
    }
  });
  it("anOldFormClientsCallsFailClosed", () => {
    const cfg = serverConfig();
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const client = makeClient({ oldForm: true });
    const reply = srv.openSession(client.request());
    expect(reply.status).toBe("attested");
    expect(client.acceptReply(reply, cfg.policyPublicKey)).toBe(true);
    expect(srv.checkCall(client.callParams("list_issues", { owner: "o" }, [])).reason).toBe("POLICY_EXPIRED");
  });
  it("unsafeWithoutClientRootDisablesWrites", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const reply = srv.openSession(makeClient({ withRoot: false }).request());
    expect(reply.status).toBe("unsafe");
    expect(reply.disabled).toEqual(RULES.disabledWhenUnsafe);
    expect(srv.session()?.status).toBe("unsafe");
  });
  it("aPinnedClientWithASignedKeyringIsAttested", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    expect(srv.openSession(makeClient().request()).status).toBe("attested");
  });
  it("anUnpinnedClientKeyIsUnsafe", () => {
    const srv = new McpServerSession({ ...serverConfig(), pinnedClientKeys: [generateKeyPair().publicKey] }, RULES, Date.now);
    const reply = srv.openSession(makeClient().request());
    expect(reply.status).toBe("unsafe");
    expect(reply.disabled).toEqual(RULES.disabledWhenUnsafe);
    const none = new McpServerSession({ ...serverConfig(), pinnedClientKeys: [] }, RULES, Date.now);
    expect(none.openSession(makeClient().request()).status).toBe("unsafe");
  });
  it("aRequestWithNoKeyringSignatureIsUnsafeNotInvalid", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const { clientKeyringSig: _sig, ...legacy } = makeClient().request();
    const reply = srv.openSession(legacy);
    expect(reply.status).toBe("unsafe");
    expect(reply.disabled).toEqual(RULES.disabledWhenUnsafe);
    expect(srv.session()?.status).toBe("unsafe");
  });
  it("replyVerifiesForClient", () => {
    const cfg = serverConfig();
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const client = makeClient();
    const reply = srv.openSession(client.request());
    expect(client.acceptReply(reply, cfg.policyPublicKey)).toBe(true);
    expect(client.acceptReply(reply, generateKeyPair().publicKey)).toBe(false);
  });
  it("replyCarriesKeyringSigAndEntrySignature", () => {
    const cfg = serverConfig();
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const client = makeClient();
    const req = client.request();
    const reply = srv.openSession(req);
    expect(reply.serverKeyring).toEqual(cfg.keyring);
    expect(reply.serverKeyringSig).toBe(cfg.keyringSig);
    expect(reply.serverKeyringNotAfter).toBe(NOT_AFTER);
    expect(reply.serverReplyCert).toEqual(cfg.replyCert);
    const { sig, ...body } = reply;
    const bytes = utf8("paztport-session-reply\n" + canonicalize(body));
    expect(verify(cfg.keyring["mcp-entry"]!, bytes, decode(sig))).toBe(true);
    expect(verify(cfg.policyPublicKey, bytes, decode(sig))).toBe(false);
    expect(verifySessionReply(reply, req, cfg.policyPublicKey, "mcp-entry", Date.now())).toBe(true);
    // stripped of its certificate and keyring signature, the reply is in the policy-key form, which it fails
    const { serverKeyringSig: _ks, serverReplyCert: _rc, ...stripped } = reply;
    expect(verifySessionReply(stripped as SessionReply, req, cfg.policyPublicKey, "mcp-entry", Date.now())).toBe(false);
    expect(client.acceptReply(reply, cfg.policyPublicKey)).toBe(true);
  });
  it("anOldFormKeyringReplyCarriesNoWindow", () => {
    const { cfg, policyPrivateKey } = serverSetup();
    const { keyringNotAfter: _w, ...rest } = cfg;
    const old: ServerPolicy = { ...rest, keyringSig: signKeyringOldForm(cfg.keyring, cfg.policyPublicKey, policyPrivateKey).sig };
    const client = makeClient();
    const reply = new McpServerSession(old, RULES, Date.now).openSession(client.request());
    expect(Object.hasOwn(reply, "serverKeyringNotAfter")).toBe(false);
    expect(client.acceptReply(reply, cfg.policyPublicKey)).toBe(true);
  });
  it("disabledInReplyIsACopy", () => {
    const rules: SessionRules = { disabledWhenUnsafe: ["create_branch"] };
    const srv = new McpServerSession(serverConfig(), rules, Date.now);
    const reply = srv.openSession(makeClient({ withRoot: false }).request());
    reply.disabled.push("list_issues");
    expect(rules.disabledWhenUnsafe).toEqual(["create_branch"]);
    expect(srv.openSession(makeClient({ withRoot: false }).request()).disabled).toEqual(["create_branch"]);
  });
  it("protoKeyInClientKeyringIsOrdinary", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const req = JSON.parse(JSON.stringify(makeClient().request()).replace('"clientKeyring":{', '"clientKeyring":{"__proto__":"k",'));
    srv.openSession(req);
    const ring = srv.session()!.request.clientKeyring;
    expect(Object.hasOwn(ring, "__proto__")).toBe(true);
    expect(ring["__proto__"]).toBe("k");
    expect(Object.keys(ring)).toContain("session");
  });
  it("malformedSessionRequestThrows", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    for (const bad of [null, "x", {}, { clientRoot: null, clientPolicyKey: 1, clientKeyring: {}, nonce: "n" }, { clientRoot: null, clientPolicyKey: "k", clientKeyring: [], nonce: "n" }, { clientRoot: { rootId: "v" }, clientPolicyKey: "k", clientKeyring: {}, nonce: "n" }]) {
      expect(() => srv.openSession(bad)).toThrow();
    }
    expect(srv.session()).toBeUndefined();
  });
});

describe("response attestation", () => {
  function setup() {
    const cfg = serverConfig();
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const client = makeClient();
    const reply = srv.openSession(client.request());
    expect(client.acceptReply(reply, cfg.policyPublicKey)).toBe(true);
    return { cfg, srv, client, reply };
  }
  it("attestedResponseVerifiesForClient", () => {
    const { srv, client, reply } = setup();
    const out = srv.attest(srv.session()!, RESULT, CALL, "third-party");
    const v = client.verify(out, { rid: CALL.rid, toolCallId: CALL.callId }, reply.serverKeyring, reply.serverRoot!);
    expect(v.reason).toBe("OK");
    expect(v.labels).toHaveLength(1);
    expect(v.labels[0]!.cls).toBe("third-party");
    expect(RESULT._meta).toBeUndefined();
  });
  it("attestationLabelMatchesClass", () => {
    const { srv } = setup();
    for (const cls of ["third-party", "private", "public", "local-untrusted"] as const) {
      const att = (srv.attest(srv.session()!, RESULT, CALL, cls)._meta as Record<string, any>)[META_ATTESTATION];
      expect(att.labels).toHaveLength(1);
      expect(att.labels[0].cls).toBe(cls);
      expect(typeof att.labels[0].cid).toBe("string");
      expect(att.chain.map((s: any) => s.svc)).toEqual(["mcp-entry", "github-tools"]);
    }
  });
  it("theResponseChainIsV3AndEndsAtTheCaller", () => {
    const { srv } = setup();
    const att = (srv.attest(srv.session()!, RESULT, { ...CALL, caller: "pi" }, "public")._meta as Record<string, any>)[META_ATTESTATION];
    expect(att.chain.map((s: any) => s.rcv)).toEqual(["github-tools", "pi"]);
    expect(att.chain.map((s: any) => s.v)).toEqual([3, 3]);
  });
  it("aResponseForAnotherCallerDoesNotVerifyForThisClient", () => {
    const { srv, client, reply } = setup();
    const out = srv.attest(srv.session()!, RESULT, { ...CALL, caller: "other" }, "public");
    expect(client.verify(out, { rid: CALL.rid, toolCallId: CALL.callId }, reply.serverKeyring, reply.serverRoot!).reason).toBe("BINDING_MISMATCH");
  });
  it("attestRecordsServedClass", () => {
    const { srv, client } = setup();
    expect([...srv.session()!.served]).toEqual([]);
    srv.attest(srv.session()!, RESULT, CALL, "third-party");
    srv.attest(srv.session()!, RESULT, { ...CALL, rid: "rid-2", callId: "call-2" }, "private");
    srv.attest(srv.session()!, RESULT, { ...CALL, rid: "rid-3", callId: "call-3" }, "third-party");
    expect(srv.session()!.served).toEqual(new Set(["third-party", "private"]));
    // a new handshake starts a new session with nothing served
    srv.openSession(client.request());
    expect(srv.session()!.served.size).toBe(0);
  });
  it("replayedResponseIsRejected", () => {
    const { srv, client, reply } = setup();
    const out = srv.attest(srv.session()!, RESULT, CALL, "public");
    const args = [{ rid: CALL.rid, toolCallId: CALL.callId }, reply.serverKeyring, reply.serverRoot!] as const;
    expect(client.verify(out, ...args).reason).toBe("OK");
    expect(client.verify(out, ...args).reason).toBe("REPLAY");
  });
  it("tamperedContentIsBindingMismatch", () => {
    const { srv, client, reply } = setup();
    const out = srv.attest(srv.session()!, RESULT, CALL, "private");
    const tampered: CallToolResult = { ...out, content: [{ type: "text", text: "hello, edited" }] };
    expect(client.verify(tampered, { rid: CALL.rid, toolCallId: CALL.callId }, reply.serverKeyring, reply.serverRoot!).reason).toBe("BINDING_MISMATCH");
  });
  it("responseIntoOtherSessionRejected", () => {
    const { srv, client: clientA, reply: replyA } = setup();
    const outA = srv.attest(srv.session()!, RESULT, CALL, "public");
    const clientB = makeClient();
    const replyB = srv.openSession(clientB.request());
    expect(clientB.acceptReply(replyB, replyA.serverPolicyKey)).toBe(true);
    expect(replyB.sess).not.toBe(replyA.sess);
    const v = clientB.verify(outA, { rid: CALL.rid, toolCallId: CALL.callId }, replyB.serverKeyring, replyB.serverRoot!);
    expect(v.reason).not.toBe("OK");
    expect(v.reason).toBe("SESSION_UNKNOWN");
    expect(v.labels).toEqual([]);
    // the response still verifies in the session it was made for
    expect(clientA.verify(outA, { rid: CALL.rid, toolCallId: CALL.callId }, replyA.serverKeyring, replyA.serverRoot!).reason).toBe("OK");
  });
  it("staleResponseIsExpired", () => {
    const { srv, client, reply } = setup();
    const out = srv.attest(srv.session()!, RESULT, CALL, "public");
    const v = client.verify(out, { rid: CALL.rid, toolCallId: CALL.callId }, reply.serverKeyring, reply.serverRoot!, Date.now() + 60_000);
    expect(v.reason).toBe("EXPIRED");
  });
  it("clientCallParamsVerifyOnServer", () => {
    const { srv, client } = setup();
    const s = srv.session()!;
    const params = client.callParams("list_issues", { owner: "o", repo: "r" }, [{ cls: "public", src: "x", h: "h" }]);
    const r = verifyCall(params, { serverId: "github" }, {
      keyring: s.request.clientKeyring,
      root: decode(s.request.clientRoot!.root),
      rootId: s.request.clientRoot!.rootId,
      allowedOrigins: ["session"],
      sess: s.sess,
      nonces: s.nonces,
      now: Date.now(),
      policyNotAfter: earliestNotAfter(s.request.clientRoot!.notAfter, s.request.clientKeyringNotAfter),
    });
    expect(r.result.reason).toBe("OK");
  });
  it("attestUsesVerifiedSession", () => {
    const { srv } = setup();
    // a session that is not the current one, as when a new handshake lands mid-call
    const other = { ...srv.session()!, sess: "verified-session-id", served: new Set<InfluenceClass>() };
    expect(other.sess).not.toBe(srv.session()!.sess);
    const out = srv.attest(other, RESULT, CALL, "private");
    const att = (out._meta as Record<string, any>)[META_ATTESTATION];
    expect(att.chain.map((s: any) => s.sess)).toEqual(["verified-session-id", "verified-session-id"]);
    expect(other.served).toEqual(new Set(["private"]));
    expect(srv.session()!.served.size).toBe(0);
  });
});

describe("call check", () => {
  function attested(tools?: string[], over: Partial<ServerPolicy> = {}) {
    const srv = new McpServerSession({ ...serverConfig(), ...over }, RULES, Date.now);
    const client = makeClient({ tools });
    const reply = srv.openSession(client.request());
    expect(client.acceptReply(reply, reply.serverPolicyKey)).toBe(true);
    return { srv, client };
  }
  it("checkCallNeedsAnAttestedSession", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    expect(() => srv.checkCall({ name: "list_issues" })).toThrow(/attested session/);
    srv.openSession(makeClient({ withRoot: false }).request());
    expect(() => srv.checkCall({ name: "list_issues" })).toThrow(/attested session/);
  });
  it("verifiedCallCarriesItsInfluence", () => {
    const { srv, client } = attested();
    const influence: InfluenceEntry[] = [{ cls: "private", src: "x", h: "h" }];
    const r = srv.checkCall(client.callParams("list_issues", { owner: "o", repo: "r" }, influence, { rid: "rid-9", callId: "call-9" }));
    expect(r).toMatchObject({ reason: "OK", rid: "rid-9", callId: "call-9", influence });
    expect(r.session).toBe(srv.session());
  });
  it("aVerifiedCallNamesItsCaller", () => {
    const { srv, client } = attested(["list_issues"]);
    expect(srv.checkCall(client.callParams("list_issues", { owner: "o", repo: "r" }, [])).caller).toBe("pi");
    const params = client.callParams("list_issues", { owner: "o", repo: "r" }, []);
    expect(srv.checkCall({ ...params, arguments: { owner: "x" } })).toMatchObject({ reason: "BINDING_MISMATCH", caller: "" });
    expect(srv.checkCall(client.callParams("create_branch", { owner: "o", repo: "r", branch: "x" }, []))).toMatchObject({
      reason: "CLIENT_PATH_NOT_ALLOWED",
      caller: "",
    });
  });
  it("pathNotAllowedIsReportedAsTheClients", () => {
    const { srv, client } = attested(["list_issues"]);
    const r = srv.checkCall(client.callParams("create_branch", { owner: "o", repo: "r", branch: "x" }, [{ cls: "private", src: "x", h: "h" }]));
    expect(r.reason).toBe("CLIENT_PATH_NOT_ALLOWED");
    expect(r.influence).toEqual([]);
  });
  it("checkCallUsesThePolicyServerId", () => {
    // the client's calls name mcp:github.<tool> as their receiver, so a server with another id refuses them
    const { srv, client } = attested(undefined, { serverId: "elsewhere" });
    expect(srv.checkCall(client.callParams("list_issues", { owner: "o", repo: "r" }, [])).reason).toBe("BINDING_MISMATCH");
  });
  it("undecodableClientRootIsChainMissing", () => {
    const { srv, client } = attested();
    srv.session()!.request.clientRoot!.root = "not base64url!";
    const r = srv.checkCall(client.callParams("list_issues", { owner: "o", repo: "r" }, []));
    expect(r).toMatchObject({ reason: "CHAIN_MISSING", rid: "", callId: "", influence: [], caller: "" });
  });
  it("attestSignsThePolicyHops", () => {
    const srv = new McpServerSession(serverSetup(["edge", "tools"]).cfg, RULES, Date.now);
    srv.openSession(makeClient().request());
    const att = (srv.attest(srv.session()!, RESULT, CALL, "public")._meta as Record<string, any>)[META_ATTESTATION];
    expect(att.chain.map((s: any) => s.svc)).toEqual(["edge", "tools"]);
    expect(att.chain.map((s: any) => s.inst)).toEqual(["mock-github-1", "mock-github-1"]);
    expect(att.chain.map((s: any) => s.rcv)).toEqual(["tools", "pi"]);
  });
});

describe("decideServerCall", () => {
  const entry = (cls: InfluenceClass): InfluenceEntry => ({ cls, src: "x", h: "h" });
  function sessions() {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    srv.openSession(makeClient().request());
    const attested = srv.session()!;
    srv.openSession(makeClient({ withRoot: false }).request());
    const unsafe = srv.session()!;
    expect([attested.status, unsafe.status]).toEqual(["attested", "unsafe"]);
    return { srv, attested, unsafe };
  }
  const write = (session: Session | undefined, clientInfluence: InfluenceEntry[], over: Partial<Parameters<typeof decideServerCall>[0]> = {}) =>
    decideServerCall({ tool: "create_branch", isWrite: true, publicDestination: true, session, clientInfluence, rules: RULES, ...over });

  it("clientInfluenceAloneDecides", () => {
    const { attested } = sessions();
    expect(write(attested, [entry("private"), entry("third-party")])).toBe("INFLUENCE_DENIED");
    expect(write(attested, [entry("private"), entry("local-untrusted")])).toBe("INFLUENCE_DENIED");
    expect(write(attested, [entry("third-party"), entry("public")])).toBe("OK");
    expect(write(attested, [])).toBe("OK");
  });
  it("servedClassesCountWhenTheClientOmitsThem", () => {
    const { srv, attested } = sessions();
    srv.attest(attested, RESULT, CALL, "private");
    expect(write(attested, [entry("third-party")])).toBe("INFLUENCE_DENIED");
    expect(write(attested, [])).toBe("OK");
    srv.attest(attested, RESULT, { ...CALL, rid: "rid-2", callId: "call-2" }, "third-party");
    expect(write(attested, [])).toBe("INFLUENCE_DENIED");
  });
  it("the owner of private data must be the destination owner", () => {
    const { attested } = sessions();
    const mine: InfluenceEntry[] = [entry("third-party"), { ...entry("private"), owner: "alice" }];
    expect(write(attested, mine, { destinationOwner: "alice" })).toBe("OK");
    expect(write(attested, mine, { destinationOwner: "bob" })).toBe("INFLUENCE_DENIED");
  });
  it("a served private class has no owner, so it is refused", () => {
    const { srv, attested } = sessions();
    srv.attest(attested, RESULT, CALL, "private");
    expect(write(attested, [entry("third-party")], { destinationOwner: "alice" })).toBe("INFLUENCE_DENIED");
  });
  it("onlyPublicWritesAreDecided", () => {
    const { attested } = sessions();
    attested.served.add("private");
    attested.served.add("third-party");
    expect(write(attested, [], { publicDestination: false })).toBe("OK");
    expect(write(attested, [], { tool: "list_issues", isWrite: false })).toBe("OK");
  });
  it("attestedSessionIgnoresTheUnsafeGate", () => {
    const { attested } = sessions();
    expect(RULES.disabledWhenUnsafe).toContain("create_branch");
    expect(write(attested, [])).toBe("OK");
  });
  it("unsafeGateRefusesListedTools", () => {
    const { unsafe } = sessions();
    expect(write(unsafe, [])).toBe("UNSAFE_SESSION");
    expect(write(unsafe, [], { publicDestination: false })).toBe("UNSAFE_SESSION");
    // no handshake yet is gated the same way
    expect(write(undefined, [])).toBe("UNSAFE_SESSION");
    expect(write(unsafe, [], { tool: "list_issues", isWrite: false })).toBe("OK");
  });
  it("writeLeftOutOfTheUnsafeListIsUngated", () => {
    const { unsafe } = sessions();
    const rules: SessionRules = { disabledWhenUnsafe: ["create_pull_request"] };
    unsafe.served.add("private");
    unsafe.served.add("third-party");
    expect(write(unsafe, [entry("private"), entry("third-party")], { rules })).toBe("OK");
    expect(write(undefined, [entry("private"), entry("third-party")], { rules })).toBe("OK");
    expect(write(unsafe, [], { rules, tool: "create_pull_request" })).toBe("UNSAFE_SESSION");
  });
});
