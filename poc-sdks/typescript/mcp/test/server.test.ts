// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
  buildPolicy,
  canonicalize,
  decideServerCall,
  decode,
  earliestNotAfter,
  encode,
  expiryWarnings,
  generateKeyPair,
  readAttestation,
  readSessionReply,
  readToken,
  signReplyCert,
  signKeyring,
  sign,
  utf8,
  verify,
  verifyRoot,
  verifySessionReply,
  writeToken,
  type InfluenceClass,
  type InfluenceEntry,
  type SessionReply,
} from "@paztport/core";
import {
  checkServerPolicy,
  handleToolCall,
  InvalidParams,
  McpServerSession,
  META_ATTESTATION,
  META_CALL_ID,
  META_VERDICT,
  readVerdict,
  verifyCall,
  type ServerPolicy,
  type Session,
  type SessionRules,
} from "../src/index.ts";
import { CLIENT_NOT_AFTER, CLIENT_POLICY, makeClient, sessionParams, tokenOf, type CallToolResult } from "./helpers/client.ts";

const RULES: SessionRules = {
  disabledWhenUnsafe: ["create_branch", "create_or_update_file", "push_files", "create_pull_request", "add_issue_comment"],
};

const DAY_MS = 86_400_000;
/** When the server's root and keyring stop being valid: 2100-01-01. */
const NOT_AFTER = 4_102_444_800_000;

/**
 * A consistent server policy for `hops`, with the policy key that signed it so a test can forge
 * parts; `windows` replaces NOT_AFTER as the root's or the keyring's.
 */
function serverSetup(
  hops: readonly [string, string] = ["mcp-entry", "github-tools"],
  windows: { rootNotAfter?: number; keyringNotAfter?: number } = {},
): { cfg: ServerPolicy; policyPrivateKey: string } {
  const [entryName, toolsName] = hops;
  const policy = generateKeyPair();
  const entry = generateKeyPair();
  const tools = generateKeyPair();
  const { signedRoot, bundles } = buildPolicy([[entryName, toolsName]], 8, policy.privateKey, windows.rootNotAfter ?? NOT_AFTER);
  const keyringNotAfter = windows.keyringNotAfter ?? NOT_AFTER;
  const ring = signKeyring({ [entryName]: entry.publicKey, [toolsName]: tools.publicKey }, policy.publicKey, policy.privateKey, keyringNotAfter);
  const cfg: ServerPolicy = {
    policyPublicKey: policy.publicKey,
    signingKeys: { [entryName]: entry.privateKey, [toolsName]: tools.privateKey },
    keyring: ring.services,
    keyringSig: ring.sig,
    keyringNotAfter,
    replyCert: signReplyCert(policy.publicKey, entryName, entry.publicKey, Date.now() + 30 * DAY_MS, policy.privateKey),
    signedRoot,
    routeProof: bundles[entryName]!.proofs[`${entryName}/${toolsName}`]!,
    inst: "mock-github-1",
    hops,
    serverId: "github",
    pinnedClientKeys: [CLIENT_POLICY.publicKey],
    clientOrigins: ["session"],
  };
  return { cfg, policyPrivateKey: policy.privateKey };
}

function serverConfig(): ServerPolicy {
  return serverSetup().cfg;
}

/** Opens a session with the params a client sends for `request`, and reads the reply token the server answers with. */
function handshake(srv: McpServerSession, request: unknown): SessionReply {
  return readSessionReply(srv.openSession(sessionParams(request)).reply);
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
  it("refusesAMissingOrEmptyClientOrigins", () => {
    const cfg = serverConfig();
    const { clientOrigins: _omitted, ...without } = cfg;
    for (const [what, policy] of [["missing", without as ServerPolicy], ["empty", { ...cfg, clientOrigins: [] }], ["blank", { ...cfg, clientOrigins: [""] }]] as const) {
      expect(() => checkServerPolicy(policy, Date.now()), what).toThrow("clientOrigins must name at least one origin service");
      expect(() => new McpServerSession(policy, RULES, Date.now), what).toThrow("clientOrigins must name at least one origin service");
    }
  });
  it("refusesAMissingOrEmptyClientOriginsRegardlessOfShape", () => {
    expect(() => new McpServerSession({ ...serverConfig(), clientOrigins: "session" as unknown as string[] }, RULES, Date.now)).toThrow("clientOrigins");
  });
  it("refusesAKeyringItsPolicyKeyDidNotSign", () => {
    const { cfg } = serverSetup();
    const other = generateKeyPair();
    const bad: Record<string, ServerPolicy> = {
      tampered: { ...cfg, keyring: { ...cfg.keyring, "github-tools": generateKeyPair().publicKey } },
      unsigned: { ...cfg, keyringSig: "" },
      "signed by another key": { ...cfg, keyringSig: signKeyring(cfg.keyring, cfg.policyPublicKey, other.privateKey, NOT_AFTER).sig },
      "window moved": { ...cfg, keyringNotAfter: NOT_AFTER + 1 },
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
      "for another service": [signReplyCert(cfg.policyPublicKey, "github-tools", entryKey, later, policyPrivateKey), "replyCert is for github-tools, not the entry mcp-entry"],
      "for another key": [signReplyCert(cfg.policyPublicKey, "mcp-entry", cfg.keyring["github-tools"]!, later, policyPrivateKey), "replyCert names a key other than the entry's keyring key"],
      "signed by another policy key": [signReplyCert(cfg.policyPublicKey, "mcp-entry", entryKey, later, another.privateKey), "replyCert is not signed by policyPublicKey"],
      "naming another policy key": [signReplyCert(another.publicKey, "mcp-entry", entryKey, later, another.privateKey), "replyCert is not signed by policyPublicKey"],
      expired: [signReplyCert(cfg.policyPublicKey, "mcp-entry", entryKey, Date.now() - 1, policyPrivateKey), "replyCert expired at"],
    };
    for (const [name, [replyCert, why]] of Object.entries(forged)) {
      expect(() => checkServerPolicy({ ...cfg, replyCert }, Date.now()), name).toThrow(why);
      expect(() => new McpServerSession({ ...cfg, replyCert }, RULES, Date.now), name).toThrow(why);
    }
  });
  it("refusesAKeyringWithoutAWindowAsItRefusesOneThatIsNotAnInteger", () => {
    // signed over its services and policy key alone, so only the missing window refuses it
    const { cfg, policyPrivateKey } = serverSetup();
    const { keyringNotAfter: _w, ...rest } = cfg;
    const keyringSig = encode(sign(policyPrivateKey, utf8("paztport-keyring\n" + canonicalize({ policy: cfg.policyPublicKey, services: cfg.keyring }))));
    const noWindow = { ...rest, keyringSig } as ServerPolicy;
    expect(() => checkServerPolicy(noWindow, Date.now())).toThrow("the keyring is not signed by policyPublicKey");
    expect(() => new McpServerSession(noWindow, RULES, Date.now)).toThrow("the keyring is not signed by policyPublicKey");
  });
  it("expiredKeyring", () => {
    const { cfg } = serverSetup(undefined, { keyringNotAfter: 5_000 });
    expect(() => checkServerPolicy(cfg, 5_000)).not.toThrow();
    expect(() => checkServerPolicy(cfg, 5_001)).toThrow("the keyring expired at 5000 (1970-01-01T00:00:05.000Z)");
  });
  it("anExpiredRootIsRefused", () => {
    const { cfg } = serverSetup(undefined, { rootNotAfter: 5_000 });
    expect(() => checkServerPolicy(cfg, 5_001)).toThrow("the root expired at 5000");
  });
  it("refusesARootWithoutAWindowAsItRefusesOneThatIsNotAnInteger", () => {
    const { cfg, policyPrivateKey } = serverSetup();
    const { notAfter: _n, ...root } = cfg.signedRoot;
    const noWindow = { ...root, sig: encode(sign(policyPrivateKey, utf8(`${root.rootId}|${root.root}`))) } as typeof cfg.signedRoot;
    for (const signedRoot of [noWindow, { ...cfg.signedRoot, notAfter: 1.5 }]) {
      expect(() => checkServerPolicy({ ...cfg, signedRoot }, Date.now())).toThrow("the root is not signed by policyPublicKey");
    }
  });
  it("rootNotSignedByPolicyKey", () => {
    const { cfg } = serverSetup();
    const other = serverSetup().cfg.signedRoot;
    for (const signedRoot of [other, { ...cfg.signedRoot, sig: other.sig }, { ...cfg.signedRoot, notAfter: NOT_AFTER + 1 }]) {
      expect(() => checkServerPolicy({ ...cfg, signedRoot }, Date.now())).toThrow("the root is not signed by policyPublicKey");
    }
  });
  it("routeProofDoesNotProve", () => {
    const { cfg } = serverSetup();
    const elsewhere = serverSetup(["mcp-entry", "other-tools"]).cfg.routeProof;
    expect(() => checkServerPolicy({ ...cfg, routeProof: elsewhere }, Date.now())).toThrow("the route proof for mcp-entry/github-tools does not prove against the root");
  });
  it("toolsKeyMismatch", () => {
    const { cfg } = serverSetup();
    for (const key of [generateKeyPair().privateKey, cfg.signingKeys["mcp-entry"]!, "not-a-key"]) {
      const bad = { ...cfg, signingKeys: { ...cfg.signingKeys, "github-tools": key } };
      expect(() => checkServerPolicy(bad, Date.now())).toThrow("signingKeys[github-tools] is not the tools hop's keyring key");
    }
    const { "github-tools": _t, ...noKey } = cfg.signingKeys;
    expect(() => checkServerPolicy({ ...cfg, signingKeys: noKey }, Date.now())).toThrow("signingKeys[github-tools]");
  });
  it("aKeyringSignedWithoutTheToolsHopIsRefused", () => {
    const { cfg, policyPrivateKey } = serverSetup();
    const { "github-tools": _gone, ...services } = cfg.keyring;
    const ring = signKeyring(services, cfg.policyPublicKey, policyPrivateKey, NOT_AFTER);
    expect(() => checkServerPolicy({ ...cfg, keyring: ring.services, keyringSig: ring.sig }, Date.now())).toThrow("the keyring has no key for the tools hop github-tools");
  });
  it("aToolsHopNamedOnlyByInheritanceHasNoKey", () => {
    const { cfg, policyPrivateKey } = serverSetup();
    const { "github-tools": inheritedKey, ...services } = cfg.keyring;
    const ring = signKeyring(services, cfg.policyPublicKey, policyPrivateKey, NOT_AFTER);
    // canonicalize refuses a prototype-bearing keyring, so the signature check fails before the own-member check can run
    const keyring = Object.assign(Object.create({ "github-tools": inheritedKey }), services) as Record<string, string>;
    expect(() => checkServerPolicy({ ...cfg, keyring, keyringSig: ring.sig }, Date.now())).toThrow("the keyring is not signed by policyPublicKey");
  });
  it("aNotAfterBeyondDateRangeNeverMakesAMessageThrow", () => {
    const big = Number.MAX_SAFE_INTEGER;
    const { cfg } = serverSetup(undefined, { keyringNotAfter: big });
    expect(() => checkServerPolicy(cfg, Date.now())).not.toThrow();
    expect(() => checkServerPolicy(cfg, big + 1)).toThrow(`the keyring expired at ${big}`);
    const { cfg: c2 } = serverSetup(undefined, { rootNotAfter: 1 });
    expect(() => checkServerPolicy(c2, 2)).toThrow("the root expired at 1 (1970-01-01T00:00:00.001Z)");
    const warned: string[] = [];
    new McpServerSession(cfg, RULES, Date.now, (m) => warned.push(m));
    expect(warned.every((m) => !m.includes("keyring"))).toBe(true);
  });
  it("warnsNearExpiry", () => {
    const now = Date.now();
    const near = now + 41 * 3_600_000;
    const { cfg, policyPrivateKey } = serverSetup(undefined, { keyringNotAfter: near, rootNotAfter: near });
    const warned: string[] = [];
    // the default certificate is long-lived, so only the keyring and root warn
    new McpServerSession(cfg, RULES, () => now, (m) => warned.push(m));
    expect(warned).toHaveLength(2);
    expect(warned[0]).toContain("keyring");
    expect(warned[0]).toContain(`notAfter ${near} (${new Date(near).toISOString()})`);
    expect(warned[1]).toContain("root");
    const certNear = { ...cfg, replyCert: signReplyCert(cfg.policyPublicKey, "mcp-entry", cfg.keyring["mcp-entry"]!, near, policyPrivateKey) };
    expect(expiryWarnings(certNear, now).map((m) => m.includes("replyCert"))).toContain(true);
    const { cfg: farCfg, policyPrivateKey: farKey } = serverSetup();
    const far = { ...farCfg, replyCert: signReplyCert(farCfg.policyPublicKey, "mcp-entry", farCfg.keyring["mcp-entry"]!, now + 30 * DAY_MS, farKey) };
    const quiet: string[] = [];
    new McpServerSession(far, RULES, () => now, (m) => quiet.push(m));
    expect(quiet).toEqual([]);
  });
  it("judgesExpiryAtTheSessionsClock", () => {
    const cfg = serverConfig();
    const { notAfter } = cfg.replyCert;
    expect(() => new McpServerSession(cfg, RULES, () => notAfter, () => {})).not.toThrow();
    expect(() => new McpServerSession(cfg, RULES, () => notAfter + 1)).toThrow("replyCert expired at");
  });
});

describe("session handshake", () => {
  it("aRequestObjectAsParamsIsInvalidParams", () => {
    // the request itself, not its token, as a peer that sends values would
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const request = makeClient().request();
    expect(() => srv.openSession(request)).toThrow(InvalidParams);
    expect(() => srv.openSession({ request })).toThrow(new InvalidParams("member request is not a string"));
    expect(srv.session()).toBeUndefined();
  });
  it("aRequestWithMetaOpensItsSession", () => {
    // MCP allows _meta, such as a progress token, on every request; it is not the request's
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const { reply } = srv.openSession({ ...sessionParams(makeClient().request()), _meta: { progressToken: 1 } });
    expect(readSessionReply(reply).status).toBe("attested");
    expect(srv.session()?.status).toBe("attested");
  });
  it("aRequestWithAnotherMemberIsInvalidParams", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const params = { ...sessionParams(makeClient().request()), other: 1 };
    expect(() => srv.openSession(params)).toThrow(InvalidParams);
    expect(srv.session()).toBeUndefined();
  });
  it("attestedWhenBothRoots", () => {
    const cfg = serverConfig();
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const reply = handshake(srv, makeClient({ withRoot: true }).request());
    expect(reply.status).toBe("attested");
    expect(reply.disabled).toEqual([]);
    expect(reply.serverRoot).toEqual(cfg.signedRoot);
    expect(reply.serverRoot!.notAfter).toBe(NOT_AFTER);
    expect(verifyRoot(reply.serverRoot!, cfg.policyPublicKey)).toBe(true);
    expect(srv.session()?.sess).toBe(reply.sess);
    expect(srv.session()?.status).toBe("attested");
  });
  it("aClientRootAndKeyringWindowSurviveParsing", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const req = makeClient().request();
    expect(req.clientRoot!.notAfter).toBe(CLIENT_NOT_AFTER);
    expect(req.clientKeyringNotAfter).toBe(CLIENT_NOT_AFTER);
    expect(handshake(srv, JSON.parse(JSON.stringify(req))).status).toBe("attested");
    expect(srv.session()!.request.clientRoot).toEqual(req.clientRoot);
    expect(srv.session()!.request.clientKeyringNotAfter).toBe(CLIENT_NOT_AFTER);
  });
  it("aTamperedClientKeyringNotAfterIsUnsafe", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const req = makeClient().request();
    expect(handshake(srv, { ...req, clientKeyringNotAfter: CLIENT_NOT_AFTER + 1 }).status).toBe("unsafe");
    expect(handshake(srv, { ...req, clientRoot: { ...req.clientRoot!, notAfter: CLIENT_NOT_AFTER + 1 } }).status).toBe("unsafe");
  });
  it("aMalformedNotAfterOpensNoSession", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const good = makeClient().request();
    expect(handshake(srv, good).status).toBe("attested");
    const current = srv.session();
    for (const bad of [1.5, -1, 2 ** 53, "x", null, true, {}, []]) {
      expect(() => handshake(srv, { ...good, clientKeyringNotAfter: bad }), `keyring ${String(bad)}`).toThrow(InvalidParams);
      const root = { ...good.clientRoot!, notAfter: bad };
      expect(() => handshake(srv, { ...good, clientRoot: root }), `root ${String(bad)}`).toThrow(InvalidParams);
    }
    // a token holding a number that is not a protocol integer is refused without repeating it
    for (const bad of [1.5, -1, 2 ** 53]) {
      const refused = () => handshake(srv, { ...good, clientKeyringNotAfter: bad });
      expect(refused, String(bad)).toThrow(/^json parse: /);
      expect(refused, String(bad)).not.toThrow(String(bad));
    }
    const ring = { ...good, clientKeyringNotAfter: "x" };
    expect(() => handshake(srv, ring)).toThrow("member clientKeyringNotAfter is not an integer");
    const root = { ...good, clientRoot: { ...good.clientRoot!, notAfter: "x" } };
    expect(() => handshake(srv, root)).toThrow("member notAfter is not an integer");
    // a request that opens no session leaves the current one in place
    expect(srv.session()).toBe(current);
  });
  it("clientMaterialWithoutNotAfterOpensNoSession", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const good = makeClient().request();
    expect(handshake(srv, good).status).toBe("attested");
    const current = srv.session();
    const { clientKeyringNotAfter: _w, ...noRingWindow } = good;
    const { notAfter: _n, ...root } = good.clientRoot!;
    expect(() => handshake(srv, noRingWindow)).toThrow(InvalidParams);
    expect(() => handshake(srv, noRingWindow)).toThrow("no member clientKeyringNotAfter");
    expect(() => handshake(srv, { ...good, clientRoot: root })).toThrow(InvalidParams);
    expect(() => handshake(srv, { ...good, clientRoot: root })).toThrow("no member notAfter");
    expect(srv.session()).toBe(current);
  });
  it("aRequestValueWithAnExtraMemberIsInvalidParams", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const good = makeClient().request();
    const extraInRoot = { ...good, clientRoot: { ...good.clientRoot!, note: "added" } };
    for (const request of [{ ...good, serverEntry: "mcp-entry" }, extraInRoot]) {
      expect(() => handshake(srv, request)).toThrow(InvalidParams);
      expect(() => handshake(srv, request)).toThrow("a member the object does not define");
    }
    expect(srv.session()).toBeUndefined();
  });
  it("anExpiredClientRootOrKeyringIsUnsafeAtTheHandshake", () => {
    const T = Date.now() + 60_000;
    for (const [what, opts] of [["keyring", { keyringNotAfter: T }], ["root", { rootNotAfter: T }]] as const) {
      let now = Date.now();
      const srv = new McpServerSession(serverConfig(), RULES, () => now);
      now = T;
      expect(handshake(srv, makeClient(opts).request()).status, `${what} at notAfter`).toBe("attested");
      now = T + 1;
      expect(handshake(srv, makeClient(opts).request()).status, `${what} one ms past`).toBe("unsafe");
    }
  });
  it("aServerWhoseOwnRootOrKeyringExpiredDegradesToUnsafeSessions", () => {
    const T = Date.now() + 60_000;
    for (const [what, windows] of [["keyring", { keyringNotAfter: T }], ["root", { rootNotAfter: T }]] as const) {
      let now = Date.now();
      const { cfg } = serverSetup(["mcp-entry", "github-tools"], windows);
      const srv = new McpServerSession(cfg, RULES, () => now, () => {});
      const client = makeClient();
      const first = handshake(srv, client.request());
      expect(first.status, what).toBe("attested");
      expect(client.acceptReply(first, cfg.policyPublicKey), what).toBe(true);
      // a session opened before expiry is still verified against the client's material
      now = T + 1;
      expect(srv.checkCall(client.callParams("list_issues", { owner: "o" }, [], { now })).reason, `${what} earlier session`).toBe("OK");
      // every new session is unsafe: reads run, writes are refused, as for any unattested caller
      const req = client.request();
      const reply = handshake(srv, req);
      expect(reply.status, what).toBe("unsafe");
      expect(reply.disabled, what).toEqual(RULES.disabledWhenUnsafe);
      const decide = (tool: string, isWrite: boolean) =>
        decideServerCall({ tool, isWrite, publicDestination: true, attested: srv.session()?.status === "attested", served: srv.session()?.served ?? [], clientInfluence: [], disabledWhenUnsafe: RULES.disabledWhenUnsafe });
      expect(decide("list_issues", false), what).toBe("OK");
      expect(decide("create_pull_request", true), what).toBe("UNSAFE_SESSION");
      // and a client judging the reply at that time refuses it, so it takes its replacement path
      expect(verifySessionReply(reply, req, cfg.policyPublicKey, "mcp-entry", now), what).toBe(false);
    }
  });
  it("callsArePolicyExpiredOnceTheClientsRootOrKeyringWindowHasPassed", () => {
    const T = 1_900_000_000_000;
    for (const [what, opts] of [["keyring", { keyringNotAfter: T }], ["root", { rootNotAfter: T }]] as const) {
      let now = Date.now();
      const cfg = serverConfig();
      const srv = new McpServerSession(cfg, RULES, () => now, () => {});
      const client = makeClient(opts);
      const reply = handshake(srv, client.request());
      expect(reply.status, what).toBe("attested");
      expect(client.acceptReply(reply, cfg.policyPublicKey), what).toBe(true);
      now = T;
      expect(srv.checkCall(client.callParams("list_issues", { owner: "o" }, [], { now: T })).reason, `${what} at notAfter`).toBe("OK");
      now = T + 1;
      const r = srv.checkCall(client.callParams("list_issues", { owner: "o" }, [], { now: T + 1 }));
      expect({ reason: r.reason, caller: r.caller, influence: r.influence }, `${what} one ms past`).toEqual({ reason: "POLICY_EXPIRED", caller: "", influence: [] });
    }
  });
  it("unsafeWithoutClientRootDisablesWrites", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const reply = handshake(srv, makeClient({ withRoot: false }).request());
    expect(reply.status).toBe("unsafe");
    expect(reply.disabled).toEqual(RULES.disabledWhenUnsafe);
    expect(srv.session()?.status).toBe("unsafe");
  });
  it("aPinnedClientWithASignedKeyringIsAttested", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    expect(handshake(srv, makeClient().request()).status).toBe("attested");
  });
  it("anUnpinnedClientKeyIsUnsafe", () => {
    const srv = new McpServerSession({ ...serverConfig(), pinnedClientKeys: [generateKeyPair().publicKey] }, RULES, Date.now);
    const reply = handshake(srv, makeClient().request());
    expect(reply.status).toBe("unsafe");
    expect(reply.disabled).toEqual(RULES.disabledWhenUnsafe);
    const none = new McpServerSession({ ...serverConfig(), pinnedClientKeys: [] }, RULES, Date.now);
    expect(handshake(none, makeClient().request()).status).toBe("unsafe");
  });
  it("aRequestWithNoKeyringSignatureIsInvalidParams", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const { clientKeyringSig: _sig, ...missing } = makeClient().request();
    for (const request of [missing, { ...missing, clientKeyringSig: null }, { ...missing, clientKeyringSig: "" }, { ...missing, clientKeyringSig: 7 }]) {
      expect(() => handshake(srv, request)).toThrow(InvalidParams);
    }
    expect(srv.session()).toBeUndefined();
  });
  it("replyVerifiesForClient", () => {
    const cfg = serverConfig();
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const client = makeClient();
    const reply = handshake(srv, client.request());
    expect(client.acceptReply(reply, cfg.policyPublicKey)).toBe(true);
    expect(client.acceptReply(reply, generateKeyPair().publicKey)).toBe(false);
  });
  it("replyCarriesKeyringSigAndEntrySignature", () => {
    const cfg = serverConfig();
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const client = makeClient();
    const req = client.request();
    const reply = handshake(srv, req);
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
  it("disabledInReplyIsACopy", () => {
    const rules: SessionRules = { disabledWhenUnsafe: ["create_branch"] };
    const srv = new McpServerSession(serverConfig(), rules, Date.now);
    const reply = handshake(srv, makeClient({ withRoot: false }).request());
    reply.disabled.push("list_issues");
    expect(rules.disabledWhenUnsafe).toEqual(["create_branch"]);
    expect(handshake(srv, makeClient({ withRoot: false }).request()).disabled).toEqual(["create_branch"]);
  });
  it("protoKeyInClientKeyringIsOrdinary", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const req = JSON.parse(JSON.stringify(makeClient().request()).replace('"clientKeyring":{', '"clientKeyring":{"__proto__":"k",'));
    handshake(srv, req);
    const ring = srv.session()!.request.clientKeyring;
    expect(Object.hasOwn(ring, "__proto__")).toBe(true);
    expect(ring["__proto__"]).toBe("k");
    expect(Object.keys(ring)).toContain("session");
  });
  it("malformedSessionRequestThrows", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    for (const bad of [null, "x", {}, { clientRoot: null, clientPolicyKey: 1, clientKeyring: {}, nonce: "n" }, { clientRoot: null, clientPolicyKey: "k", clientKeyring: [], nonce: "n" }, { clientRoot: { rootId: "v" }, clientPolicyKey: "k", clientKeyring: {}, nonce: "n" }]) {
      expect(() => handshake(srv, bad)).toThrow();
    }
    expect(srv.session()).toBeUndefined();
  });
});

describe("response attestation", () => {
  function setup() {
    const cfg = serverConfig();
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const client = makeClient();
    const reply = handshake(srv, client.request());
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
      const att = readAttestation((srv.attest(srv.session()!, RESULT, CALL, cls)._meta as Record<string, string>)[META_ATTESTATION]!);
      expect(att.labels).toHaveLength(1);
      expect(att.labels[0].cls).toBe(cls);
      expect(typeof att.labels[0].cid).toBe("string");
      expect(att.chain.map((s: any) => s.svc)).toEqual(["mcp-entry", "github-tools"]);
    }
  });
  it("theResponseChainIsV3AndEndsAtTheCaller", () => {
    const { srv } = setup();
    const att = readAttestation((srv.attest(srv.session()!, RESULT, { ...CALL, caller: "pi" }, "public")._meta as Record<string, string>)[META_ATTESTATION]!);
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
    handshake(srv, client.request());
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
    const replyB = handshake(srv, clientB.request());
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
    const att = readAttestation((out._meta as Record<string, string>)[META_ATTESTATION]!);
    expect(att.chain.map((s: any) => s.sess)).toEqual(["verified-session-id", "verified-session-id"]);
    expect(other.served).toEqual(new Set(["private"]));
    expect(srv.session()!.served.size).toBe(0);
  });
});

describe("call check", () => {
  function attested(tools?: string[], over: Partial<ServerPolicy> = {}) {
    const srv = new McpServerSession({ ...serverConfig(), ...over }, RULES, Date.now);
    const client = makeClient({ tools });
    const reply = handshake(srv, client.request());
    expect(client.acceptReply(reply, reply.serverPolicyKey)).toBe(true);
    return { srv, client };
  }
  it("aCallWhoseMetaHoldsValuesIsChainMissing", async () => {
    // a peer that sends each _meta member as the value its token holds
    const { srv, client } = attested(["list_issues"]);
    const params = client.callParams("list_issues", { owner: "o", repo: "r" }, []);
    const meta = params._meta as Record<string, unknown>;
    const values = Object.fromEntries(Object.entries(meta).map(([k, v]) => [k, k === META_CALL_ID ? v : readToken(v as string)]));
    expect(srv.checkCall({ ...params, _meta: values })).toMatchObject({ reason: "CHAIN_MISSING", caller: "", influence: [] });
    const out = await srv.handleToolCall({ ...params, _meta: values }, { isWrite: false, publicDestination: false }, "enforce", () => ({ result: RESULT, cls: "public" }));
    expect(out).toMatchObject({ verdict: "CHAIN_MISSING", ran: false, verified: null });
    // the tokens themselves verify
    expect(srv.checkCall(params).reason).toBe("OK");
  });
  it("checkCallNeedsAnAttestedSession", () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    expect(() => srv.checkCall({ name: "list_issues" })).toThrow(/attested session/);
    handshake(srv, makeClient({ withRoot: false }).request());
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
  it("anOriginOutsideClientOriginsIsBadOrigin", () => {
    const { srv, client } = attested(["list_issues"], { clientOrigins: ["somebody-else"] });
    expect(srv.checkCall(client.callParams("list_issues", { owner: "o", repo: "r" }, []))).toMatchObject({ reason: "BAD_ORIGIN", caller: "" });
  });
  it("anyListedOriginIsAccepted", () => {
    const { srv, client } = attested(["list_issues"], { clientOrigins: ["somebody-else", "session"] });
    expect(srv.checkCall(client.callParams("list_issues", { owner: "o", repo: "r" }, [])).reason).toBe("OK");
  });
  it("attestSignsThePolicyHops", () => {
    const srv = new McpServerSession(serverSetup(["edge", "tools"]).cfg, RULES, Date.now);
    handshake(srv, makeClient().request());
    const att = readAttestation((srv.attest(srv.session()!, RESULT, CALL, "public")._meta as Record<string, string>)[META_ATTESTATION]!);
    expect(att.chain.map((s: any) => s.svc)).toEqual(["edge", "tools"]);
    expect(att.chain.map((s: any) => s.inst)).toEqual(["mock-github-1", "mock-github-1"]);
    expect(att.chain.map((s: any) => s.rcv)).toEqual(["tools", "pi"]);
  });
});

describe("handleToolCall", () => {
  const READ = { isWrite: false, publicDestination: false };
  const PUBLIC_WRITE = { isWrite: true, publicDestination: true };
  const ARGS = { owner: "o", repo: "r" };
  /** Private content and third-party content together: a public write is refused. */
  const TAINTED_PRIVATE: InfluenceEntry[] = [
    { cls: "private", src: "x", h: "h", owner: "o" },
    { cls: "third-party", src: "y", h: "h2" },
  ];
  const meta = (r: object): Record<string, any> => (r as { _meta?: Record<string, any> })._meta ?? {};
  /** The verdict a result's `_meta` carries, read from its token. */
  const verdictOf = (r: object) => readVerdict(meta(r)[META_VERDICT]);

  function open(tools: string[], withRoot = true) {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const client = makeClient({ tools, withRoot });
    const reply = handshake(srv, client.request());
    client.acceptReply(reply, reply.serverPolicyKey);
    return { srv, client };
  }

  it("aVerifiedOkCallRunsAndIsAttested", async () => {
    const { srv, client } = open(["list_issues"]);
    let ran = 0;
    const out = await srv.handleToolCall(client.callParams("list_issues", ARGS, [], { rid: "r-1", callId: "c-1" }), READ, "enforce", () => {
      ran++;
      return { result: RESULT, cls: "public" };
    });
    expect(ran).toBe(1);
    expect(out).toMatchObject({ verdict: "OK", ran: true, verified: { reason: "OK", rid: "r-1", callId: "c-1" } });
    expect(readAttestation(meta(out.result)[META_ATTESTATION]).labels[0]!.cls).toBe("public");
    expect(meta(out.result)[META_VERDICT]).toBeUndefined();
    expect(srv.session()!.served).toEqual(new Set(["public"]));
  });

  it("anUnsafeSessionRunsAReadUnattestedAndRefusesAListedWrite", async () => {
    const { srv, client } = open(["list_issues", "create_pull_request"], false);
    expect(srv.session()!.status).toBe("unsafe");
    const read = await srv.handleToolCall(client.callParams("list_issues", ARGS, []), READ, "enforce", () => ({ result: RESULT, cls: "public" }));
    expect(read).toMatchObject({ verdict: "OK", ran: true, verified: null });
    expect(meta(read.result)[META_ATTESTATION]).toBeUndefined();
    let ran = false;
    const write = await srv.handleToolCall(client.callParams("create_pull_request", ARGS, []), PUBLIC_WRITE, "enforce", () => {
      ran = true;
      return { result: RESULT, cls: "public" };
    });
    expect(ran).toBe(false);
    expect(write).toMatchObject({ verdict: "UNSAFE_SESSION", ran: false });
    expect(write.result).toMatchObject({ isError: true, _meta: { [META_VERDICT]: writeToken({ reason: "UNSAFE_SESSION" }) } });
  });

  it("enforceRefusesWithOnlyTheReasonAndDoesNotAttest", async () => {
    const { srv, client } = open(["list_issues", "create_pull_request"]);
    const influence = TAINTED_PRIVATE;
    let ran = false;
    const out = await srv.handleToolCall(client.callParams("create_pull_request", ARGS, influence), PUBLIC_WRITE, "enforce", () => {
      ran = true;
      return { result: RESULT, cls: "public" };
    });
    expect(ran).toBe(false);
    expect(out).toMatchObject({ verdict: "INFLUENCE_DENIED", ran: false, verified: { reason: "OK" } });
    expect(out.result).toEqual({
      content: [{ type: "text", text: "Paztport refused this call: INFLUENCE_DENIED" }],
      isError: true,
      _meta: { [META_VERDICT]: writeToken({ reason: "INFLUENCE_DENIED" }) },
    });
    expect(srv.session()!.served.size).toBe(0);
  });

  it("auditRunsTheCallAndNotesTheReasonWithAudit", async () => {
    const { srv, client } = open(["list_issues", "create_pull_request"]);
    const influence = TAINTED_PRIVATE;
    const seen: string[] = [];
    const out = await srv.handleToolCall(client.callParams("create_pull_request", ARGS, influence), PUBLIC_WRITE, "audit", ({ verdict }) => {
      seen.push(verdict);
      return { result: RESULT, cls: "public" };
    });
    expect(seen).toEqual(["INFLUENCE_DENIED"]);
    expect(out).toMatchObject({ verdict: "INFLUENCE_DENIED", ran: true });
    expect(verdictOf(out.result)).toEqual({ reason: "INFLUENCE_DENIED", audit: true });
    expect(meta(out.result)[META_ATTESTATION]).toBeDefined();
  });

  it("aFailedChainIsRefusedInEnforceAndNeverAttested", async () => {
    const { srv, client } = open(["list_issues"]);
    const params = client.callParams("list_issues", ARGS, []);
    const out = await srv.handleToolCall({ ...params, arguments: { owner: "x" } }, READ, "enforce", () => ({ result: RESULT, cls: "public" }));
    expect(out).toMatchObject({ verdict: "BINDING_MISMATCH", ran: false, verified: null });
    const audit = await srv.handleToolCall({ ...params, arguments: { owner: "x" } }, READ, "audit", () => ({ result: RESULT, cls: "public" }));
    expect(audit.ran).toBe(true);
    expect(meta(audit.result)[META_ATTESTATION]).toBeUndefined();
    expect(verdictOf(audit.result).audit).toBe(true);
  });

  it("destinationOwnerPassesThroughToTheDecision", async () => {
    const { srv, client } = open(["create_pull_request"]);
    const owned: InfluenceEntry[] = [
      { cls: "private", src: "x", h: "h", owner: "o" },
      { cls: "third-party", src: "y", h: "h2" },
    ];
    const run = () => ({ result: RESULT, cls: "public" as const });
    const same = await srv.handleToolCall(client.callParams("create_pull_request", ARGS, owned), { ...PUBLIC_WRITE, destinationOwner: "o" }, "enforce", run);
    expect(same).toMatchObject({ verdict: "OK", ran: true });
    const other = await srv.handleToolCall(client.callParams("create_pull_request", ARGS, owned), { ...PUBLIC_WRITE, destinationOwner: "elsewhere" }, "enforce", run);
    expect(other).toMatchObject({ verdict: "INFLUENCE_DENIED", ran: false });
  });

  it("auditInAnUnsafeSessionRunsTheWriteUnattestedWithTheVerdict", async () => {
    const { srv, client } = open(["create_pull_request"], false);
    const out = await srv.handleToolCall(client.callParams("create_pull_request", ARGS, []), PUBLIC_WRITE, "audit", () => ({ result: RESULT, cls: "public" }));
    expect(out).toMatchObject({ verdict: "UNSAFE_SESSION", ran: true, verified: null });
    expect(verdictOf(out.result)).toEqual({ reason: "UNSAFE_SESSION", audit: true });
    expect(meta(out.result)[META_ATTESTATION]).toBeUndefined();
  });

  it("detailFromRunComesBackWithTheOutcome", async () => {
    const { srv, client } = open(["list_issues"]);
    const out = await srv.handleToolCall(client.callParams("list_issues", ARGS, []), READ, "enforce", () => ({ result: RESULT, cls: "public", detail: 42 }));
    if (out.ran) expect(out.detail).toBe(42);
    else throw new Error("expected the call to run");
  });

  describe("with no server session", () => {
    const params = { name: "create_pull_request", arguments: ARGS };
    const run = () => ({ result: RESULT, cls: "public" as const });
    it("enforceRefusesAListedWriteUnsafeSession", async () => {
      const out = await handleToolCall(null, RULES, params, PUBLIC_WRITE, "enforce", run);
      expect(out).toMatchObject({ verdict: "UNSAFE_SESSION", ran: false, verified: null });
      expect(out.result).toMatchObject({ isError: true, _meta: { [META_VERDICT]: writeToken({ reason: "UNSAFE_SESSION" }) } });
    });
    it("auditRunsItWithTheNote", async () => {
      const out = await handleToolCall(null, RULES, params, PUBLIC_WRITE, "audit", run);
      expect(out).toMatchObject({ verdict: "UNSAFE_SESSION", ran: true, verified: null });
      expect(verdictOf(out.result)).toEqual({ reason: "UNSAFE_SESSION", audit: true });
      expect(meta(out.result)[META_ATTESTATION]).toBeUndefined();
    });
    it("aReadRunsUnattested", async () => {
      const out = await handleToolCall(null, RULES, { name: "list_issues", arguments: ARGS }, READ, "enforce", run);
      expect(out).toMatchObject({ verdict: "OK", ran: true });
      expect(meta(out.result)).toEqual({});
    });
  });

  it("noHandshakeIsAnUnsafeSession", async () => {
    const srv = new McpServerSession(serverConfig(), RULES, Date.now);
    const out = await srv.handleToolCall({ name: "create_pull_request", arguments: ARGS }, PUBLIC_WRITE, "enforce", () => ({ result: RESULT, cls: "public" }));
    expect(out).toMatchObject({ verdict: "UNSAFE_SESSION", ran: false });
  });
});
