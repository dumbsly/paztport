// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { buildPolicy, decode, generateKeyPair, META_ATTESTATION, signRoot, verifyCall, verifyRoot, type InfluenceClass } from "@paztport/path-attest";
import type { CallToolResult } from "../src/mcp.ts";
import { loadServerConfig, PaztportServer, type ServerPaztportConfig, type SessionRules } from "../src/paztport.ts";
import { makeClient } from "./helpers/client.ts";

const RULES: SessionRules = {
  disabledWhenUnsafe: ["create_branch", "create_or_update_file", "push_files", "create_pull_request", "add_issue_comment"],
};

function serverConfig(): ServerPaztportConfig {
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
  };
}

const RESULT: CallToolResult = { content: [{ type: "text", text: "hello" }] };
const CALL = { rid: "rid-1", callId: "call-1", name: "list_issues", args: { owner: "o", repo: "r" } };

describe("session handshake", () => {
  it("attestedWhenBothRoots", () => {
    const cfg = serverConfig();
    const srv = new PaztportServer(cfg, RULES, Date.now);
    const reply = srv.openSession(makeClient({ withRoot: true }).request());
    expect(reply.status).toBe("attested");
    expect(reply.disabled).toEqual([]);
    expect(reply.serverRoot).toEqual(cfg.signedRoot);
    expect(verifyRoot(reply.serverRoot!, cfg.policyPublicKey)).toBe(true);
    expect(srv.session()?.sess).toBe(reply.sess);
    expect(srv.session()?.status).toBe("attested");
  });
  it("unsafeWithoutClientRootDisablesWrites", () => {
    const srv = new PaztportServer(serverConfig(), RULES, Date.now);
    const reply = srv.openSession(makeClient({ withRoot: false }).request());
    expect(reply.status).toBe("unsafe");
    expect(reply.disabled).toEqual(RULES.disabledWhenUnsafe);
    expect(srv.session()?.status).toBe("unsafe");
  });
  it("replyVerifiesForClient", () => {
    const cfg = serverConfig();
    const srv = new PaztportServer(cfg, RULES, Date.now);
    const client = makeClient();
    const reply = srv.openSession(client.request());
    expect(client.acceptReply(reply, cfg.policyPublicKey)).toBe(true);
    expect(client.acceptReply(reply, generateKeyPair().publicKey)).toBe(false);
  });
  it("disabledInReplyIsACopy", () => {
    const rules: SessionRules = { disabledWhenUnsafe: ["create_branch"] };
    const srv = new PaztportServer(serverConfig(), rules, Date.now);
    const reply = srv.openSession(makeClient({ withRoot: false }).request());
    reply.disabled.push("list_issues");
    expect(rules.disabledWhenUnsafe).toEqual(["create_branch"]);
    expect(srv.openSession(makeClient({ withRoot: false }).request()).disabled).toEqual(["create_branch"]);
  });
  it("protoKeyInClientKeyringIsOrdinary", () => {
    const srv = new PaztportServer(serverConfig(), RULES, Date.now);
    const req = JSON.parse(JSON.stringify(makeClient().request()).replace('"clientKeyring":{', '"clientKeyring":{"__proto__":"k",'));
    srv.openSession(req);
    const ring = srv.session()!.request.clientKeyring;
    expect(Object.hasOwn(ring, "__proto__")).toBe(true);
    expect(ring["__proto__"]).toBe("k");
    expect(Object.keys(ring)).toContain("session");
  });
  it("malformedSessionRequestThrows", () => {
    const srv = new PaztportServer(serverConfig(), RULES, Date.now);
    for (const bad of [null, "x", {}, { clientRoot: null, clientPolicyKey: 1, clientKeyring: {}, nonce: "n" }, { clientRoot: null, clientPolicyKey: "k", clientKeyring: [], nonce: "n" }, { clientRoot: { rootId: "v" }, clientPolicyKey: "k", clientKeyring: {}, nonce: "n" }]) {
      expect(() => srv.openSession(bad)).toThrow();
    }
    expect(srv.session()).toBeUndefined();
  });
});

describe("response attestation", () => {
  function setup() {
    const cfg = serverConfig();
    const srv = new PaztportServer(cfg, RULES, Date.now);
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

describe("loadServerConfig", () => {
  const dirs: string[] = [];
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));
  it("loadServerConfigReadsPolicyToolOutput", () => {
    const dir = mkdtempSync(join(tmpdir(), "paztport-cfg-"));
    dirs.push(dir);
    const tool = (f: string) => join(import.meta.dirname, "../../policy-tool-ts/src", f);
    writeFileSync(join(dir, "paths.yaml"), "paths:\n  - [mcp-entry, github-tools]\n");
    execFileSync("node", [tool("keygen.ts"), "--out", dir, "--services", "mcp-entry,github-tools"], { stdio: "pipe" });
    execFileSync("node", [tool("policy.ts"), "--paths", join(dir, "paths.yaml"), "--policy-key", join(dir, "policy.key"), "--out", dir], { stdio: "pipe" });
    const cfg = loadServerConfig(dir);
    expect(cfg.inst).toBe("mock-github-1");
    expect(Object.keys(cfg.keyring).sort()).toEqual(["github-tools", "mcp-entry"]);
    expect(verifyRoot(cfg.signedRoot, cfg.policyPublicKey)).toBe(true);
    expect(cfg.routeProof.rootId).toBe(cfg.signedRoot.rootId);
    // the loaded config drives a full handshake and a verifiable response
    const srv = new PaztportServer(cfg, RULES, Date.now);
    const client = makeClient();
    const reply = srv.openSession(client.request());
    expect(client.acceptReply(reply, cfg.policyPublicKey)).toBe(true);
    const out = srv.attest(srv.session()!, RESULT, CALL, "public");
    expect(client.verify(out, { rid: CALL.rid, toolCallId: CALL.callId }, reply.serverKeyring, reply.serverRoot!).reason).toBe("OK");
  });

  /** Writes cfg in the policy-tool file layout, after `tweak` edits the file contents. */
  function writeDir(cfg: ServerPaztportConfig, tweak: (files: Record<string, unknown>) => void = () => {}): string {
    const dir = mkdtempSync(join(tmpdir(), "paztport-cfg-"));
    dirs.push(dir);
    const files: Record<string, unknown> = {
      "keyring.json": { services: { ...cfg.keyring }, policy: cfg.policyPublicKey },
      "policy.key": cfg.policyPrivateKey,
      "mcp-entry.key": cfg.signingKeys["mcp-entry"],
      "github-tools.key": cfg.signingKeys["github-tools"],
      "root.json": cfg.signedRoot,
      "proofs-mcp-entry.json": { proofs: { "mcp-entry/github-tools": cfg.routeProof } },
    };
    tweak(files);
    mkdirSync(dir, { recursive: true });
    for (const [name, v] of Object.entries(files)) {
      writeFileSync(join(dir, name), typeof v === "string" ? v + "\n" : JSON.stringify(v));
    }
    return dir;
  }

  it("loadServerConfigAcceptsConsistentFiles", () => {
    const cfg = serverConfig();
    expect(loadServerConfig(writeDir(cfg))).toEqual(cfg);
  });
  it("loadServerConfigRejectsMalformedProof", () => {
    const dir = writeDir(serverConfig(), (f) => {
      f["proofs-mcp-entry.json"] = { proofs: { "mcp-entry/github-tools": { leafSalt: 1 } } };
    });
    expect(() => loadServerConfig(dir)).toThrow(/route proof/);
  });
  it("loadServerConfigRejectsProofForOtherRoute", () => {
    const cfg = serverConfig();
    const other = buildPolicy([["mcp-entry", "elsewhere"]], 8, cfg.policyPrivateKey);
    const dir = writeDir(cfg, (f) => {
      f["proofs-mcp-entry.json"] = { proofs: { "mcp-entry/github-tools": other.bundles["mcp-entry"]!.proofs["mcp-entry/elsewhere"] } };
    });
    expect(() => loadServerConfig(dir)).toThrow(/route proof/);
  });
  it("loadServerConfigRejectsRootNotSignedByPolicyKey", () => {
    const cfg = serverConfig();
    const forged = signRoot(decode(cfg.signedRoot.root), cfg.signedRoot.rootId, generateKeyPair().privateKey);
    const dir = writeDir(cfg, (f) => {
      f["root.json"] = forged;
    });
    expect(() => loadServerConfig(dir)).toThrow(/root\.json/);
  });
  it("loadServerConfigRejectsMismatchedPolicyKey", () => {
    const dir = writeDir(serverConfig(), (f) => {
      f["policy.key"] = generateKeyPair().privateKey;
    });
    expect(() => loadServerConfig(dir)).toThrow(/policy\.key/);
  });
  it("loadServerConfigRejectsMismatchedSigningKeys", () => {
    for (const svc of ["mcp-entry", "github-tools"]) {
      const dir = writeDir(serverConfig(), (f) => {
        f[`${svc}.key`] = generateKeyPair().privateKey;
      });
      expect(() => loadServerConfig(dir)).toThrow(new RegExp(`${svc}\\.key`));
    }
  });
  it("loadServerConfigRejectsMissingKeyringEntry", () => {
    const dir = writeDir(serverConfig(), (f) => {
      delete (f["keyring.json"] as { services: Record<string, string> }).services["github-tools"];
    });
    expect(() => loadServerConfig(dir)).toThrow(/github-tools/);
  });
  it("loadServerConfigRejectsUnusableKey", () => {
    const dir = writeDir(serverConfig(), (f) => {
      f["mcp-entry.key"] = "not-a-key";
    });
    expect(() => loadServerConfig(dir)).toThrow(/mcp-entry\.key/);
  });
  it("loadServerConfigKeyringProtoKeyIsOrdinary", () => {
    const cfg = serverConfig();
    const dir = writeDir(cfg);
    const path = join(dir, "keyring.json");
    writeFileSync(path, JSON.stringify({ services: { ...cfg.keyring }, policy: cfg.policyPublicKey }).replace('"services":{', '"services":{"__proto__":"x",'));
    const loaded = loadServerConfig(dir);
    expect(Object.hasOwn(loaded.keyring, "__proto__")).toBe(true);
    expect(loaded.keyring["__proto__"]).toBe("x");
  });
});
