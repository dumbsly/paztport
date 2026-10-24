// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { buildPolicy, decode, generateKeyPair, META_ATTESTATION, verifyCall, verifyRoot } from "@paztport/path-attest";
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
    expect(client.acceptReply(srv.openSession(client.request()), cfg.policyPublicKey)).toBe(true);
    return { cfg, srv, client };
  }
  it("attestedResponseVerifiesForClient", () => {
    const { cfg, srv, client } = setup();
    const out = srv.attest(RESULT, CALL, "third-party");
    const v = client.verify(out, { rid: CALL.rid, toolCallId: CALL.callId }, cfg.keyring, cfg.signedRoot);
    expect(v.reason).toBe("OK");
    expect(v.labels).toHaveLength(1);
    expect(v.labels[0]!.cls).toBe("third-party");
    expect(RESULT._meta).toBeUndefined();
  });
  it("attestationLabelMatchesClass", () => {
    const { srv } = setup();
    for (const cls of ["third-party", "private", "public", "local-untrusted"] as const) {
      const att = (srv.attest(RESULT, CALL, cls)._meta as Record<string, any>)[META_ATTESTATION];
      expect(att.labels).toHaveLength(1);
      expect(att.labels[0].cls).toBe(cls);
      expect(typeof att.labels[0].cid).toBe("string");
      expect(att.chain.map((s: any) => s.svc)).toEqual(["mcp-entry", "github-tools"]);
    }
  });
  it("replayedResponseIsRejected", () => {
    const { cfg, srv, client } = setup();
    const out = srv.attest(RESULT, CALL, "public");
    const args = [{ rid: CALL.rid, toolCallId: CALL.callId }, cfg.keyring, cfg.signedRoot] as const;
    expect(client.verify(out, ...args).reason).toBe("OK");
    expect(client.verify(out, ...args).reason).toBe("REPLAY");
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
  it("attestWithoutSessionThrows", () => {
    const srv = new PaztportServer(serverConfig(), RULES, Date.now);
    expect(() => srv.attest(RESULT, CALL, "public")).toThrow();
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
    expect(client.acceptReply(srv.openSession(client.request()), cfg.policyPublicKey)).toBe(true);
    const out = srv.attest(RESULT, CALL, "public");
    expect(client.verify(out, { rid: CALL.rid, toolCallId: CALL.callId }, cfg.keyring, cfg.signedRoot).reason).toBe("OK");
  });
});
