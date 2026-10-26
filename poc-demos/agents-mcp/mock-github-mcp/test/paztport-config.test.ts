// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { buildPolicy, decode, generateKeyPair, signRoot, verifyRoot } from "@paztport/core";
import { McpServerSession, type ServerPolicy, type SessionRules } from "@paztport/mcp";
import type { CallToolResult } from "../src/mcp.ts";
import { loadServerConfig } from "../src/paztport.ts";
import { makeClient } from "./helpers/client.ts";

const RULES: SessionRules = {
  disabledWhenUnsafe: ["create_branch", "create_or_update_file", "push_files", "create_pull_request", "add_issue_comment"],
};

function serverConfig(): ServerPolicy {
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
  };
}

const RESULT: CallToolResult = { content: [{ type: "text", text: "hello" }] };
const CALL = { rid: "rid-1", callId: "call-1", name: "list_issues", args: { owner: "o", repo: "r" } };

describe("loadServerConfig", () => {
  const dirs: string[] = [];
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));
  it("loadServerConfigReadsPolicyToolOutput", () => {
    const dir = mkdtempSync(join(tmpdir(), "paztport-cfg-"));
    dirs.push(dir);
    const tool = (f: string) => join(import.meta.dirname, "../../node_modules/@paztport/policy-tool/src", f);
    writeFileSync(join(dir, "paths.yaml"), "paths:\n  - [mcp-entry, github-tools]\n");
    execFileSync("node", [tool("keygen.ts"), "--out", dir, "--services", "mcp-entry,github-tools"], { stdio: "pipe" });
    execFileSync("node", [tool("policy.ts"), "--paths", join(dir, "paths.yaml"), "--policy-key", join(dir, "policy.key"), "--out", dir], { stdio: "pipe" });
    const cfg = loadServerConfig(dir);
    expect(cfg.inst).toBe("mock-github-1");
    expect(Object.keys(cfg.keyring).sort()).toEqual(["github-tools", "mcp-entry"]);
    expect(verifyRoot(cfg.signedRoot, cfg.policyPublicKey)).toBe(true);
    expect(cfg.routeProof.rootId).toBe(cfg.signedRoot.rootId);
    // the loaded config drives a full handshake and a verifiable response
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const client = makeClient();
    const reply = srv.openSession(client.request());
    expect(client.acceptReply(reply, cfg.policyPublicKey)).toBe(true);
    const out = srv.attest(srv.session()!, RESULT, CALL, "public");
    expect(client.verify(out, { rid: CALL.rid, toolCallId: CALL.callId }, reply.serverKeyring, reply.serverRoot!).reason).toBe("OK");
  });

  /** Writes cfg in the policy-tool file layout, after `tweak` edits the file contents. */
  function writeDir(cfg: ServerPolicy, tweak: (files: Record<string, unknown>) => void = () => {}): string {
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
  it("loadServerConfigNamesTheRouteWhenItsProofDoesNotVerify", () => {
    const message = "route proof for mcp-entry/github-tools does not verify against root.json";
    const cfg = serverConfig();
    const p = cfg.routeProof;
    const flipped = (p.leafSalt[0] === "A" ? "B" : "A") + p.leafSalt.slice(1);
    const wrongProof = writeDir(cfg, (f) => {
      f["proofs-mcp-entry.json"] = { proofs: { "mcp-entry/github-tools": { ...p, leafSalt: flipped } } };
    });
    expect(() => loadServerConfig(wrongProof)).toThrow(message);
    const wrongRoot = writeDir(cfg, (f) => {
      f["proofs-mcp-entry.json"] = { proofs: { "mcp-entry/github-tools": { ...p, rootId: "vother" } } };
    });
    expect(() => loadServerConfig(wrongRoot)).toThrow(message);
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
