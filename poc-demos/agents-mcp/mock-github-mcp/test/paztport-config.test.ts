// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { buildPolicy, decode, generateKeyPair, issueReplyCert, signKeyring, signRoot, verifyRoot, verifySessionReply } from "@paztport/core";
import { McpServerSession, type ServerPolicy, type SessionRules } from "@paztport/mcp";
import type { CallToolResult } from "../src/mcp.ts";
import { loadServerConfig } from "../src/paztport.ts";
import { CLIENT_POLICY, makeClient } from "./helpers/client.ts";

const RULES: SessionRules = {
  disabledWhenUnsafe: ["create_branch", "create_or_update_file", "push_files", "create_pull_request", "add_issue_comment"],
};

const DAY_MS = 86_400_000;
const REGENERATE = "regenerate the demo keys with npm run setup-demo -- --force";

/** A consistent server config and the policy private key that signed it, which the server itself never holds. */
function serverSetup(): { cfg: ServerPolicy; policyPrivateKey: string } {
  const policy = generateKeyPair();
  const entry = generateKeyPair();
  const tools = generateKeyPair();
  const { signedRoot, bundles } = buildPolicy([["mcp-entry", "github-tools"]], 8, policy.privateKey);
  const ring = signKeyring({ "mcp-entry": entry.publicKey, "github-tools": tools.publicKey }, policy.publicKey, policy.privateKey);
  const cfg: ServerPolicy = {
    policyPublicKey: policy.publicKey,
    signingKeys: { "mcp-entry": entry.privateKey, "github-tools": tools.privateKey },
    keyring: ring.services,
    keyringSig: ring.sig,
    replyCert: issueReplyCert(policy.publicKey, "mcp-entry", entry.publicKey, Date.now() + DAY_MS, policy.privateKey),
    signedRoot,
    routeProof: bundles["mcp-entry"]!.proofs["mcp-entry/github-tools"]!,
    inst: "mock-github-1",
    hops: ["mcp-entry", "github-tools"],
    serverId: "github",
    pinnedClientKeys: [CLIENT_POLICY.publicKey],
  };
  return { cfg, policyPrivateKey: policy.privateKey };
}

const serverConfig = (): ServerPolicy => serverSetup().cfg;

const RESULT: CallToolResult = { content: [{ type: "text", text: "hello" }] };
const CALL = { rid: "rid-1", callId: "call-1", name: "list_issues", args: { owner: "o", repo: "r" }, caller: "pi" };

describe("loadServerConfig", () => {
  const dirs: string[] = [];
  afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));
  it("loadServerConfigReadsPolicyToolOutput", () => {
    const dir = mkdtempSync(join(tmpdir(), "paztport-cfg-"));
    dirs.push(dir);
    const tool = (f: string) => join(import.meta.dirname, "../../node_modules/@paztport/policy-tool/src", f);
    writeFileSync(join(dir, "paths.yaml"), "paths:\n  - [mcp-entry, github-tools]\n");
    execFileSync("node", [tool("keygen.ts"), "--out", dir, "--services", "mcp-entry,github-tools"], { stdio: "pipe" });
    execFileSync(
      "node",
      [tool("policy.ts"), "--paths", join(dir, "paths.yaml"), "--policy-key", join(dir, "policy.key"), "--out", dir, "--reply-cert-svc", "mcp-entry", "--keyring", join(dir, "keyring.json")],
      { stdio: "pipe" },
    );
    writeFileSync(join(dir, "client-policy.pub"), CLIENT_POLICY.publicKey + "\n");
    rmSync(join(dir, "policy.key"));
    const cfg = loadServerConfig(dir);
    expect(cfg.inst).toBe("mock-github-1");
    expect(Object.keys(cfg.keyring).sort()).toEqual(["github-tools", "mcp-entry"]);
    expect(verifyRoot(cfg.signedRoot, cfg.policyPublicKey)).toBe(true);
    expect(cfg.routeProof.rootId).toBe(cfg.signedRoot.rootId);
    // the loaded config drives a full handshake and a verifiable response
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const client = makeClient();
    const reply = srv.openSession(client.request());
    expect(reply.status).toBe("attested");
    expect(client.acceptReply(reply, cfg.policyPublicKey)).toBe(true);
    expect(reply.serverReplyCert).toEqual(cfg.replyCert);
    const out = srv.attest(srv.session()!, RESULT, CALL, "public");
    expect(client.verify(out, { rid: CALL.rid, toolCallId: CALL.callId }, reply.serverKeyring, reply.serverRoot!).reason).toBe("OK");
  });

  /** Writes cfg in the policy-tool file layout, after `tweak` edits the file contents. */
  function writeDir(cfg: ServerPolicy, tweak: (files: Record<string, unknown>) => void = () => {}): string {
    const dir = mkdtempSync(join(tmpdir(), "paztport-cfg-"));
    dirs.push(dir);
    const files: Record<string, unknown> = {
      "keyring.json": { services: { ...cfg.keyring }, policy: cfg.policyPublicKey, sig: cfg.keyringSig },
      "reply-cert.json": cfg.replyCert,
      "mcp-entry.key": cfg.signingKeys["mcp-entry"],
      "github-tools.key": cfg.signingKeys["github-tools"],
      "root.json": cfg.signedRoot,
      "proofs-mcp-entry.json": { proofs: { "mcp-entry/github-tools": cfg.routeProof } },
      "client-policy.pub": cfg.pinnedClientKeys[0],
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
    const dir = writeDir(cfg);
    // the server holds no policy private key
    expect(existsSync(join(dir, "policy.key"))).toBe(false);
    expect(loadServerConfig(dir)).toEqual(cfg);
  });
  it("loadServerConfigIgnoresAStalePolicyKey", () => {
    const cfg = serverConfig();
    const dir = writeDir(cfg, (f) => {
      f["policy.key"] = generateKeyPair().privateKey;
    });
    expect(loadServerConfig(dir)).toEqual(cfg);
  });
  it("loadServerConfigRefusesAKeyringWhoseSignatureFails", () => {
    const cfg = serverConfig();
    const tampered = writeDir(cfg, (f) => {
      (f["keyring.json"] as { services: Record<string, string> }).services["github-tools"] = generateKeyPair().publicKey;
    });
    expect(() => loadServerConfig(tampered)).toThrow(`keyring.json is not signed by its policy key: ${REGENERATE}`);
    const unsigned = writeDir(cfg, (f) => {
      delete (f["keyring.json"] as { sig?: string }).sig;
    });
    expect(() => loadServerConfig(unsigned)).toThrow(`keyring.json is not signed by its policy key: ${REGENERATE}`);
    const other = writeDir(cfg, (f) => {
      (f["keyring.json"] as { sig: string }).sig = signKeyring(cfg.keyring, cfg.policyPublicKey, generateKeyPair().privateKey).sig;
    });
    expect(() => loadServerConfig(other)).toThrow(`keyring.json is not signed by its policy key: ${REGENERATE}`);
  });
  it("loadServerConfigNamesTheFixWhenTheReplyCertificateIsMissingOrMalformed", () => {
    const missing = writeDir(serverConfig(), (f) => {
      delete f["reply-cert.json"];
    });
    expect(() => loadServerConfig(missing)).toThrow(`${missing}/reply-cert.json is missing: ${REGENERATE}`);
    for (const bad of [{}, { ...serverConfig().replyCert, notAfter: 1.5 }, "not a certificate"]) {
      const dir = writeDir(serverConfig(), (f) => {
        f["reply-cert.json"] = JSON.stringify(bad);
      });
      expect(() => loadServerConfig(dir), JSON.stringify(bad)).toThrow(`${dir}/reply-cert.json is not a reply certificate: ${REGENERATE}`);
    }
  });
  it("loadServerConfigRefusesAReplyCertificateThatDoesNotCertifyTheEntryKey", () => {
    const { cfg, policyPrivateKey } = serverSetup();
    const later = Date.now() + DAY_MS;
    const forged: Record<string, [unknown, string]> = {
      expired: [issueReplyCert(cfg.policyPublicKey, "mcp-entry", cfg.keyring["mcp-entry"]!, Date.now() - 1, policyPrivateKey), "has expired"],
      "for github-tools": [issueReplyCert(cfg.policyPublicKey, "github-tools", cfg.keyring["github-tools"]!, later, policyPrivateKey), "is not for mcp-entry"],
      "for another key": [issueReplyCert(cfg.policyPublicKey, "mcp-entry", cfg.keyring["github-tools"]!, later, policyPrivateKey), "is not for mcp-entry's key in keyring.json"],
      "signed by another policy key": [
        issueReplyCert(cfg.policyPublicKey, "mcp-entry", cfg.keyring["mcp-entry"]!, later, generateKeyPair().privateKey),
        "is not signed by the keyring.json policy key",
      ],
      "naming another policy key": [
        (() => {
          const other = generateKeyPair();
          return issueReplyCert(other.publicKey, "mcp-entry", cfg.keyring["mcp-entry"]!, later, other.privateKey);
        })(),
        "is not signed by the keyring.json policy key",
      ],
    };
    for (const [name, [cert, why]] of Object.entries(forged)) {
      const dir = writeDir(cfg, (f) => {
        f["reply-cert.json"] = cert;
      });
      expect(() => loadServerConfig(dir), name).toThrow(`${dir}/reply-cert.json ${why}: ${REGENERATE}`);
    }
  });
  it("aLoadedConfigsReplyVerifiesUnderTheEntryKeyNotThePolicyKey", () => {
    const cfg = loadServerConfig(writeDir(serverConfig()));
    const srv = new McpServerSession(cfg, RULES, Date.now);
    const client = makeClient();
    const req = client.request();
    const reply = srv.openSession(req);
    expect(verifySessionReply(reply, req, cfg.policyPublicKey, "mcp-entry", Date.now())).toBe(true);
    expect(verifySessionReply(reply, req, cfg.policyPublicKey, "mcp-entry", cfg.replyCert.notAfter + 1)).toBe(false);
  });
  it("loadServerConfigPinsTheClientPolicyKey", () => {
    const cfg = serverConfig();
    const dir = writeDir(cfg);
    writeFileSync(join(dir, "client-policy.pub"), `  ${CLIENT_POLICY.publicKey}\n\n`);
    expect(loadServerConfig(dir).pinnedClientKeys).toEqual([CLIENT_POLICY.publicKey]);
  });
  it("loadServerConfigNamesTheFixWhenTheClientPinIsMissing", () => {
    const dir = writeDir(serverConfig(), (f) => {
      delete f["client-policy.pub"];
    });
    expect(() => loadServerConfig(dir)).toThrow(`${dir}/client-policy.pub is missing: regenerate the demo keys with npm run setup-demo -- --force`);
  });
  it("loadServerConfigRejectsAClientPinThatIsNotAPublicKey", () => {
    for (const text of ["", "  \n", "not-a-key", generateKeyPair().privateKey]) {
      const dir = writeDir(serverConfig());
      writeFileSync(join(dir, "client-policy.pub"), text);
      expect(() => loadServerConfig(dir), JSON.stringify(text)).toThrow(
        `${dir}/client-policy.pub is not a public key: regenerate the demo keys with npm run setup-demo -- --force`,
      );
    }
  });
  it("loadServerConfigRejectsMalformedProof", () => {
    const dir = writeDir(serverConfig(), (f) => {
      f["proofs-mcp-entry.json"] = { proofs: { "mcp-entry/github-tools": { leafSalt: 1 } } };
    });
    expect(() => loadServerConfig(dir)).toThrow(/route proof/);
  });
  it("loadServerConfigRejectsProofForOtherRoute", () => {
    const { cfg, policyPrivateKey } = serverSetup();
    const other = buildPolicy([["mcp-entry", "elsewhere"]], 8, policyPrivateKey);
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
  it("loadServerConfigRejectsMismatchedSigningKeys", () => {
    for (const svc of ["mcp-entry", "github-tools"]) {
      const dir = writeDir(serverConfig(), (f) => {
        f[`${svc}.key`] = generateKeyPair().privateKey;
      });
      expect(() => loadServerConfig(dir)).toThrow(new RegExp(`${svc}\\.key`));
    }
  });
  it("loadServerConfigRejectsMissingKeyringEntry", () => {
    const { cfg, policyPrivateKey } = serverSetup();
    const { "github-tools": _gone, ...services } = cfg.keyring;
    const dir = writeDir(cfg, (f) => {
      f["keyring.json"] = signKeyring(services, cfg.policyPublicKey, policyPrivateKey);
    });
    expect(() => loadServerConfig(dir)).toThrow("keyring.json has no entry for github-tools");
  });
  it("loadServerConfigRejectsUnusableKey", () => {
    const dir = writeDir(serverConfig(), (f) => {
      f["mcp-entry.key"] = "not-a-key";
    });
    expect(() => loadServerConfig(dir)).toThrow(/mcp-entry\.key/);
  });
  it("loadServerConfigKeyringProtoKeyIsOrdinary", () => {
    const { cfg, policyPrivateKey } = serverSetup();
    const dir = writeDir(cfg);
    const path = join(dir, "keyring.json");
    const services = JSON.parse(JSON.stringify(cfg.keyring).replace("{", '{"__proto__":"x",')) as Record<string, string>;
    const ring = signKeyring(services, cfg.policyPublicKey, policyPrivateKey);
    writeFileSync(path, JSON.stringify({ services: ring.services, policy: ring.policy, sig: ring.sig }));
    const loaded = loadServerConfig(dir);
    expect(Object.hasOwn(loaded.keyring, "__proto__")).toBe(true);
    expect(loaded.keyring["__proto__"]).toBe("x");
  });
});
