// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  bindMcpCall,
  bindResponse,
  bindResult,
  deriveSessionId,
  META_ATTESTATION,
  newContentId,
  newNonce,
  NonceCache,
  NONCE_TTL_MS,
  sessionStatus,
  signSessionReply,
  signStampV2,
  type ContentLabel,
  type InfluenceClass,
  type MerkleProof,
  type ResponseAttestation,
  type SessionReply,
  type SessionRequest,
  type SignedRoot,
} from "@paztport/path-attest";
import type { CallToolResult } from "./mcp.ts";

/** Refusal key on error results (re-exported from index.ts). */
export const META_VERDICT = "paztport/verdict";

const ROUTE = "mcp-entry/github-tools";

export type ServerPaztportConfig = {
  policyPrivateKey: string;
  policyPublicKey: string;
  signingKeys: { "mcp-entry": string; "github-tools": string };
  keyring: Record<string, string>;
  signedRoot: SignedRoot;
  /** Proof for the route mcp-entry/github-tools. */
  routeProof: MerkleProof;
  inst: string;
};

export type Session = {
  sess: string;
  status: "attested" | "unsafe";
  request: SessionRequest;
  nonces: NonceCache;
};

export type SessionRules = { disabledWhenUnsafe: string[] };

function readText(path: string): string {
  return readFileSync(path, "utf8").trim();
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, "utf8"));
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function str(v: unknown, what: string): string {
  if (typeof v !== "string") {
    throw new Error(`${what} must be a string`);
  }
  return v;
}

/** Loads the files the policy-tool keygen and policy CLIs write into one directory. */
export function loadServerConfig(dir: string): ServerPaztportConfig {
  const ring = readJson(join(dir, "keyring.json"));
  if (!isObject(ring) || !isObject(ring.services)) {
    throw new Error("malformed keyring.json");
  }
  const keyring: Record<string, string> = {};
  for (const [svc, key] of Object.entries(ring.services)) {
    keyring[svc] = str(key, `keyring entry ${svc}`);
  }
  const root = readJson(join(dir, "root.json"));
  if (!isObject(root)) {
    throw new Error("malformed root.json");
  }
  const signedRoot: SignedRoot = { rootId: str(root.rootId, "rootId"), root: str(root.root, "root"), sig: str(root.sig, "sig") };
  const bundle = readJson(join(dir, "proofs-mcp-entry.json"));
  const routeProof = isObject(bundle) && isObject(bundle.proofs) ? (bundle.proofs[ROUTE] as MerkleProof | undefined) : undefined;
  if (routeProof === undefined) {
    throw new Error(`proofs-mcp-entry.json has no proof for ${ROUTE}`);
  }
  return {
    policyPrivateKey: readText(join(dir, "policy.key")),
    policyPublicKey: str(ring.policy, "keyring policy"),
    signingKeys: { "mcp-entry": readText(join(dir, "mcp-entry.key")), "github-tools": readText(join(dir, "github-tools.key")) },
    keyring,
    signedRoot,
    routeProof,
    inst: "mock-github-1",
  };
}

function parseSessionRequest(params: unknown): SessionRequest {
  if (!isObject(params)) {
    throw new Error("session request must be an object");
  }
  let clientRoot: SignedRoot | null = null;
  if (params.clientRoot !== null) {
    const r = params.clientRoot;
    if (!isObject(r)) {
      throw new Error("clientRoot must be an object or null");
    }
    clientRoot = { rootId: str(r.rootId, "clientRoot.rootId"), root: str(r.root, "clientRoot.root"), sig: str(r.sig, "clientRoot.sig") };
  }
  if (!isObject(params.clientKeyring)) {
    throw new Error("clientKeyring must be an object");
  }
  const clientKeyring: Record<string, string> = {};
  for (const [svc, key] of Object.entries(params.clientKeyring)) {
    clientKeyring[svc] = str(key, `clientKeyring entry ${svc}`);
  }
  return {
    clientRoot,
    clientPolicyKey: str(params.clientPolicyKey, "clientPolicyKey"),
    clientKeyring,
    nonce: str(params.nonce, "nonce"),
  };
}

export class PaztportServer {
  private readonly cfg: ServerPaztportConfig;
  private readonly rules: SessionRules;
  private readonly now: () => number;
  private current: Session | undefined;

  constructor(cfg: ServerPaztportConfig, rules: SessionRules, now: () => number) {
    this.cfg = cfg;
    this.rules = rules;
    this.now = now;
  }

  openSession(params: unknown): SessionReply {
    const request = parseSessionRequest(params);
    const status = sessionStatus(request, this.cfg.signedRoot, this.cfg.policyPublicKey);
    const serverNonce = newNonce();
    const sess = deriveSessionId(request.clientRoot?.sig ?? null, this.cfg.signedRoot.sig, request.nonce, serverNonce, {
      clientPolicyKey: request.clientPolicyKey,
      clientKeyring: request.clientKeyring,
    });
    const disabled = status === "unsafe" ? this.rules.disabledWhenUnsafe : [];
    const reply = signSessionReply(
      {
        serverRoot: this.cfg.signedRoot,
        serverPolicyKey: this.cfg.policyPublicKey,
        serverKeyring: this.cfg.keyring,
        nonce: serverNonce,
        sess,
        status,
        disabled,
      },
      this.cfg.policyPrivateKey,
    );
    this.current = { sess, status, request, nonces: new NonceCache(NONCE_TTL_MS) };
    return reply;
  }

  session(): Session | undefined {
    return this.current;
  }

  attest(
    result: CallToolResult,
    call: { rid: string; callId: string; name: string; args: unknown },
    cls: InfluenceClass,
  ): CallToolResult {
    const session = this.current;
    if (session === undefined) {
      throw new Error("no session");
    }
    const labels: ContentLabel[] = [{ cls, cid: newContentId() }];
    const resultHash = bindResult(result);
    const base = { rid: call.rid, ts: this.now(), inst: this.cfg.inst, sess: session.sess, infl: "" };
    const s0 = signStampV2(
      { ...base, svc: "mcp-entry", bind: bindMcpCall(call.name, call.callId, call.args), prev: "" },
      this.cfg.signingKeys["mcp-entry"],
    );
    const s1 = signStampV2(
      { ...base, svc: "github-tools", bind: bindResponse(resultHash, call.callId, labels), prev: s0.sig },
      this.cfg.signingKeys["github-tools"],
    );
    const attestation: ResponseAttestation = { chain: [s0, s1], proof: this.cfg.routeProof, labels, resultHash };
    return { ...result, _meta: { ...result._meta, [META_ATTESTATION]: attestation } };
  }
}
