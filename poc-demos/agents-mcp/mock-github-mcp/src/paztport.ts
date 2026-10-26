// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  bindMcpCall,
  bindResponse,
  bindResult,
  decode,
  deriveSessionId,
  META_ATTESTATION,
  newContentId,
  newNonce,
  NonceCache,
  NONCE_TTL_MS,
  parseProof,
  sessionStatus,
  sign,
  signSessionReply,
  signStampV2,
  utf8,
  verify,
  verifyCall,
  verifyProof,
  verifyRoot,
  type ContentLabel,
  type InfluenceClass,
  type InfluenceEntry,
  type MerkleProof,
  type ReasonCode,
  type ResponseAttestation,
  type SessionReply,
  type SessionRequest,
  type SignedRoot,
} from "@paztport/core";
import { InvalidParams, type CallToolResult } from "./mcp.ts";

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
  /** Every class this server has attested in a response in this session (sticky). */
  served: Set<InfluenceClass>;
};

/**
 * Tools refused in an unsafe session. A tool left out of this list runs ungated in unsafe sessions,
 * where no influence rule applies; the server's default lists every write tool.
 */
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

/** Copies a string map into an object whose keys (even "__proto__") are ordinary own properties. */
function stringMap(v: Record<string, unknown>, what: string): Record<string, string> {
  return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, str(x, `${what} entry ${k}`)]));
}

const PROBE = utf8("paztport-mock-github key probe");

/** True when the private key signs a probe that the public key verifies. */
function keysMatch(privateKey: string, publicKey: string): boolean {
  try {
    return verify(publicKey, PROBE, sign(privateKey, PROBE));
  } catch {
    return false;
  }
}

/** Throws a clear Error unless the loaded files are mutually consistent. */
function validateServerConfig(cfg: ServerPaztportConfig): void {
  if (!verifyRoot(cfg.signedRoot, cfg.policyPublicKey)) {
    throw new Error("root.json is not signed by the keyring.json policy key");
  }
  if (!keysMatch(cfg.policyPrivateKey, cfg.policyPublicKey)) {
    throw new Error("policy.key does not match the keyring.json policy key");
  }
  for (const svc of ["mcp-entry", "github-tools"] as const) {
    if (!Object.hasOwn(cfg.keyring, svc)) {
      throw new Error(`keyring.json has no entry for ${svc}`);
    }
    if (!keysMatch(cfg.signingKeys[svc], cfg.keyring[svc]!)) {
      throw new Error(`${svc}.key does not match its keyring.json entry`);
    }
  }
  let rootBytes: Uint8Array;
  try {
    rootBytes = decode(cfg.signedRoot.root);
  } catch {
    throw new Error("root.json root is not valid base64url");
  }
  if (cfg.routeProof.rootId !== cfg.signedRoot.rootId || !verifyProof(cfg.routeProof, ROUTE, rootBytes)) {
    throw new Error(`route proof for ${ROUTE} does not verify against root.json`);
  }
}

/** Loads and validates the files the policy-tool keygen and policy CLIs write into one directory. */
export function loadServerConfig(dir: string): ServerPaztportConfig {
  const ring = readJson(join(dir, "keyring.json"));
  if (!isObject(ring) || !isObject(ring.services)) {
    throw new Error("malformed keyring.json");
  }
  const keyring = stringMap(ring.services, "keyring");
  const root = readJson(join(dir, "root.json"));
  if (!isObject(root)) {
    throw new Error("malformed root.json");
  }
  const signedRoot: SignedRoot = { rootId: str(root.rootId, "rootId"), root: str(root.root, "root"), sig: str(root.sig, "sig") };
  const bundle = readJson(join(dir, "proofs-mcp-entry.json"));
  const rawProof = isObject(bundle) && isObject(bundle.proofs) && Object.hasOwn(bundle.proofs, ROUTE) ? bundle.proofs[ROUTE] : undefined;
  if (rawProof === undefined) {
    throw new Error(`proofs-mcp-entry.json has no proof for ${ROUTE}`);
  }
  let routeProof: MerkleProof;
  try {
    routeProof = parseProof(rawProof);
  } catch (e) {
    throw new Error(`malformed route proof for ${ROUTE} in proofs-mcp-entry.json: ${(e as Error).message}`);
  }
  const cfg: ServerPaztportConfig = {
    policyPrivateKey: readText(join(dir, "policy.key")),
    policyPublicKey: str(ring.policy, "keyring policy"),
    signingKeys: { "mcp-entry": readText(join(dir, "mcp-entry.key")), "github-tools": readText(join(dir, "github-tools.key")) },
    keyring,
    signedRoot,
    routeProof,
    inst: "mock-github-1",
  };
  validateServerConfig(cfg);
  return cfg;
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
  const clientKeyring = stringMap(params.clientKeyring, "clientKeyring");
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

  /**
   * Handles a paztport/session handshake. There is one session per connection: a new handshake
   * replaces the current session (its keyring, nonces and served classes), so calls signed for the
   * old session are refused afterwards. A malformed request throws InvalidParams.
   */
  openSession(params: unknown): SessionReply {
    let request: SessionRequest;
    try {
      request = parseSessionRequest(params);
    } catch (e) {
      throw new InvalidParams((e as Error).message);
    }
    const status = sessionStatus(request, this.cfg.signedRoot, this.cfg.policyPublicKey);
    const serverNonce = newNonce();
    const sess = deriveSessionId(request.clientRoot?.sig ?? null, this.cfg.signedRoot.sig, request.nonce, serverNonce, {
      clientPolicyKey: request.clientPolicyKey,
      clientKeyring: request.clientKeyring,
    });
    const disabled = status === "unsafe" ? [...this.rules.disabledWhenUnsafe] : [];
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
    this.current = { sess, status, request, nonces: new NonceCache(NONCE_TTL_MS), served: new Set() };
    return reply;
  }

  session(): Session | undefined {
    return this.current;
  }

  /** Verifies a tools/call params object against the current attested session's client policy. */
  checkCall(
    params: Record<string, unknown>,
  ): { reason: ReasonCode; rid: string; callId: string; influence: InfluenceEntry[]; session: Session } {
    const session = this.current;
    if (session === undefined || session.status !== "attested" || session.request.clientRoot === null) {
      throw new Error("checkCall needs an attested session");
    }
    let root: Uint8Array;
    try {
      root = decode(session.request.clientRoot.root);
    } catch {
      return { reason: "CHAIN_MISSING", rid: "", callId: "", influence: [], session };
    }
    const v = verifyCall(params, { serverId: "github" }, {
      keyring: session.request.clientKeyring,
      root,
      rootId: session.request.clientRoot.rootId,
      allowedOrigins: ["session"],
      sess: session.sess,
      nonces: session.nonces,
      now: this.now(),
    });
    const reason = v.result.reason === "PATH_NOT_ALLOWED" ? "CLIENT_PATH_NOT_ALLOWED" : v.result.reason;
    return { reason, rid: v.rid, callId: v.callId, influence: reason === "OK" ? v.influence : [], session };
  }

  /** Stamps a result for `session`, the session checkCall verified the call against (not necessarily the current one). */
  attest(
    session: Session,
    result: CallToolResult,
    call: { rid: string; callId: string; name: string; args: unknown },
    cls: InfluenceClass,
  ): CallToolResult {
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
    session.served.add(cls);
    return { ...result, _meta: { ...result._meta, [META_ATTESTATION]: attestation } };
  }
}
