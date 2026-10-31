// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Test-only simulator of the pi extension's client harness: never part of the server.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  bindPrompt,
  buildPolicy,
  commitInfluence,
  decode,
  generateKeyPair,
  newNonce,
  parseProof,
  NonceCache,
  NONCE_TTL_MS,
  signKeyring,
  signRoot,
  signStampV3,
  verifySessionReply,
  type ContentLabel,
  type InfluenceEntry,
  type MerkleProof,
  type ReasonCode,
  type SessionReply,
  type SessionRequest,
  type SignedRoot,
} from "@paztport/core";
import {
  bindMcpCall,
  META_CALL_ID,
  META_CHAIN,
  META_INFLUENCE,
  META_PROOF,
  verifyMcpResponse,
} from "@paztport/mcp";
import type { CallToolResult } from "../../src/mcp.ts";

export const ALL_TOOLS = [
  "list_issues",
  "issue_read",
  "get_file_contents",
  "search_repositories",
  "create_branch",
  "create_or_update_file",
  "push_files",
  "create_pull_request",
  "add_issue_comment",
];

export type TestClient = {
  request(): SessionRequest;
  acceptReply(reply: SessionReply, pinnedServerKey: string): boolean;
  callParams(
    name: string,
    args: object,
    influence: InfluenceEntry[],
    opts?: { now?: number; callId?: string; rid?: string },
  ): Record<string, unknown>;
  verify(
    result: CallToolResult,
    call: { rid: string; toolCallId: string },
    serverKeyring: Record<string, string>,
    serverRoot: SignedRoot,
    now?: number,
  ): { reason: ReasonCode; labels: ContentLabel[] };
};

/** The policy key every generated test client signs with, so a test server can pin it. */
export const CLIENT_POLICY = generateKeyPair();

/** When a generated test client's root and keyring stop being valid: 2100-01-01. */
export const CLIENT_NOT_AFTER = 4_102_444_800_000;

/** `keyringSig` is the policy key's signature over the session and pi keys and `keyringNotAfter`, the keyring's window. */
type ClientMaterial = {
  policyPublicKey: string;
  session: { privateKey: string; publicKey: string };
  pi: { privateKey: string; publicKey: string };
  keyringSig: string;
  keyringNotAfter: number;
  signedRoot: SignedRoot;
  proofFor(tool: string): MerkleProof;
};

function generatedMaterial(tools: string[]): ClientMaterial {
  const policy = CLIENT_POLICY;
  const { signedRoot, bundles } = buildPolicy(
    tools.map((t) => ["session", "pi", `mcp:github.${t}`]),
    8,
    policy.privateKey,
    CLIENT_NOT_AFTER,
  );
  const session = generateKeyPair();
  const pi = generateKeyPair();
  return {
    policyPublicKey: policy.publicKey,
    session,
    pi,
    keyringSig: signKeyring({ session: session.publicKey, pi: pi.publicKey }, policy.publicKey, policy.privateKey, CLIENT_NOT_AFTER).sig,
    keyringNotAfter: CLIENT_NOT_AFTER,
    signedRoot,
    proofFor: (tool) => bundles["pi"]!.proofs[`session/pi/mcp:github.${tool}`]!,
  };
}

/** Loads what `setup-demo.ts` wrote into `<out>/client`: session/pi keys, keyring, root and pi's proofs. */
function loadMaterial(dir: string): ClientMaterial {
  const text = (f: string) => readFileSync(join(dir, f), "utf8").trim();
  const json = (f: string) => JSON.parse(text(f)) as any;
  const ring = json("keyring.json");
  const bundle = json("proofs-pi.json");
  return {
    policyPublicKey: ring.policy,
    session: { privateKey: text("session.key"), publicKey: ring.services.session },
    pi: { privateKey: text("pi.key"), publicKey: ring.services.pi },
    keyringSig: ring.sig,
    keyringNotAfter: ring.notAfter,
    signedRoot: json("root.json"),
    proofFor: (tool) => parseProof(bundle.proofs[`session/pi/mcp:github.${tool}`]),
  };
}

/**
 * `forgeRoot` signs the client root with a key other than the advertised clientPolicyKey.
 * `fromDir` uses the keys, root and proofs produced by `setup-demo.ts` instead of generating fresh ones.
 */
export function makeClient(opts: { withRoot?: boolean; forgeRoot?: boolean; tools?: string[]; fromDir?: string } = {}): TestClient {
  const m = opts.fromDir !== undefined ? loadMaterial(opts.fromDir) : generatedMaterial(opts.tools ?? ALL_TOOLS);
  const { session, pi, signedRoot } = m;
  const policy = { publicKey: m.policyPublicKey };
  const forged = opts.forgeRoot ? signRoot(decode(signedRoot.root), signedRoot.rootId, generateKeyPair().privateKey, CLIENT_NOT_AFTER) : signedRoot;
  const clientRoot: SignedRoot | null = opts.withRoot === false ? null : forged;
  const responseNonces = new NonceCache(NONCE_TTL_MS);
  let req: SessionRequest | undefined;
  let sess: string | undefined;
  let seq = 0;

  const request = (): SessionRequest => {
    req = {
      clientRoot,
      clientPolicyKey: policy.publicKey,
      clientKeyring: { session: session.publicKey, pi: pi.publicKey },
      clientKeyringSig: m.keyringSig,
      clientKeyringNotAfter: m.keyringNotAfter,
      nonce: newNonce(),
    };
    return req;
  };

  return {
    request,
    acceptReply(reply, pinnedServerKey) {
      if (req === undefined || !verifySessionReply(reply, req, pinnedServerKey, "mcp-entry", Date.now())) {
        return false;
      }
      sess = reply.sess;
      return true;
    },
    callParams(name, args, influence, o = {}) {
      if (sess === undefined) {
        throw new Error("no accepted session");
      }
      const now = o.now ?? Date.now();
      const rid = o.rid ?? `rid-${++seq}`;
      const callId = o.callId ?? `call-${seq}`;
      const s0 = signStampV3(
        { svc: "session", inst: "session-1", rid, ts: now, sess, rcv: "pi", bind: bindPrompt("test prompt"), infl: "", prev: "" },
        session.privateKey,
      );
      const s1 = signStampV3(
        {
          svc: "pi",
          inst: "pi-1",
          rid,
          ts: now,
          sess,
          rcv: `mcp:github.${name}`,
          bind: bindMcpCall(name, callId, args),
          infl: commitInfluence(influence),
          prev: s0.sig,
        },
        pi.privateKey,
      );
      return {
        name,
        arguments: args,
        _meta: {
          [META_CHAIN]: [s0, s1],
          [META_PROOF]: m.proofFor(name),
          [META_INFLUENCE]: influence,
          [META_CALL_ID]: callId,
        },
      };
    },
    verify(result, call, serverKeyring, serverRoot, now = Date.now()) {
      if (sess === undefined) {
        throw new Error("no accepted session");
      }
      const r = verifyMcpResponse(result, { ...call, receiver: "pi" }, {
        keyring: serverKeyring,
        root: decode(serverRoot.root),
        rootId: serverRoot.rootId,
        allowedOrigins: ["mcp-entry"],
        sess,
        nonces: responseNonces,
        now,
        policyNotAfter: serverRoot.notAfter,
      });
      return { reason: r.result.reason, labels: r.labels };
    },
  };
}
