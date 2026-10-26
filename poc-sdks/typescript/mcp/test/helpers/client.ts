// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Test-only simulator of an MCP client harness (session, then pi): never part of the server.

import {
  bindPrompt,
  buildPolicy,
  commitInfluence,
  decode,
  generateKeyPair,
  newNonce,
  NonceCache,
  NONCE_TTL_MS,
  signRoot,
  signStampV2,
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
} from "../../src/index.ts";

/** The MCP tools/call result shape these tests use. */
export type CallToolResult = {
  content: { type: "text"; text: string }[];
  isError?: boolean;
  structuredContent?: unknown;
  _meta?: Record<string, unknown>;
};

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

/** `forgeRoot` signs the client root with a key other than the advertised clientPolicyKey. */
type ClientMaterial = {
  policyPublicKey: string;
  session: { privateKey: string; publicKey: string };
  pi: { privateKey: string; publicKey: string };
  signedRoot: SignedRoot;
  proofFor(tool: string): MerkleProof;
};

function generatedMaterial(tools: string[]): ClientMaterial & { policyPrivateKey: string } {
  const policy = generateKeyPair();
  const { signedRoot, bundles } = buildPolicy(
    tools.map((t) => ["session", "pi", `mcp:github.${t}`]),
    8,
    policy.privateKey,
  );
  return {
    policyPublicKey: policy.publicKey,
    policyPrivateKey: policy.privateKey,
    session: generateKeyPair(),
    pi: generateKeyPair(),
    signedRoot,
    proofFor: (tool) => bundles["pi"]!.proofs[`session/pi/mcp:github.${tool}`]!,
  };
}

/**
 * `forgeRoot` signs the client root with a key other than the advertised clientPolicyKey.
 * `tools` limits the client policy to those tools' routes.
 */
export function makeClient(opts: { withRoot?: boolean; forgeRoot?: boolean; tools?: string[] } = {}): TestClient {
  const m = generatedMaterial(opts.tools ?? ALL_TOOLS);
  const { session, pi, signedRoot } = m;
  const policy = { publicKey: m.policyPublicKey };
  const forged = opts.forgeRoot ? signRoot(decode(signedRoot.root), signedRoot.rootId, generateKeyPair().privateKey) : signedRoot;
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
      nonce: newNonce(),
    };
    return req;
  };

  return {
    request,
    acceptReply(reply, pinnedServerKey) {
      if (req === undefined || !verifySessionReply(reply, req, pinnedServerKey)) {
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
      const s0 = signStampV2(
        { svc: "session", inst: "session-1", rid, ts: now, sess, bind: bindPrompt("test prompt"), infl: "", prev: "" },
        session.privateKey,
      );
      const s1 = signStampV2(
        { svc: "pi", inst: "pi-1", rid, ts: now, sess, bind: bindMcpCall(name, callId, args), infl: commitInfluence(influence), prev: s0.sig },
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
      const r = verifyMcpResponse(result, call, {
        keyring: serverKeyring,
        root: decode(serverRoot.root),
        rootId: serverRoot.rootId,
        allowedOrigins: ["mcp-entry"],
        sess,
        nonces: responseNonces,
        now,
      });
      return { reason: r.result.reason, labels: r.labels };
    },
  };
}
