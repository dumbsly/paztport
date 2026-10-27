// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  bindResponse,
  bindResult,
  decode,
  deriveSessionId,
  newContentId,
  newNonce,
  NonceCache,
  NONCE_TTL_MS,
  ORIGIN_SVC,
  publicWriteRefused,
  sessionStatus,
  signSessionReply,
  signStampV2,
  type ContentLabel,
  type InfluenceClass,
  type InfluenceEntry,
  type InfluenceFact,
  type MerkleProof,
  type ReasonCode,
  type ResponseAttestation,
  type SessionReply,
  type SessionRequest,
  type SignedRoot,
} from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_ATTESTATION } from "./meta.ts";
import { verifyCall } from "./verify-call.ts";

/** What an MCP server attests with: its policy, its signing keys and the route its responses travel. */
export type ServerPolicy = {
  policyPrivateKey: string;
  policyPublicKey: string;
  /** Each hop's private key, by service name. */
  signingKeys: Record<string, string>;
  keyring: Record<string, string>;
  signedRoot: SignedRoot;
  /** Proof for the route `<entry>/<tools>` of `hops`. */
  routeProof: MerkleProof;
  inst: string;
  /** The services that sign each response, in chain order: the entry that took the call, then the one that ran it. */
  hops: readonly [entry: string, tools: string];
  /** The server id clients name in their receiver, `mcp:<serverId>.<tool>`. */
  serverId: string;
  /** The client policy keys this server opens attested sessions for; empty means every session is unsafe. */
  pinnedClientKeys: readonly string[];
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
 * where no influence rule applies; a server's default should list every write tool.
 */
export type SessionRules = { disabledWhenUnsafe: string[] };

export type ServerCallCheck = { reason: ReasonCode; rid: string; callId: string; influence: InfluenceEntry[]; session: Session };

/** Thrown for a malformed request; an MCP server answers it with -32602 Invalid params. The message names the bad field. */
export class InvalidParams extends Error {}

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
    // a missing signature is not malformed, only unsigned: the session is then unsafe
    clientKeyringSig: typeof params.clientKeyringSig === "string" ? params.clientKeyringSig : "",
    nonce: str(params.nonce, "nonce"),
  };
}

/** The server side of one MCP connection: its paztport/session handshake, call checks and response stamps. */
export class McpServerSession {
  private readonly policy: ServerPolicy;
  private readonly rules: SessionRules;
  private readonly now: () => number;
  private current: Session | undefined;

  constructor(policy: ServerPolicy, rules: SessionRules, now: () => number) {
    this.policy = policy;
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
    const status = sessionStatus(request, this.policy.signedRoot, this.policy.policyPublicKey, this.policy.pinnedClientKeys);
    const serverNonce = newNonce();
    const sess = deriveSessionId(request.clientRoot?.sig ?? null, this.policy.signedRoot.sig, request.nonce, serverNonce, {
      clientPolicyKey: request.clientPolicyKey,
      clientKeyring: request.clientKeyring,
    });
    const disabled = status === "unsafe" ? [...this.rules.disabledWhenUnsafe] : [];
    const reply = signSessionReply(
      {
        serverRoot: this.policy.signedRoot,
        serverPolicyKey: this.policy.policyPublicKey,
        serverKeyring: this.policy.keyring,
        nonce: serverNonce,
        sess,
        status,
        disabled,
      },
      this.policy.policyPrivateKey,
    );
    this.current = { sess, status, request, nonces: new NonceCache(NONCE_TTL_MS), served: new Set() };
    return reply;
  }

  session(): Session | undefined {
    return this.current;
  }

  /** Verifies a tools/call params object against the current attested session's client policy. */
  checkCall(params: Record<string, unknown>): ServerCallCheck {
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
    const v = verifyCall(params, { serverId: this.policy.serverId }, {
      keyring: session.request.clientKeyring,
      root,
      rootId: session.request.clientRoot.rootId,
      allowedOrigins: [ORIGIN_SVC],
      sess: session.sess,
      nonces: session.nonces,
      now: this.now(),
    });
    const reason = v.result.reason === "PATH_NOT_ALLOWED" ? "CLIENT_PATH_NOT_ALLOWED" : v.result.reason;
    return { reason, rid: v.rid, callId: v.callId, influence: reason === "OK" ? v.influence : [], session };
  }

  /** Stamps a result for `session`, the session checkCall verified the call against (not necessarily the current one). */
  attest<R extends Record<string, unknown> & { _meta?: Record<string, unknown> }>(
    session: Session,
    result: R,
    call: { rid: string; callId: string; name: string; args: unknown },
    cls: InfluenceClass,
  ): R {
    const [entry, tools] = this.policy.hops;
    const labels: ContentLabel[] = [{ cls, cid: newContentId() }];
    const resultHash = bindResult(result);
    const base = { rid: call.rid, ts: this.now(), inst: this.policy.inst, sess: session.sess, infl: "" };
    const s0 = signStampV2(
      { ...base, svc: entry, bind: bindMcpCall(call.name, call.callId, call.args), prev: "" },
      this.policy.signingKeys[entry]!,
    );
    const s1 = signStampV2(
      { ...base, svc: tools, bind: bindResponse(resultHash, call.callId, labels), prev: s0.sig },
      this.policy.signingKeys[tools]!,
    );
    const attestation: ResponseAttestation = { chain: [s0, s1], proof: this.policy.routeProof, labels, resultHash };
    session.served.add(cls);
    return { ...result, _meta: { ...result._meta, [META_ATTESTATION]: attestation } };
  }
}

/**
 * What the influence rule sees in an attested session: the client's verified influence plus every
 * class this server served in the session. A served class carries no owner. The union only adds
 * facts, so the server is stricter, never looser, than the harness: a client that fails to record a
 * private (or third-party) label cannot launder it past the rule.
 */
function contextInfluence(influence: InfluenceEntry[], session: Session): InfluenceFact[] {
  return [...influence, ...[...session.served].map((cls) => ({ cls }))];
}

/** The influence rule applied to a tool call: only a write to a public destination is decided by it. */
export function publicWriteDecision(
  isWrite: boolean,
  publicDestination: boolean,
  influence: readonly InfluenceFact[],
  destinationOwner?: string,
): "OK" | "INFLUENCE_DENIED" {
  if (!isWrite || !publicDestination) return "OK";
  return publicWriteRefused(influence, destinationOwner) ? "INFLUENCE_DENIED" : "OK";
}

/**
 * The server's decision on a tools/call, once any chain it carries has verified (`clientInfluence` is
 * then checkCall's influence). In an attested session the influence rule decides, over the union of
 * the client's influence and the classes served in the session. Otherwise (an unsafe session, or no
 * handshake yet) the tools in `rules.disabledWhenUnsafe` are refused and every other tool runs ungated.
 */
export function decideServerCall(opts: {
  tool: string;
  isWrite: boolean;
  publicDestination: boolean;
  session: Session | undefined;
  clientInfluence: InfluenceEntry[];
  rules: SessionRules;
  destinationOwner?: string;
}): "OK" | "UNSAFE_SESSION" | "INFLUENCE_DENIED" {
  const { session } = opts;
  if (session?.status === "attested") {
    return publicWriteDecision(opts.isWrite, opts.publicDestination, contextInfluence(opts.clientInfluence, session), opts.destinationOwner);
  }
  return opts.rules.disabledWhenUnsafe.includes(opts.tool) ? "UNSAFE_SESSION" : "OK";
}
