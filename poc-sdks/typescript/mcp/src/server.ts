// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

import {
  bindResponse,
  bindResult,
  buildSessionReply,
  checkOwnMaterial,
  decode,
  describeNotAfter,
  describeOwnMaterialProblem,
  earliestNotAfter,
  expiryWarnings,
  keyPairMatches,
  newContentId,
  NonceCache,
  NONCE_TTL_MS,
  parseSessionRequest,
  provesPath,
  signStampV3,
  verifyReplyCert,
  type ContentLabel,
  type InfluenceClass,
  type InfluenceEntry,
  type LegacySessionRequest,
  type MerkleProof,
  type ReasonCode,
  type ReplyCert,
  type ResponseAttestation,
  type SessionReply,
  type SessionRequest,
  type SignedRoot,
} from "@paztport/core";
import { bindMcpCall } from "./binding.ts";
import { META_ATTESTATION } from "./meta.ts";
import { verifyCall } from "./verify-call.ts";

/**
 * What an MCP server attests with: its policy, its signing keys and the route its responses travel. It holds no
 * policy private key: session replies are signed by the entry's key (`hops[0]`), under `keyringSig` and `replyCert`.
 */
export type ServerPolicy = {
  policyPublicKey: string;
  /** Each hop's private key, by service name. */
  signingKeys: Record<string, string>;
  keyring: Record<string, string>;
  /** The policy key's signature over `keyring` and `keyringNotAfter`. */
  keyringSig: string;
  /** The keyring's window, which checkServerPolicy requires (a policy without one is the old form); replies carry it as `serverKeyringNotAfter`. */
  keyringNotAfter: number;
  /** The policy key's certificate for the entry's key; checkServerPolicy refuses one that is not for `hops[0]`'s keyring key or has expired. */
  replyCert: ReplyCert;
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
  /** The services whose origin stamp a call chain may start with, the client's origin names; required and non-empty, with no default. */
  clientOrigins: readonly string[];
};

export type Session = {
  sess: string;
  status: "attested" | "unsafe";
  request: SessionRequest | LegacySessionRequest;
  nonces: NonceCache;
  /** Every class this server has attested in a response in this session (sticky). */
  served: Set<InfluenceClass>;
};

/**
 * Tools refused in an unsafe session. A tool left out of this list runs ungated in unsafe sessions,
 * where no influence rule applies; a server's default should list every write tool.
 */
export type SessionRules = { disabledWhenUnsafe: string[] };

/** A call check's verdict; `caller` is the verified call's last signer, "" when the call did not verify. */
export type ServerCallCheck = { reason: ReasonCode; rid: string; callId: string; influence: InfluenceEntry[]; caller: string; session: Session };

/** Thrown for a malformed request; an MCP server answers it with -32602 Invalid params. The message names the bad field. */
export class InvalidParams extends Error {}

/**
 * Throws an Error naming the fault unless `policy` can serve at `now`: the keyring is in the new form, signed by
 * `policyPublicKey` over `keyringNotAfter`, and current; `signingKeys[hops[0]]` is the entry's keyring key; `replyCert`
 * verifies under `policyPublicKey`, is for `hops[0]` and that key, and has not expired; the root is in the new form,
 * current and signed by `policyPublicKey`; the keyring has its own key for `hops[1]` and `signingKeys[hops[1]]` matches
 * it; `clientOrigins` is non-empty; and `routeProof` proves `hops[0]/hops[1]` against the root. The keyring and root checks are core's
 * checkOwnMaterial; the rest is this server's. McpServerSession calls it on construction.
 */
export function checkServerPolicy(policy: ServerPolicy, now: number): void {
  const entry = policy.hops[0];
  const tools = policy.hops[1];
  if (!Array.isArray(policy.clientOrigins) || policy.clientOrigins.length === 0 || !policy.clientOrigins.every((o) => typeof o === "string" && o !== "")) {
    throw new Error("server policy refused: clientOrigins must name at least one origin service");
  }
  const own = checkOwnMaterial(policy, now);
  const refuseOwn = (subject: "keyring" | "root"): void => {
    const problem = own.find((p) => p.subject === subject);
    if (problem !== undefined) {
      throw new Error(`server policy refused: ${describeOwnMaterialProblem(problem)}`);
    }
  };
  refuseOwn("keyring");
  if (!Object.hasOwn(policy.keyring, entry)) {
    throw new Error(`server policy refused: the keyring has no key for the entry ${entry}`);
  }
  const entryKey = policy.keyring[entry]!;
  const signingKey = Object.hasOwn(policy.signingKeys, entry) ? policy.signingKeys[entry] : undefined;
  if (typeof signingKey !== "string" || !keyPairMatches(signingKey, entryKey)) {
    throw new Error(`server policy refused: signingKeys[${entry}] is not the entry's keyring key`);
  }
  const cert = policy.replyCert;
  if (!verifyReplyCert(cert, policy.policyPublicKey)) {
    throw new Error("server policy refused: replyCert is not signed by policyPublicKey");
  }
  if (cert.svc !== entry) {
    throw new Error(`server policy refused: replyCert is for ${cert.svc}, not the entry ${entry}`);
  }
  if (cert.key !== entryKey) {
    throw new Error("server policy refused: replyCert names a key other than the entry's keyring key");
  }
  if (now > cert.notAfter) {
    throw new Error(`server policy refused: replyCert expired at ${describeNotAfter(cert.notAfter)}`);
  }
  refuseOwn("root");
  const root = policy.signedRoot;
  if (!Object.hasOwn(policy.keyring, tools)) {
    throw new Error(`server policy refused: the keyring has no key for the tools hop ${tools}`);
  }
  const toolsKey = Object.hasOwn(policy.signingKeys, tools) ? policy.signingKeys[tools] : undefined;
  if (typeof toolsKey !== "string" || !keyPairMatches(toolsKey, policy.keyring[tools]!)) {
    throw new Error(`server policy refused: signingKeys[${tools}] is not the tools hop's keyring key`);
  }
  let rootBytes: Uint8Array;
  try {
    rootBytes = decode(root.root);
  } catch {
    throw new Error("server policy refused: the root is not valid base64url");
  }
  if (!provesPath(policy.routeProof, `${entry}/${tools}`, rootBytes, root.rootId)) {
    throw new Error(`server policy refused: the route proof for ${entry}/${tools} does not prove against the root`);
  }
}

/** The server side of one MCP connection: its paztport/session handshake, call checks and response stamps. */
export class McpServerSession {
  private readonly policy: ServerPolicy;
  private readonly rules: SessionRules;
  private readonly now: () => number;
  private current: Session | undefined;

  /**
   * Throws, as checkServerPolicy does at `now()`, for a policy whose replies no client would accept. Then passes each
   * expiryWarnings message to `warn`, by default `console.error` (stderr: a stdio server's stdout carries the protocol).
   */
  constructor(policy: ServerPolicy, rules: SessionRules, now: () => number, warn: (message: string) => void = console.error) {
    checkServerPolicy(policy, now());
    for (const message of expiryWarnings(policy, now())) warn(message);
    this.policy = policy;
    this.rules = rules;
    this.now = now;
  }

  /**
   * Handles a paztport/session handshake. There is one session per connection: a new handshake
   * replaces the current session (its keyring, nonces and served classes), so calls signed for the
   * old session are refused afterwards. A malformed request throws InvalidParams. The reply is in the entry-key
   * form, signed by the entry's key; only the key changed: "attested" is said only after sessionStatus's checks, at
   * `now()`: an old-form or expired client root or keyring makes the session unsafe, and so does this server's own
   * root or keyring once it has expired, so a server left running past its material degrades to unattested
   * sessions rather than stopping. It carries the keyring's window as `serverKeyringNotAfter` when the keyring has one.
   */
  openSession(params: unknown): SessionReply {
    let request: SessionRequest | LegacySessionRequest;
    try {
      request = parseSessionRequest(params);
    } catch (e) {
      throw new InvalidParams((e as Error).message);
    }
    const reply = buildSessionReply(
      { ...this.policy, entryPrivateKey: this.policy.signingKeys[this.policy.hops[0]]! },
      request,
      { pinnedClientKeys: this.policy.pinnedClientKeys, disabledWhenUnsafe: this.rules.disabledWhenUnsafe },
      this.now(),
    );
    const { sess, status } = reply;
    this.current = { sess, status, request, nonces: new NonceCache(NONCE_TTL_MS), served: new Set() };
    return reply;
  }

  session(): Session | undefined {
    return this.current;
  }

  /** Verifies a tools/call params object against the current attested session's client policy, until the earlier of the client root's and keyring's windows (POLICY_EXPIRED after it, and always for old-form material). */
  checkCall(params: Record<string, unknown>): ServerCallCheck {
    const session = this.current;
    if (session === undefined || session.status !== "attested" || session.request.clientRoot === null) {
      throw new Error("checkCall needs an attested session");
    }
    let root: Uint8Array;
    try {
      root = decode(session.request.clientRoot.root);
    } catch {
      return { reason: "CHAIN_MISSING", rid: "", callId: "", influence: [], caller: "", session };
    }
    const v = verifyCall(params, { serverId: this.policy.serverId }, {
      keyring: session.request.clientKeyring,
      root,
      rootId: session.request.clientRoot.rootId,
      allowedOrigins: this.policy.clientOrigins,
      sess: session.sess,
      nonces: session.nonces,
      now: this.now(),
      policyNotAfter: earliestNotAfter(session.request.clientRoot.notAfter, session.request.clientKeyringNotAfter),
    });
    const reason = v.result.reason === "PATH_NOT_ALLOWED" ? "CLIENT_PATH_NOT_ALLOWED" : v.result.reason;
    const ok = reason === "OK";
    return { reason, rid: v.rid, callId: v.callId, influence: ok ? v.influence : [], caller: ok ? v.result.suspectSvc : "", session };
  }

  /**
   * Stamps a result for `session`, the session checkCall verified the call against (not necessarily the current
   * one). The chain runs entry, then tools, then back to `call.caller`, checkCall's caller: the client that made the call.
   */
  attest<R extends Record<string, unknown> & { _meta?: Record<string, unknown> }>(
    session: Session,
    result: R,
    call: { rid: string; callId: string; name: string; args: unknown; caller: string },
    cls: InfluenceClass,
  ): R {
    const [entry, tools] = this.policy.hops;
    const labels: ContentLabel[] = [{ cls, cid: newContentId() }];
    const resultHash = bindResult(result);
    const base = { rid: call.rid, ts: this.now(), inst: this.policy.inst, sess: session.sess, infl: "" };
    const s0 = signStampV3(
      { ...base, svc: entry, rcv: tools, bind: bindMcpCall(call.name, call.callId, call.args), prev: "" },
      this.policy.signingKeys[entry]!,
    );
    const s1 = signStampV3(
      { ...base, svc: tools, rcv: call.caller, bind: bindResponse(resultHash, call.callId, labels), prev: s0.sig },
      this.policy.signingKeys[tools]!,
    );
    const attestation: ResponseAttestation = { chain: [s0, s1], proof: this.policy.routeProof, labels, resultHash };
    session.served.add(cls);
    return { ...result, _meta: { ...result._meta, [META_ATTESTATION]: attestation } };
  }
}
