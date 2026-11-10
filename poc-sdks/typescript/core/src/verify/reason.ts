// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The outcome of verification: "OK" or exactly one reason for rejection. Each code names the check of the spec's live
 * order (verification.md) that gives it; the first check that fails is the result. A service that enforces refuses a
 * call whose verification gives any code but "OK": over MCP with an error result whose verdict carries the code,
 * over HTTP (the Java and Go SDKs) with the status each code names and the body `{"reason":"<code>"}`; in audit mode
 * it serves the call and reports the code. A response check that fails refuses nothing: the response counts as
 * `local-untrusted`. The codes in OfflineReasonCode come from the offline verifier of a record and are never given
 * live; a client never accepts one as a server's verdict.
 */
export type ReasonCode =
  /** Every check held. Not a refusal. */
  | "OK"
  /** Check 1: no chain, or one that does not read, or a transport field around it that does not read. 403. */
  | "CHAIN_MISSING"
  /** Check 3: the origin's service is not an allowed origin (offline, also: not the expected instance). 403. */
  | "BAD_ORIGIN"
  /**
   * Check 2: a signed field holds `|`. Check 4: a stamp's service has no key in a current keyring, or its signature
   * fails (offline, also: it is not by the expected signer). 403.
   */
  | "BAD_SIGNATURE"
  /** Check 4: a stamp's `prev` is not the previous stamp's `sig`, or not empty at the origin. 403. */
  | "BROKEN_LINK"
  /**
   * Check 7: the last stamp is outside the call window, or the origin outside the run's lifetime (offline, outside the
   * age limits). 403. Also the client's local gate's refusal of a step on an origin outside the age limits.
   */
  | "EXPIRED"
  /** Check 5: the stamps do not all carry the origin's `rid`, or they name another request. 403. */
  | "RID_MISMATCH"
  /**
   * Check 4: a stamp's `rcv` names the wrong hop: one before the last is not the next stamp's svc, bare or with `#`
   * and an operation, or the last is not the chain's receiver. Check 8: the last stamp's `bind` is not the binding of
   * what was received. Before the live order, over MCP: a call whose tools/call binding cannot be computed, or a
   * response whose resultHash is not the result received or whose response binding cannot be computed. Offline: a
   * local step whose decision does not read, is for another call, or cannot be bound. 403.
   */
  | "BINDING_MISMATCH"
  /**
   * Check 10: the nonce key was seen before, or the nonce cache forgets keys sooner than twice the call window. 403.
   */
  | "REPLAY"
  /**
   * Check 11: the route is not proven against a current pinned root. 403. Also the client's local gate's verdict for a
   * tool its route list does not have.
   */
  | "PATH_NOT_ALLOWED"
  /**
   * Check 6: a stamp names another session. Over HTTP, also a call whose `X-Path-Session` names no live session opened
   * by the sending peer. 403.
   */
  | "SESSION_UNKNOWN"
  /** Check 11 at an MCP server, against the client's policy: its name for PATH_NOT_ALLOWED there. */
  | "CLIENT_PATH_NOT_ALLOWED"
  /**
   * Check 9: the influence does not read, or the last stamp does not commit to it. 403; but influence that does not
   * read is refused 400 wherever verification has not refused the request first, in audit mode too.
   */
  | "INFLUENCE_MISMATCH"
  /**
   * No check of the live order: the owner-aware rule refused a public write, in a server's decision on a call or in
   * the client's local gate.
   */
  | "INFLUENCE_DENIED"
  /** No check of the live order: in an unsafe session, the call reached an endpoint or tool disabled there. 403. */
  | "UNSAFE_SESSION"
  /** No check of the live order: the client's local gate refused a path or program outside the signed rules. */
  | "SCOPE_DENIED"
  /** No check of the live order: the client's local gate could not tell what the call would touch. */
  | "UNCHECKABLE"
  /** Offline only, check 7: a stamp's `ts` is not the time recorded with it, or no time is recorded. */
  | "TIME_MISMATCH"
  /** Offline only, check 7: the origin does not bind the run's recorded prompt. */
  | "PROMPT_MISMATCH"
  /**
   * Offline only: a recorded call that otherwise verifies, in a session whose recorded handshake is attested, but whose
   * last stamp's `ts` is past one of the session's limits.
   */
  | "OUTSIDE_SESSION"
  /** Offline only: a recorded local step whose recorded route verdict or proof disagrees with what its chain proves. */
  | "PROOF_MISMATCH"
  /** Offline only: a recorded local step whose signed `rulesHash` is not the client's. */
  | "RULES_MISMATCH"
  /** Offline only: a recorded local step whose decision, re-derived from its signed rules, is not the one it signed. */
  | "VERDICT_MISMATCH"
  /** Check 12: the peer the transport authenticated is not the last signer. 403. */
  | "PEER_MISMATCH"
  /**
   * Check 0: every keyring, or every root, the verifier pins is past its notAfter, so the policy owner no longer
   * vouches for them. It is about the verifier's own configuration, not the request, so it names no one. 403. Also the
   * client's local gate's refusal of a step under an expired root or keyring.
   */
  | "POLICY_EXPIRED";

/**
 * The codes only the offline verifier of a recorded chain gives, which ReasonCode also holds; no live verifier or
 * server returns them.
 */
export type OfflineReasonCode =
  | "TIME_MISMATCH"
  | "PROMPT_MISMATCH"
  | "OUTSIDE_SESSION"
  | "PROOF_MISMATCH"
  | "RULES_MISMATCH"
  | "VERDICT_MISMATCH";

/**
 * A typed verification outcome, naming a suspect for the responder's quarantine decision. With a transport
 * peer, the suspect is that authenticated sender, at every check, OK included: `suspectSvc` is its service and
 * `suspectInst` its address. Without one, `suspectSvc` names the last service that provably sent the request,
 * proven by its key, and `suspectInst` the instance that service reported in its own stamp; they are set only
 * for `OK` and `PATH_NOT_ALLOWED`, and every other rejection leaves them empty, because the name would be
 * unsigned or the genuine stamp would belong to another request. A v3 stamp binds its receiver, so a chain
 * forwarded unchanged to another receiver is BINDING_MISMATCH, and names no one without a peer. POLICY_EXPIRED
 * names no one even with a peer: it is the verifier's own policy running out, not the sender's doing.
 */
export type VerifyResult = { ok: boolean; reason: ReasonCode; suspectSvc: string; suspectInst: string };
