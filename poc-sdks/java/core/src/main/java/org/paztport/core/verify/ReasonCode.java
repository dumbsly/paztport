// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

/**
 * The outcome of verification: {@link #OK} or exactly one reason for rejection. Each constant names the check of the
 * spec's live order (verification.md) that gives it; the first check that fails is the result. A service that
 * enforces refuses a request whose verification gives any code but {@code OK}, over HTTP with the status each
 * constant names and the body {@code {"reason":"<code>"}}; in audit mode it serves the request and reports the code.
 * A response that fails check 9c is refused by the caller; one that fails any other check is used as not verified
 * (verification.md, The live order). A code marked offline only comes from the offline verifier of a record and is
 * never given live.
 */
public enum ReasonCode {
    /** Every check held. Not a refusal. */
    OK,
    /**
     * Check 1: no chain, or one that does not read (a stamp whose {@code v} is not 4 included), or a transport field
     * around it that does not read. 403.
     */
    CHAIN_MISSING,
    /** Check 2: the origin's service is not an allowed origin (offline, also: not the expected instance). 403. */
    BAD_ORIGIN,
    /**
     * Check 3: a stamp's service has no key in a current keyring, or its signature fails (offline, also: it is not by
     * the expected signer). 403.
     */
    BAD_SIGNATURE,
    /** Check 3: a stamp's {@code prev} is not the previous stamp's {@code sig}, or not empty at the origin. 403. */
    BROKEN_LINK,
    /**
     * Check 7: the last stamp is outside the call window, or the origin outside the run's lifetime (offline, outside
     * the age limits). 403.
     */
    EXPIRED,
    /** Check 5: the stamps do not all carry the origin's {@code rid}, or they name another request. 403. */
    RID_MISMATCH,
    /**
     * Check 4: a stamp's {@code rcv} names the wrong hop: one before the last is not the next stamp's
     * {@code svc}, bare or with {@code #} and an operation, or the last is not this receiver or the operation it
     * dispatches the request to, a keyed operation with no key value included, verified as dispatched to none.
     * Check 8: the last stamp's {@code bind} is not the binding of what was received. And the Spring starter's
     * dispatch check: the handler about to run is another operation, or for a keyed one reads a different key value
     * or none. 403.
     */
    BINDING_MISMATCH,
    /**
     * Check 11: the nonce key was seen before, or the nonce cache forgets keys sooner than twice the call window.
     * 403.
     */
    REPLAY,
    /** Check 12: the route is not proven against a current pinned root. 403. */
    PATH_NOT_ALLOWED,
    /**
     * Check 6: a stamp names another session. Over HTTP, also a call whose {@code X-Path-Session} names no live
     * session opened by the sending peer. 403.
     */
    SESSION_UNKNOWN,
    /**
     * Check 9a: the blocks do not read, are not one per stamp, or one does not match its stamp's {@code ext}. 403;
     * but 400 at every service about to serve a request it did not verify, which applies check 9a itself whenever
     * the chain read (verification.md, "A service never serves a request whose blocks fail check 9a"): in audit
     * mode, with no verifier, or with Paztport off.
     */
    EXTENSION_MISMATCH,
    /**
     * Check 9b: a block holds, in {@code items} or {@code requires}, a name the verifier's
     * {@code allowedExtensions} does not hold. 403.
     */
    EXTENSION_NOT_ALLOWED,
    /**
     * Check 9c, live only: the last block requires an extension the receiver does not act on. 403. A recorded call or
     * response was held to it live, so no offline verifier gives it.
     */
    EXTENSION_REQUIRED,
    /**
     * No check of the live order: the extension {@code influence} refused an item on a request's block that does not
     * read as an entry. 400 over HTTP in either mode; live and offline.
     */
    INFLUENCE_MISMATCH,
    /** Check 10: the peer the transport authenticated is not the last signer. 403. */
    PEER_MISMATCH,
    /** Offline only, check 7: a stamp's {@code ts} is not the time recorded with it, or no time is recorded. */
    TIME_MISMATCH,
    /** Offline only, check 7: the origin does not bind the run's recorded prompt. */
    PROMPT_MISMATCH,
    /**
     * No check of the live order: the every-stamp rule or the owner-aware rule of the extension {@code influence}
     * refused a public write. {@code Influence.decide} gives it, and the handler answers the write: 403 over HTTP in
     * either mode.
     */
    INFLUENCE_DENIED,
    /**
     * No check of the live order: the extension {@code intent} refused the items handed over under it, which do not
     * read as at most one item of facts in the origin's block and none in any later block. 400 over HTTP in either
     * mode; live only.
     */
    INTENT_MISMATCH,
    /**
     * No check of the live order: the extension {@code intent} refused a request that lacks, in a verified hand-over, a
     * fact the receiving operation requires. 403 over HTTP in either mode.
     */
    INTENT_MISSING,
    /**
     * No check of the live order: the receiving application compared its request with the facts of the extension
     * {@code intent} and refused. The handler answers the request: 403 over HTTP in either mode.
     */
    INTENT_DENIED,
    /**
     * No check of the live order: in an unsafe session, the call reached an endpoint disabled there. 403.
     */
    UNSAFE_SESSION,
    /**
     * Check 0: every keyring, or every root, the verifier pins is past its {@code notAfter}, so the policy owner no
     * longer vouches for them. It is about the verifier's own configuration, not the request, so it names no one.
     * 403.
     */
    POLICY_EXPIRED,
    /**
     * Offline only: a recorded call that otherwise verifies, in a session whose recorded handshake is attested, but
     * whose last stamp's {@code ts} is past one of the session's limits.
     */
    OUTSIDE_SESSION
}
