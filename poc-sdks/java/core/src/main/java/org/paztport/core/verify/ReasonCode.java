// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

/** The outcome of verification: {@link #OK} or exactly one reason for rejection. */
public enum ReasonCode {
    OK,
    CHAIN_MISSING,
    BAD_ORIGIN,
    BAD_SIGNATURE,
    BROKEN_LINK,
    EXPIRED,
    RID_MISMATCH,
    BINDING_MISMATCH,
    REPLAY,
    PATH_NOT_ALLOWED,
    SESSION_UNKNOWN,
    INFLUENCE_MISMATCH,
    PEER_MISMATCH,
    TIME_MISMATCH,
    PROMPT_MISMATCH,
    INFLUENCE_DENIED,
    UNSAFE_SESSION,
    /**
     * The policy key's keyring or root is past its {@code notAfter}, or carries none, so the policy owner no longer
     * vouches for it. It is about the verifier's own configuration, not the request, so it is not attributable.
     */
    POLICY_EXPIRED
}
