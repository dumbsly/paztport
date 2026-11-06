// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.verify;

/**
 * The nonce cache could not answer, so the replay check has no verdict: not "seen" and not "unseen". It carries the
 * cache's own exception as its cause and says nothing else, so no key reaches a log through it. {@link Verifier#verify}
 * throws it; a host decides what an unanswered request gets.
 */
public final class NonceCacheUnavailableException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public NonceCacheUnavailableException(Throwable cause) {
        super("the nonce cache could not answer", cause);
    }
}
