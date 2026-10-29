// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.session;

/**
 * The client's verdict on a session reply, in the order the checks run: the first failure is the outcome.
 * Everything but {@link #ATTESTED} and {@link #UNSAFE} means the server may have opened an attested session the
 * client cannot use, so the client replaces it with a request that carries no root.
 */
public enum ReplyCheck {
    /** The reply is genuine and the server attested the session. */
    ATTESTED,
    /** The reply is genuine and the server opened an unsafe session. */
    UNSAFE,
    /** The reply does not have the shape of a session reply. */
    MALFORMED_REPLY,
    /** The reply names a policy key other than the one the client pinned. */
    PIN_MISMATCH,
    /** The signature, a root, the session id or the attested-needs-roots rule failed. */
    BAD_SIGNATURE
}
