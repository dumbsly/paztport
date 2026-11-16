// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http.boundary;

/**
 * Thrown by {@link BoundaryClient#post} when the session with the partner does not meet the egress's requirement
 * (spec sessions.md, A client that requires extensions): the reply did not list a required extension, or the
 * session is unsafe, and the egress's configuration does not let it go on without them. The call was not sent; at
 * most the handshake that opened the session was. It must not be retried against this session, which gives the
 * same answer to every call until it ends at the egress's idle period and the partner is asked again.
 *
 * <p>It is an {@link IllegalStateException}, as the egress's other refusals to send are, so code that already
 * catches those is unchanged; code that must tell a withheld call apart, such as an interceptor that decides whether
 * a call may be retried, catches this type.
 */
public final class RequirementUnmetException extends IllegalStateException {

    private static final long serialVersionUID = 1L;

    /** Only the egress throws it, with its one message. */
    RequirementUnmetException() {
        super(BoundaryClient.REQUIREMENT_UNMET);
    }
}
