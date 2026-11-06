// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

/**
 * What names one delivery of a request to this service, for the application's own idempotency handling: the chain's
 * {@code rid}, the last signer's {@code svc}, and the last stamp's {@code bind}. It exists only for a request whose
 * chain passed the live order at this hop; a refused request, an audit failure, an origin, a hop that is off and a
 * partner call have none.
 *
 * <p>The key ({@code rid}, {@code svc}) names the delivery, and no one but that signer can send it. The same key and
 * {@code bind} is the same request sent again by that signer. The same key with another {@code bind} is a different
 * request under a reused key, to refuse. A user's second click or a client's own resend is a new {@code rid}, and
 * needs the application's own idempotency key.
 *
 * @param rid the request tree's id, from the first stamp
 * @param svc the last signer's service name
 * @param bind the last stamp's binding of the request's method, target and body
 */
public record Delivery(String rid, String svc, String bind) {
}
