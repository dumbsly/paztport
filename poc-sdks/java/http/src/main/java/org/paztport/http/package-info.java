// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Paztport over HTTP, with no web framework, in two layers.
 *
 * <p>The protocol is a set of functions over values: the header codecs and response check ({@code HttpV3}), the
 * request binding, and the receivers. {@code HttpReceiver.accept} decides one request for a service and
 * {@code PartnerReceiver.accept} one call for a partner, from an {@code InboundRequest} and the peer the transport
 * authenticated ({@code PeerCert}); {@code Accepted.attest} attests a complete answer; {@code HttpSessions.serve}
 * answers a session handshake from the partner's registry ({@code PartnerSessions}); {@code UnsafeOperations} says
 * what an unsafe session may not do. None of them keeps per-request state, so another language mirrors these.
 *
 * <p>The blocking Java binding carries their results for one request on its thread: {@code RequestContext}, which a
 * framework's adapter enters per request and the handler, the caller and {@code PublicWrites} read. Its verified
 * chain is set only from a receiver's result, which only a receiver can make, so the receivers sit in this package
 * beside it. A reactive framework, or another language, would bind the same results its own way.
 */
package org.paztport.http;
