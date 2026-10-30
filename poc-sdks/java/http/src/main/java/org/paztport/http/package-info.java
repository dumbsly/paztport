// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * Paztport over HTTP, with no web framework, in two layers.
 *
 * <p>The protocol is a set of functions over values: the header codecs and response check ({@code HttpV3}), the
 * request binding, the receivers and the caller. {@code HttpReceiver.accept} decides one request for a service and
 * {@code PartnerReceiver.accept} one call for a partner, from an {@code InboundRequest} and the peer the transport
 * authenticated ({@code PeerCert}); {@code Accepted.attest} attests a complete answer; {@code HttpSessions.serve}
 * answers a session handshake from the partner's registry ({@code PartnerSessions}); {@code UnsafeOperations} says
 * what an unsafe session may not do. {@code HttpCaller.stamp} stamps one of the service's own calls, naming the
 * receiver by the policy name its host maps to, and {@code HttpCaller.check} says what its response adds to the
 * request's influence. None of them keeps per-request state, so another language mirrors these.
 * {@code BoundaryClient} is the egress to a partner, over a JDK {@code HttpClient}: it sends nothing unless the
 * binding below holds a chain that verified here, which it only reads.
 *
 * <p>The blocking Java binding carries their results for one request on its thread: {@code RequestContext}, whose
 * {@code accept} a framework's adapter runs each request's receiver through, and which the handler, the caller's
 * blocking {@code stamp} and {@code record}, and {@code PublicWrites} read. It opens the request's scope before the
 * receiver runs, and sets its verified chain only from the result of the receiver it ran, so the receivers sit in
 * this package beside it. A reactive framework, or another language, would bind the same results its own way.
 */
package org.paztport.http;
