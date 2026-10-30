// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

/**
 * The starter's request path and its entry points. The request path is the two servlet filters, {@code InboundFilter}
 * for a service and {@code PartnerFilter} for a partner, with {@code CachedBodyHttpServletRequest}, which lets them
 * hash a body and still pass it on. They adapt {@code paztport-http}'s receivers, which decide each request, and
 * enter each result into {@code RequestContext}, the request-scoped carrier of the chain and the influence that the
 * handler, the outbound calls and {@code PublicWrites} then read. {@code ReceivedRequestListener} is the hook that
 * offers each request to an application before verification. The entry points are {@code PaztportAutoConfiguration},
 * which defines the filters and the public-writes rule, and {@code PaztportProperties}, the {@code paztport.*}
 * settings it binds. The sub-packages hold the rest.
 *
 * <p>Nothing here can mark a chain verified: only {@code RequestContext.accept} does, from the receiver it runs.
 */
package org.paztport.spring;
