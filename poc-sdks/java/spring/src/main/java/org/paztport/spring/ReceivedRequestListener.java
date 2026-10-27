// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

/**
 * Optional hook offered every request the inbound filter receives, with the raw
 * attestation headers and body, before verification runs. It lets an application
 * observe traffic (a demo harness retaining a request to replay, say) without the
 * SDK knowing what it is for. Implementations must not throw or block.
 *
 * <p>Each header is passed as received, or null when absent. {@code target} is the
 * raw path plus {@code ?} and the raw query when there is one: what the binding covers.
 */
@FunctionalInterface
public interface ReceivedRequestListener {

    void received(String chain, String proof, String influence, String method, String target, byte[] body);
}
