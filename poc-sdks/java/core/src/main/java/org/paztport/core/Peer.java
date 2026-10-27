// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import java.util.Objects;

/**
 * The sender a transport authenticated, for example from an mTLS certificate: its service name and its network
 * address. Only {@code svc} is compared with the chain; {@code inst} is the transport's address for the sender,
 * not a signed value, and is what a responder acts against when the result names the peer.
 */
public record Peer(String svc, String inst) {

    public Peer {
        Objects.requireNonNull(svc, "svc");
        Objects.requireNonNull(inst, "inst");
    }
}
