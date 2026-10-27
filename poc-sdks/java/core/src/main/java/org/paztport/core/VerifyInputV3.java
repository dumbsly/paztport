// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * What a live verifier is handed for one chain. Every field comes from the receiver's own transport or
 * configuration, never trusted from the request beyond the values being checked: {@code stamps}, {@code
 * influence} and {@code proof} are the received JSON as it arrived, so a wrong type is a rejection rather than a
 * parse error at the caller.
 *
 * <p>{@code influence} null means none received ({@code []}); {@code proof} null means no proof received;
 * {@code peer} null means no authenticated peer. {@code receiver} is what the last stamp's {@code rcv} must
 * name, and {@code receiverInRoute} says whether the route ends there: true for a call, false for a response.
 */
public record VerifyInputV3(
        JsonNode stamps,
        String expectedBind,
        JsonNode influence,
        JsonNode proof,
        String receiver,
        boolean receiverInRoute,
        String nonceKey,
        Peer peer) {
}
