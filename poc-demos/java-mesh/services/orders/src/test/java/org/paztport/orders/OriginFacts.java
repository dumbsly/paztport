// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import org.paztport.core.crypto.Crypto;
import org.paztport.core.influence.Influence;
import org.paztport.core.intent.Intent;
import org.paztport.core.intent.IntentFacts;
import org.paztport.core.stamp.Block;
import org.paztport.core.stamp.Stamp;
import org.paztport.core.verify.ExtensionSettings;
import org.paztport.core.verify.HandOver;
import org.paztport.http.RequestContext;
import org.paztport.http.TestScopes;

/** A request to orders from the gateway, verified here, whose origin block states the facts given. */
final class OriginFacts {

    private static final ExtensionSettings ACTS_ON = ExtensionSettings.of(Set.of(Influence.NAME, Intent.NAME), null);

    private OriginFacts() {
    }

    /** The facts of alice's purchase of order 123, at the price the order book gives it. */
    static IntentFacts alicePays(long amount) {
        return IntentFacts.builder().put("customer", "alice").put("order", "123").put("amount", amount).build();
    }

    /**
     * Runs {@code handler} in a scope opened as the receiver opens one for a chain that verified here: the gateway's
     * one stamp, its block holding {@code facts} under {@code intent}.
     */
    static <T> T servedWith(IntentFacts facts, Supplier<T> handler) {
        List<Stamp> chain = List.of(Stamp.sign("gateway", "gw-1", "rid-1", 1L, "", "orders#purchase", "bind", "", "",
                Crypto.generateEd25519KeyPair().getPrivate()));
        Block origin = Block.of(Map.of(Intent.NAME, List.of(facts.toItem())), List.of());
        try (RequestContext.Scope scope = RequestContext.open()) {
            TestScopes.verified(chain, new HandOver(true, chain, List.of(origin), ACTS_ON));
            return handler.get();
        }
    }
}
