// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.core.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;

class RoutesTest {

    @Test
    void joinsOneTwoAndThreeHopRoutesWithSlashes() {
        assertEquals("gateway", Routes.join(List.of("gateway")));
        assertEquals("gateway/orders", Routes.join(List.of("gateway", "orders")));
        assertEquals("gateway/orders/payment", Routes.join(List.of("gateway", "orders", "payment")));
    }
}
