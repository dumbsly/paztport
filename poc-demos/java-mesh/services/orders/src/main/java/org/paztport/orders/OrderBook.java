// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import java.util.Map;
import org.springframework.stereotype.Component;

/** The shop's orders, seeded for the demo: who placed each, where to reach them, what they bought and its price. */
@Component
public class OrderBook {

    /** One order. The customer and email are private to that customer. */
    public record Order(String id, String customer, String email, String item, long amount) {
    }

    private final Map<String, Order> orders = Map.of(
            "123", new Order("123", "alice", "alice@shop.example", "widget", 100),
            "456", new Order("456", "mallory", "mallory@mail.example", "gadget", 40));

    /** The order with this id, or null when there is none. */
    public Order byId(String id) {
        return id == null ? null : orders.get(id);
    }
}
