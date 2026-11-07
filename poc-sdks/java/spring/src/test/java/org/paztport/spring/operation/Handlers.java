// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.operation;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

/** Orders' handlers, each answering its own name, so a test can tell which one ran. */
@RestController
class Handlers {

    @GetMapping("/orders/{id}")
    String getOrder(@PathVariable String id) {
        return "getOrder";
    }

    @GetMapping("/orders/search")
    String search() {
        return "search";
    }

    @PostMapping("/orders")
    String createOrder() {
        return "createOrder";
    }

    @GetMapping("/items/{id:\\d+}")
    String getItem(@PathVariable String id) {
        return "getItem";
    }

    /** Mapped, and in no table: reachable only by a route that names no operation. */
    @GetMapping("/debug")
    String debug() {
        return "debug";
    }
}
