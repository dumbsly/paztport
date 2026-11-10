// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import java.util.Map;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * The verifier endpoint. By the time a request reaches this handler the inbound
 * filter has already verified the chain; a bad chain never gets here.
 */
@RestController
public class PaymentController {

    @PostMapping("/pay")
    public Map<String, String> pay(@RequestBody(required = false) String ignored) {
        return Map.of("status", "PAID");
    }

    /**
     * Holds one item. The operation is keyed by the item in the path, so a request tree holds each item at most once:
     * a second call for the same item is refused as a replay before it gets here.
     */
    @PostMapping("/holds/{item}")
    public Map<String, String> hold(@PathVariable String item) {
        return Map.of("hold", item, "status", "HELD");
    }
}
