// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.orders;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/** Appends its stamp (via the interceptor) and calls payment. */
@RestController
public class OrdersController {

    private final RestClient http;
    private final String paymentUrl;

    public OrdersController(RestClient http, @Value("${downstream.payment-url}") String paymentUrl) {
        this.http = http;
        this.paymentUrl = paymentUrl;
    }

    @PostMapping("/orders")
    public Map<String, Object> order(@RequestBody(required = false) String ignored) {
        String payment = http.post()
                .uri(paymentUrl + "/pay")
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"amount\":100}")
                .retrieve()
                .body(String.class);
        return Map.of("order", "OK", "payment", payment);
    }
}
