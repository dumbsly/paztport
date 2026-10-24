// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.gateway;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/** Entry point. Originates a chain and calls orders; the interceptor stamps the outbound call. */
@RestController
public class CheckoutController {

    private final RestClient http;
    private final String ordersUrl;

    public CheckoutController(RestClient http, @Value("${downstream.orders-url}") String ordersUrl) {
        this.http = http;
        this.ordersUrl = ordersUrl;
    }

    @PostMapping("/checkout")
    public Map<String, Object> checkout(@RequestBody(required = false) String ignored) {
        String downstream = http.post()
                .uri(ordersUrl + "/orders")
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"item\":\"widget\"}")
                .retrieve()
                .body(String.class);
        return Map.of("checkout", "OK", "downstream", downstream);
    }
}
