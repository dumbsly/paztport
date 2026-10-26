// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.gateway;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * The gateway->search route. Calling this hands search a real, legitimately
 * stamped chain — which the attack demo then has search try to misuse.
 */
@RestController
public class FindController {

    private final RestClient http;
    private final String searchUrl;

    public FindController(RestClient http, @Value("${downstream.search-url}") String searchUrl) {
        this.http = http;
        this.searchUrl = searchUrl;
    }

    @GetMapping("/find")
    public Map<String, Object> find(@RequestParam(required = false, defaultValue = "") String q) {
        String downstream = http.get()
                .uri(searchUrl + "/search?q=" + q)
                .retrieve()
                .body(String.class);
        return Map.of("find", "OK", "downstream", downstream);
    }
}
