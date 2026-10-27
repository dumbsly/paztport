// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.gateway;

import java.util.Map;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The demo's customer login: fixed bearer tokens, from {@code demo.tokens}, each naming one customer. It stands in
 * for a real identity provider; the customer it gives is the shop's own record of who is asking, so services
 * downstream take it from the gateway rather than from anything a request says about itself.
 */
@ConfigurationProperties(prefix = "demo")
public class DemoTokens {

    private static final String BEARER = "Bearer ";

    private final Map<String, String> tokens;

    /** @param tokens each token to the customer it names */
    public DemoTokens(Map<String, String> tokens) {
        this.tokens = tokens == null ? Map.of() : Map.copyOf(tokens);
    }

    /** The customer an {@code Authorization} header names, or null for no header, another scheme or an unknown token. */
    public String customerFor(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER)) {
            return null;
        }
        String token = authorizationHeader.substring(BEARER.length());
        return token.isEmpty() ? null : tokens.get(token);
    }
}
