// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.search;

import java.util.List;
import java.util.Map;
import org.paztport.http.RequestContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Endpoint of the gateway->search route. Normal traffic always works. */
@RestController
public class SearchController {

    private final StolenChainStore stolenChains;

    public SearchController(StolenChainStore stolenChains) {
        this.stolenChains = stolenChains;
    }

    @GetMapping("/search")
    public Map<String, Object> search(@RequestParam(required = false, defaultValue = "") String q) {
        // Remember the chain we were legitimately handed, for the attack demo.
        stolenChains.record(RequestContext.inboundChain());
        return Map.of("query", q, "results", List.of());
    }
}
