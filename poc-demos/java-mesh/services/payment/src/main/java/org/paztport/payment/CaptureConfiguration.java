// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.payment;

import org.paztport.spring.ReceivedRequestListener;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the replay harness for the demo's attacker scenarios. The SDK filter
 * offers every received request to the listener before verifying it, so the
 * store holds a request that was still valid when it arrived. Enabled only when
 * {@code paztport.capture=true}; the {@link DebugCaptureController} that serves
 * the store is conditional on the same property.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "paztport.capture", havingValue = "true")
class CaptureConfiguration {

    @Bean
    CaptureStore captureStore() {
        return new CaptureStore();
    }

    @Bean
    ReceivedRequestListener captureListener(CaptureStore store) {
        return (chain, proof, method, path, body) ->
                store.record(new CapturedRequest(chain, proof, method, path, body));
    }
}
