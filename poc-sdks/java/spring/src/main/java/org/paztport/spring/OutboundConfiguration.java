// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import static org.paztport.spring.Durations.readTimeout;

import org.paztport.core.policy.ProofBundle;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.VerifierV3;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.restclient.RestClientCustomizer;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The beans for this service's own calls: the stamping customizer on the shared {@code RestClient.Builder}, and the
 * pooled client that presents {@code paztport.tls-bundle} with its customizer. The two customizers are defined here
 * in the order the builder applies them. {@link PaztportAutoConfiguration} imports it; it is not for an application
 * to use directly.
 */
@Configuration(proxyBeanMethods = false)
class OutboundConfiguration {

    @Bean
    @ConditionalOnProperty("paztport.key-path")
    RestClientCustomizer paztportRestClientCustomizer(
            StamperV3 stamper, ObjectProvider<ProofBundle> bundle, ObjectProvider<VerifierV3> verifier,
            PaztportProperties props) {
        OutboundInterceptor interceptor = new OutboundInterceptor(
                stamper, bundle.getIfAvailable(), verifier.getIfAvailable(), props.getServiceName());
        return builder -> builder.requestInterceptor(interceptor);
    }

    /**
     * The one client per application that presents {@code paztport.tls-bundle}, shared so that its connections
     * pool. The bundle is looked up when the context starts, so a name that does not exist, or an application
     * without SSL bundles, fails at startup rather than on the first call. The context closes it on shutdown.
     */
    @Bean
    @ConditionalOnProperty("paztport.tls-bundle")
    PooledTlsClient paztportTlsClient(ObjectProvider<SslBundles> ssl, PaztportProperties props) {
        SslBundles bundles = ssl.getIfAvailable();
        if (bundles == null) {
            throw new IllegalStateException(
                    "paztport.tls-bundle is set but no SSL bundles are configured (spring.ssl.bundle.*)");
        }
        return PooledTlsClient.of(bundles.getBundle(props.getTlsBundle()), readTimeout(props));
    }

    /** Kept apart from the stamping customizer, so a service that only verifies still presents its certificate. */
    @Bean
    @ConditionalOnProperty("paztport.tls-bundle")
    RestClientCustomizer paztportTlsRestClientCustomizer(PooledTlsClient tls) {
        return builder -> builder.requestFactory(tls.requestFactory());
    }
}
