// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.outbound;

import io.micrometer.observation.ObservationRegistry;
import java.time.Clock;
import java.time.Duration;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.Verifier;
import org.paztport.http.HttpCaller;
import org.paztport.spring.PaztportAutoConfiguration;
import org.paztport.spring.PaztportProperties;
import org.paztport.spring.internal.Durations;
import org.paztport.spring.operation.OperationConfiguration;
import org.paztport.spring.trust.ResponseVerifier;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.restclient.RestClientCustomizer;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The beans for this service's own calls: the stamping customizer on the shared {@code RestClient.Builder}, which
 * names each receiver by {@code paztport.receiver-names} or else by its host, names the operation a call invokes on a
 * receiver whose table it holds ({@link OperationConfiguration#receiverTables}) and checks each response with the
 * {@link ResponseVerifier}, and the pooled client that presents {@code paztport.tls-bundle} with its customizer. The
 * two customizers are defined here in the order the builder applies them. {@link PaztportAutoConfiguration} imports
 * it; it is not for an application to use directly.
 */
@Configuration(proxyBeanMethods = false)
public class OutboundConfiguration {

    @Bean
    @ConditionalOnProperty("paztport.key-path")
    RestClientCustomizer paztportRestClientCustomizer(
            Stamper stamper, ObjectProvider<ProofBundle> bundle, ObjectProvider<ResponseVerifier> responses,
            PaztportProperties props, ObjectProvider<ObservationRegistry> observations) {
        ResponseVerifier checks = responses.getIfAvailable();
        Verifier verifier = checks != null ? checks.verifier() : null;
        ProofBundle proofs = bundle.getIfAvailable();
        OutboundInterceptor interceptor = new OutboundInterceptor(HttpCaller.builder(props.getServiceName(), stamper)
                .bundle(proofs).verifier(verifier).receivers(props.getReceiverNames())
                .operations(OperationConfiguration.receiverTables(props, proofs, checks)).build(),
                observations.getIfAvailable(() -> ObservationRegistry.NOOP), unconnectedRetry(props));
        return builder -> builder.requestInterceptor(interceptor);
    }

    /**
     * The retry of calls that never connected, or null where {@code paztport.retry-unconnected} turns it off. It
     * refuses a connect timeout that is not under half of the origin's window, since a retry must fit in that
     * window after a first connect that timed out. This service's window stands in for its receivers', which it
     * cannot know; inside one mesh the services share these settings.
     */
    private static UnconnectedRetry unconnectedRetry(PaztportProperties props) {
        if (!props.isRetryUnconnected()) {
            return null;
        }
        Duration connect = Durations.connectTimeout(props);
        long window = Durations.runMaxAgeMs(props);
        if (connect.toMillis() >= window - connect.toMillis()) {
            throw new IllegalStateException("paztport.connect-timeout-ms (" + connect.toMillis()
                    + ") is not under half of the origin window, " + window + " ms (paztport.run-max-age-ms, else "
                    + "paztport.max-age-ms): a call that never connected is sent once more, and both attempts must "
                    + "fit that window. Shorten the connect timeout, or set paztport.retry-unconnected=false");
        }
        return new UnconnectedRetry(connect, window, Clock.systemUTC());
    }

    /**
     * The one client per application that presents {@code paztport.tls-bundle}, shared so that its connections
     * pool. The bundle is looked up when the context starts, so a name that does not exist, or an application
     * without SSL bundles, fails at startup rather than on the first call. The context closes it on shutdown.
     * {@code paztport.tls-bundle=false} leaves it out, as the condition reads {@code false} as unset, and with it
     * the customizer below and the events' TLS.
     */
    @Bean
    @ConditionalOnProperty("paztport.tls-bundle")
    PooledTlsClient paztportTlsClient(ObjectProvider<SslBundles> ssl, PaztportProperties props) {
        SslBundles bundles = ssl.getIfAvailable();
        if (bundles == null) {
            throw new IllegalStateException(
                    "paztport.tls-bundle is set but no SSL bundles are configured (spring.ssl.bundle.*)");
        }
        return PooledTlsClient.of(bundles.getBundle(props.getTlsBundle()), Durations.readTimeout(props),
                Durations.connectTimeout(props));
    }

    /** Kept apart from the stamping customizer, so a service that only verifies still presents its certificate. */
    @Bean
    @ConditionalOnProperty("paztport.tls-bundle")
    RestClientCustomizer paztportTlsRestClientCustomizer(PooledTlsClient tls) {
        return builder -> builder.requestFactory(tls.requestFactory());
    }
}
