// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.event;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.function.Supplier;
import org.paztport.core.crypto.KeyFiles;
import org.paztport.spring.PaztportAutoConfiguration;
import org.paztport.spring.PaztportProperties;
import org.paztport.spring.internal.Durations;
import org.paztport.spring.outbound.PooledTlsClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The bean that reports attestation events: to the responder, signed, where there is one, otherwise to the log.
 * {@link PaztportAutoConfiguration} imports it; it is not for an application to use directly.
 */
@Configuration(proxyBeanMethods = false)
public class EventConfiguration {

    /**
     * Events go to the responder, if there is one, on the bare JDK client, each bounded by the event timeout
     * ({@link ResponderEventPublisher}); otherwise only to the log.
     */
    @Bean
    @ConditionalOnProperty(name = "paztport.verify", havingValue = "true")
    EventPublisher eventPublisher(PaztportProperties props, ObjectProvider<PooledTlsClient> tls) {
        String responderUrl = props.getResponderUrl();
        if (responderUrl != null && !responderUrl.isBlank()) {
            String eventKeyPath = props.getEventKeyPath();
            if (eventKeyPath == null || eventKeyPath.isBlank()) {
                throw new IllegalStateException(
                        "paztport.responder-url is set but paztport.event-key-path is not");
            }
            Duration timeout = Durations.positiveMs(props.getEventTimeoutMs(), "paztport.event-timeout-ms");
            // The bare JDK client, never the shared builder's stamping interceptor: the pooled one over the TLS
            // bundle, read on the first event, else a plain one of the starter's own.
            Supplier<HttpClient> http;
            if (props.getTlsBundle() != null) {
                PooledTlsClient pooled = tls.getObject();
                http = pooled::httpClient;
            } else {
                HttpClient plain = HttpClient.newBuilder()
                        .version(HttpClient.Version.HTTP_1_1)
                        .connectTimeout(timeout)
                        .build();
                http = () -> plain;
            }
            return new ResponderEventPublisher(
                    http,
                    timeout,
                    responderUrl,
                    props.getServiceName(),
                    KeyFiles.loadPrivateKey(Path.of(eventKeyPath)),
                    System::currentTimeMillis);
        }
        return new LoggingEventPublisher();
    }
}
