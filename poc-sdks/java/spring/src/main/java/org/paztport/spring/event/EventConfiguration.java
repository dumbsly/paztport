// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.event;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Duration;
import org.paztport.core.crypto.KeyFiles;
import org.paztport.http.event.EventPublisher;
import org.paztport.http.event.LoggingEventPublisher;
import org.paztport.http.event.ResponderEventPublisher;
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
            PrivateKey eventKey = KeyFiles.loadPrivateKey(Path.of(eventKeyPath));
            // The bare JDK client, never the shared builder's stamping interceptor: the pooled one over the TLS
            // bundle when there is a TLS client (the bean, not the property, says so, so that
            // paztport.tls-bundle=false is off here as everywhere), else a plain one of the starter's own. It is
            // built last, after every lookup that can throw, so that a failed startup leaves none open: the
            // publisher's own checks, of a timeout already found positive, cannot fail after it.
            PooledTlsClient pooled = tls.getIfAvailable();
            HttpClient http = pooled != null ? pooled.httpClient() : HttpClient.newBuilder()
                    .version(HttpClient.Version.HTTP_1_1)
                    .connectTimeout(timeout)
                    .build();
            return new ResponderEventPublisher(http, timeout, responderUrl, props.getServiceName(), eventKey,
                    System::currentTimeMillis);
        }
        return new LoggingEventPublisher();
    }
}
