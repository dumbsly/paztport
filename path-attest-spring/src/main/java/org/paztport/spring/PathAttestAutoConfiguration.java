// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.util.Set;
import java.util.UUID;
import org.paztport.core.InMemoryNonceCache;
import org.paztport.core.ProofBundle;
import org.paztport.core.Verifier;
import org.paztport.core.VerifierConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;

/**
 * Wires the inbound filter and outbound interceptor from {@code path-attest.*}.
 * Beans appear only when their inputs are configured, so each service holds only
 * what its role requires: callers get a stamper and interceptor, verifiers get a
 * Verifier, and every service gets the inbound filter.
 */
@AutoConfiguration
@EnableConfigurationProperties(PathAttestProperties.class)
public class PathAttestAutoConfiguration {

    @Bean
    @ConditionalOnProperty("path-attest.key-path")
    OutboundStamper outboundStamper(PathAttestProperties props) {
        return new OutboundStamper(
                props.getServiceName(),
                instance(props),
                ConfigLoader.loadPrivateKey(Path.of(props.getKeyPath())),
                props.isOrigin(),
                () -> UUID.randomUUID().toString(),
                System::currentTimeMillis);
    }

    @Bean
    @ConditionalOnProperty("path-attest.proofs-path")
    ProofBundle proofBundle(PathAttestProperties props) {
        return ConfigLoader.loadProofBundle(Path.of(props.getProofsPath()));
    }

    @Bean
    @ConditionalOnProperty("path-attest.key-path")
    RestClientCustomizer pathAttestRestClientCustomizer(
            OutboundStamper stamper, org.springframework.beans.factory.ObjectProvider<ProofBundle> bundle) {
        OutboundInterceptor interceptor = new OutboundInterceptor(stamper, bundle.getIfAvailable());
        return builder -> builder.requestInterceptor(interceptor);
    }

    @Bean
    @ConditionalOnProperty(name = "path-attest.verify", havingValue = "true")
    Verifier verifier(PathAttestProperties props) {
        VerifierConfig cfg = VerifierConfig.pinned(
                ConfigLoader.loadKeyring(Path.of(props.getKeyringPath())),
                ConfigLoader.loadSignedRoot(Path.of(props.getRootPath())),
                ConfigLoader.loadPolicyKey(Path.of(props.getKeyringPath())),
                Set.copyOf(props.getOrigins()),
                props.getMaxAgeMs(),
                props.getServiceName(),
                new InMemoryNonceCache(),
                System::currentTimeMillis);
        return new Verifier(cfg);
    }

    @Bean
    @ConditionalOnProperty(name = "path-attest.verify", havingValue = "true")
    ModeHolder modeHolder(PathAttestProperties props) {
        return new ModeHolder(VerificationMode.fromProperty(props.getMode()));
    }

    @Bean
    @ConditionalOnProperty(name = "path-attest.verify", havingValue = "true")
    EventPublisher eventPublisher(PathAttestProperties props) {
        String responderUrl = props.getResponderUrl();
        if (responderUrl != null && !responderUrl.isBlank()) {
            return new ResponderEventPublisher(responderUrl);
        }
        return new LoggingEventPublisher();
    }

    @Bean
    @ConditionalOnProperty(name = "path-attest.verify", havingValue = "true")
    AdminModeController adminModeController(ModeHolder modeHolder) {
        return new AdminModeController(modeHolder);
    }

    @Bean
    @ConditionalOnProperty(name = "path-attest.capture", havingValue = "true")
    CaptureStore captureStore() {
        return new CaptureStore();
    }

    @Bean
    @ConditionalOnProperty(name = "path-attest.capture", havingValue = "true")
    DebugCaptureController debugCaptureController(CaptureStore store) {
        return new DebugCaptureController(store);
    }

    @Bean
    FilterRegistrationBean<InboundFilter> inboundFilterRegistration(
            org.springframework.beans.factory.ObjectProvider<Verifier> verifier,
            org.springframework.beans.factory.ObjectProvider<ModeHolder> modeHolder,
            org.springframework.beans.factory.ObjectProvider<EventPublisher> publisher,
            org.springframework.beans.factory.ObjectProvider<CaptureStore> captureStore) {
        InboundFilter filter = new InboundFilter(
                verifier.getIfAvailable(), modeHolder.getIfAvailable(),
                publisher.getIfAvailable(), captureStore.getIfAvailable());
        FilterRegistrationBean<InboundFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.addUrlPatterns("/*");
        return registration;
    }

    private static String instance(PathAttestProperties props) {
        if (props.getInstance() != null && !props.getInstance().isBlank()) {
            return props.getInstance();
        }
        String host = System.getenv("HOSTNAME");
        if (host != null && !host.isBlank()) {
            return host;
        }
        try {
            return InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException e) {
            return props.getServiceName();
        }
    }
}
