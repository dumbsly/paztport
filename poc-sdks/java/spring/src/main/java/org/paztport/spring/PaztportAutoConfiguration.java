// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.util.Set;
import java.util.UUID;
import org.paztport.core.InMemoryNonceCache;
import org.paztport.core.KeyFiles;
import org.paztport.core.ProofBundle;
import org.paztport.core.StamperV3;
import org.paztport.core.VerifierConfigV3;
import org.paztport.core.VerifierV3;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;

/**
 * Wires the inbound filter and outbound interceptor from {@code paztport.*}.
 * Beans appear only when their inputs are configured, so each service holds only
 * what its role requires: callers get a stamper and interceptor, a service with
 * a keyring, a root and the policy pin gets a VerifierV3, and every service gets
 * the inbound filter, which verifies requests only where {@code paztport.verify=true}.
 * Wherever there is a VerifierV3, the interceptor also checks every response it
 * gets, and wherever there is a stamper, the filter attests the responses it sends.
 *
 * <p>The verifier is pinned: the keyring and the root must both verify under
 * {@code policy.pub}, or the context fails to start. Inside one mesh a request
 * tree is one call, so the session is empty and the run's age defaults to the
 * call's.
 */
@AutoConfiguration
@EnableConfigurationProperties(PaztportProperties.class)
public class PaztportAutoConfiguration {

    @Bean
    @ConditionalOnProperty("paztport.key-path")
    StamperV3 stamper(PaztportProperties props) {
        return new StamperV3(
                props.getServiceName(),
                instance(props),
                KeyFiles.loadPrivateKey(Path.of(props.getKeyPath())),
                props.isOrigin(),
                () -> UUID.randomUUID().toString(),
                System::currentTimeMillis);
    }

    @Bean
    @ConditionalOnProperty("paztport.proofs-path")
    ProofBundle proofBundle(PaztportProperties props) {
        return ConfigLoader.loadProofBundle(Path.of(props.getProofsPath()));
    }

    @Bean
    @ConditionalOnProperty("paztport.key-path")
    RestClientCustomizer paztportRestClientCustomizer(
            StamperV3 stamper, ObjectProvider<ProofBundle> bundle, ObjectProvider<VerifierV3> verifier,
            PaztportProperties props) {
        OutboundInterceptor interceptor = new OutboundInterceptor(
                stamper, bundle.getIfAvailable(), verifier.getIfAvailable(), props.getServiceName());
        return builder -> builder.requestInterceptor(interceptor);
    }

    @Bean
    @ConditionalOnProperty({"paztport.keyring-path", "paztport.root-path", "paztport.policy-key-path"})
    VerifierV3 verifier(PaztportProperties props) {
        long runMaxAgeMs = props.getRunMaxAgeMs() != null ? props.getRunMaxAgeMs() : props.getMaxAgeMs();
        VerifierConfigV3 cfg = VerifierConfigV3.pinned(
                ConfigLoader.loadKeyringFile(Path.of(props.getKeyringPath())),
                ConfigLoader.loadSignedRoot(Path.of(props.getRootPath())),
                ConfigLoader.loadPolicyPin(Path.of(props.getPolicyKeyPath())),
                Set.copyOf(props.getOrigins()),
                "",
                new InMemoryNonceCache(),
                System::currentTimeMillis,
                props.getMaxAgeMs(),
                runMaxAgeMs);
        return new VerifierV3(cfg);
    }

    @Bean
    @ConditionalOnProperty(name = "paztport.verify", havingValue = "true")
    ModeHolder modeHolder(PaztportProperties props) {
        return new ModeHolder(VerificationMode.fromProperty(props.getMode()));
    }

    @Bean
    @ConditionalOnProperty(name = "paztport.verify", havingValue = "true")
    EventPublisher eventPublisher(PaztportProperties props) {
        String responderUrl = props.getResponderUrl();
        if (responderUrl != null && !responderUrl.isBlank()) {
            String eventKeyPath = props.getEventKeyPath();
            if (eventKeyPath == null || eventKeyPath.isBlank()) {
                throw new IllegalStateException(
                        "paztport.responder-url is set but paztport.event-key-path is not");
            }
            return new ResponderEventPublisher(
                    responderUrl,
                    props.getServiceName(),
                    KeyFiles.loadPrivateKey(Path.of(eventKeyPath)),
                    System::currentTimeMillis);
        }
        return new LoggingEventPublisher();
    }

    @Bean
    @ConditionalOnProperty(name = "paztport.verify", havingValue = "true")
    AdminModeController adminModeController(ModeHolder modeHolder, PaztportProperties props) {
        return new AdminModeController(modeHolder, props.getAdminToken());
    }

    /**
     * A service told to verify but given no trust paths fails to start, rather
     * than serving unverified requests it was meant to check.
     */
    @Bean
    FilterRegistrationBean<InboundFilter> inboundFilterRegistration(
            PaztportProperties props,
            ObjectProvider<VerifierV3> verifier,
            ObjectProvider<ModeHolder> modeHolder,
            ObjectProvider<EventPublisher> publisher,
            ObjectProvider<ReceivedRequestListener> listener,
            ObjectProvider<StamperV3> stamper) {
        VerifierV3 requestVerifier = null;
        if (props.isVerify()) {
            requestVerifier = verifier.getIfAvailable();
            if (requestVerifier == null) {
                throw new IllegalStateException("paztport.verify is true but paztport.keyring-path, "
                        + "paztport.root-path and paztport.policy-key-path are not all set");
            }
        }
        InboundFilter filter = new InboundFilter(
                requestVerifier, props.getServiceName(), modeHolder.getIfAvailable(),
                publisher.getIfAvailable(), listener.getIfAvailable(), stamper.getIfAvailable());
        FilterRegistrationBean<InboundFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.addUrlPatterns("/*");
        return registration;
    }

    private static String instance(PaztportProperties props) {
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
