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
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.web.client.RestClientCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.web.client.RestClient;

/**
 * Wires the inbound filter and outbound interceptor from {@code paztport.*}.
 * Beans appear only when their inputs are configured, so each service holds only
 * what its role requires: callers get a stamper and interceptor, a service with
 * a keyring, a root and the policy pin gets a VerifierV3, and every service gets
 * the inbound filter, which verifies requests only where {@code paztport.verify=true}.
 * Wherever there is a VerifierV3, the interceptor also checks every response it
 * gets. A non-origin service with both a stamper and a VerifierV3 attests the
 * responses it sends, but only to requests whose chain verified there, and not
 * while a service that verifies requests is in {@code off} mode; an origin never
 * attests.
 *
 * <p>The verifier is pinned: the keyring and the root must both verify under
 * {@code policy.pub}, or the context fails to start. Inside one mesh a request
 * tree is one call, so the session is empty and the run's age defaults to the
 * call's. Its replay cache forgets a key once it is older than the verifier
 * needs, at least twice the call window, so memory follows the traffic in that
 * window rather than every request and response ever checked.
 *
 * <p>Under mutual TLS, {@code paztport.tls-bundle} names the SSL bundle this
 * service presents: on the shared {@code RestClient.Builder}, beside the
 * stamping interceptor, and on the responder client, which is built apart from
 * the shared builder so that events are never stamped. Both draw on one
 * {@link PooledTlsClient}, so their connections are pooled and reused rather
 * than opened per call. A bundle that does not exist fails the context at
 * startup.
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
        return PooledTlsClient.of(bundles.getBundle(props.getTlsBundle()));
    }

    /** Kept apart from the stamping customizer, so a service that only verifies still presents its certificate. */
    @Bean
    @ConditionalOnProperty("paztport.tls-bundle")
    RestClientCustomizer paztportTlsRestClientCustomizer(PooledTlsClient tls) {
        return builder -> builder.requestFactory(tls.requestFactory());
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
                new InMemoryNonceCache(nonceTtlMs(props.getMaxAgeMs())),
                System::currentTimeMillis,
                props.getMaxAgeMs(),
                runMaxAgeMs);
        return new VerifierV3(cfg);
    }

    /** The verifier refuses a cache that forgets sooner than twice the call window, so this never goes below it. */
    static long nonceTtlMs(long maxAgeMs) {
        return Math.max(VerifierConfigV3.NONCE_TTL_MS, 2 * maxAgeMs);
    }

    @Bean
    @ConditionalOnProperty(name = "paztport.verify", havingValue = "true")
    ModeHolder modeHolder(PaztportProperties props) {
        return new ModeHolder(VerificationMode.fromProperty(props.getMode()));
    }

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
            // TLS only, never the shared builder's stamping interceptor.
            RestClient.Builder http = props.getTlsBundle() != null ? tls.getObject().builder() : RestClient.builder();
            return new ResponderEventPublisher(
                    http.build(),
                    responderUrl,
                    props.getServiceName(),
                    KeyFiles.loadPrivateKey(Path.of(eventKeyPath)),
                    System::currentTimeMillis);
        }
        return new LoggingEventPublisher();
    }

    /** Always present: the rule needs no keys, only this service's name for its trace line. */
    @Bean
    PublicWrites paztportPublicWrites(PaztportProperties props) {
        return new PublicWrites(props.getServiceName());
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
        VerifierV3 shared = verifier.getIfAvailable();
        if (props.isVerify() && shared == null) {
            throw new IllegalStateException("paztport.verify is true but paztport.keyring-path, "
                    + "paztport.root-path and paztport.policy-key-path are not all set");
        }
        // The verifier goes to every service that has one: where requests are not verified, it decides attestation.
        InboundFilter filter = new InboundFilter(
                shared, props.isVerify(), props.isOrigin(), props.getServiceName(), modeHolder.getIfAvailable(),
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
