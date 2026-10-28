// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.paztport.core.Base64Url;
import org.paztport.core.Crypto;
import org.paztport.core.InMemoryNonceCache;
import org.paztport.core.KeyFiles;
import org.paztport.core.KeyringFile;
import org.paztport.core.ProofBundle;
import org.paztport.core.ReplyCert;
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
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

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
 *
 * <p>Setting {@code paztport.boundary.url} makes this service the egress to a
 * partner organisation, with a {@link BoundaryClient} that presents its own
 * bundle, {@code paztport.boundary.tls-bundle}. Setting {@code paztport.partner.enabled} makes this service the
 * partner's entry, which answers other organisations' session handshakes and verifies their calls with
 * {@link PartnerFilter} in place of the inbound filter, behind {@link PartnerGate}.
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

    /**
     * The egress's client to the partner. Everything it needs is checked first, and the context fails naming
     * whatever is missing, rather than an egress starting that cannot sign, prove its route or open a session. A
     * partner URL that is not {@code https} fails it too (the client itself accepts one, for tests' stubs), as does
     * an idle period that is not positive, or a boundary key that is not 32 bytes. It builds its own TLS client from
     * {@code paztport.boundary.tls-bundle}, never the shared one, so the partner's CA is trusted only on calls to
     * the partner. A {@link BoundaryListener} bean, if there is one, is told what each attested call sends. With
     * several, the one marked {@code @Primary} is told and the others are not; with several and none primary, the
     * context fails rather than pick one. The context closes the client on shutdown.
     */
    @Bean
    @ConditionalOnProperty("paztport.boundary.url")
    BoundaryClient paztportBoundaryClient(PaztportProperties props, ObjectProvider<StamperV3> stamper,
            ObjectProvider<ProofBundle> bundle, ObjectProvider<SslBundles> ssl,
            ObjectProvider<BoundaryListener> listener) {
        PaztportProperties.Boundary b = props.getBoundary();
        Map<String, String> needed = new LinkedHashMap<>();
        needed.put("paztport.key-path", props.getKeyPath());
        needed.put("paztport.proofs-path", props.getProofsPath());
        needed.put("paztport.keyring-path", props.getKeyringPath());
        needed.put("paztport.root-path", props.getRootPath());
        needed.put("paztport.policy-key-path", props.getPolicyKeyPath());
        needed.put("paztport.boundary.partner", b.getPartner());
        needed.put("paztport.boundary.url", b.getUrl());
        needed.put("paztport.boundary.tls-bundle", b.getTlsBundle());
        needed.put("paztport.boundary.partner-policy-key-path", b.getPartnerPolicyKeyPath());
        needed.put("paztport.boundary.blinding-key-path", b.getBlindingKeyPath());
        List<String> missing = new ArrayList<>();
        needed.forEach((name, value) -> {
            if (value == null || value.isBlank()) {
                missing.add(name);
            }
        });
        if (!missing.isEmpty()) {
            throw new IllegalStateException("paztport.boundary.url is set but these are not: "
                    + String.join(", ", missing));
        }
        // The calls carry the boundary stamp and the influence's owners, which must not cross in the clear.
        URI partnerUrl = URI.create(b.getUrl());
        if (!"https".equalsIgnoreCase(partnerUrl.getScheme())) {
            throw new IllegalStateException("paztport.boundary.url must be an https URL: " + b.getUrl());
        }
        if (b.getSessionIdleMs() <= 0) {
            throw new IllegalStateException("paztport.boundary.session-idle-ms must be positive");
        }
        byte[] blindingKey = ConfigLoader.loadBoundaryKey(Path.of(b.getBlindingKeyPath()),
                "paztport.boundary.blinding-key-path");
        SslBundles bundles = ssl.getIfAvailable();
        if (bundles == null) {
            throw new IllegalStateException(
                    "paztport.boundary.tls-bundle is set but no SSL bundles are configured (spring.ssl.bundle.*)");
        }
        return new BoundaryClient(
                stamper.getObject(),
                bundle.getObject(),
                ConfigLoader.loadSignedRoot(Path.of(props.getRootPath())),
                ConfigLoader.loadKeyringFile(Path.of(props.getKeyringPath())),
                ConfigLoader.loadPolicyPin(Path.of(props.getPolicyKeyPath())),
                b.getPartner(),
                partnerUrl,
                ConfigLoader.loadPolicyPin(Path.of(b.getPartnerPolicyKeyPath())),
                blindingKey,
                listener.getIfAvailable(),
                PooledTlsClient.of(bundles.getBundle(b.getTlsBundle())),
                b.getSessionIdleMs());
    }

    /**
     * The partner's session registry. Everything it needs is checked first, and the context fails naming what is
     * wrong: a partner that also verifies as a shop service does, no clients pinned, no origins allowed, or a session
     * cap or idle period that is not positive. Its replies are signed by its own entry service's key, never the
     * policy key, so it also refuses to start, in this order, unless: its keyring verifies under its pin; the
     * keyring holds {@code paztport.service-name}; that entry is the key at {@code paztport.key-path}; the reply
     * certificate verifies under the pin, names that service and that key, and has not expired by the wall clock.
     * Each would otherwise sign replies no client could accept. A certificate that expires while the service runs
     * is not caught here: replies then fail at the client, which falls back to an unsafe session, so the
     * certificate must be reissued and the service restarted before it expires. No message carries key material.
     */
    @Bean
    @ConditionalOnProperty("paztport.partner.enabled")
    PartnerSessions paztportPartnerSessions(PaztportProperties props) {
        PaztportProperties.Partner p = props.getPartner();
        if (props.isVerify()) {
            throw new IllegalStateException("paztport.partner.enabled cannot be combined with paztport.verify=true");
        }
        Map<String, String> needed = new LinkedHashMap<>();
        needed.put("paztport.service-name", props.getServiceName());
        needed.put("paztport.keyring-path", props.getKeyringPath());
        needed.put("paztport.root-path", props.getRootPath());
        needed.put("paztport.policy-key-path", props.getPolicyKeyPath());
        needed.put("paztport.key-path", props.getKeyPath());
        needed.put("paztport.partner.reply-cert-path", p.getReplyCertPath());
        List<String> missing = new ArrayList<>();
        needed.forEach((name, value) -> {
            if (value == null || value.isBlank()) {
                missing.add(name);
            }
        });
        if (p.getClientPolicyKeyPaths().isEmpty()) {
            missing.add("paztport.partner.client-policy-key-paths");
        }
        if (p.getClientOrigins().isEmpty()) {
            missing.add("paztport.partner.client-origins");
        }
        if (!missing.isEmpty()) {
            throw new IllegalStateException("paztport.partner.enabled is set but these are not: "
                    + String.join(", ", missing));
        }
        if (p.getMaxSessionsPerPeer() < 1) {
            throw new IllegalStateException("paztport.partner.max-sessions-per-peer must be at least 1");
        }
        if (p.getSessionIdleMs() <= 0) {
            throw new IllegalStateException("paztport.partner.session-idle-ms must be positive");
        }
        String service = props.getServiceName();
        String pin = ConfigLoader.loadPolicyPin(Path.of(props.getPolicyKeyPath()));
        KeyringFile keyring = ConfigLoader.loadKeyringFile(Path.of(props.getKeyringPath()));
        if (!keyring.verifies(pin)) {
            throw new IllegalStateException("paztport.keyring-path does not verify under paztport.policy-key-path");
        }
        String entryKey = keyring.services().get(service);
        if (entryKey == null) {
            throw new IllegalStateException("paztport.keyring-path has no key for paztport.service-name");
        }
        PrivateKey serviceKey = KeyFiles.loadPrivateKey(Path.of(props.getKeyPath()));
        if (!belongsTo(serviceKey, entryKey)) {
            throw new IllegalStateException(
                    "paztport.key-path does not match the key paztport.keyring-path holds for paztport.service-name");
        }
        ReplyCert cert;
        try {
            cert = ReplyCert.load(Path.of(p.getReplyCertPath()));
        } catch (UncheckedIOException e) {
            throw new IllegalStateException("paztport.partner.reply-cert-path could not be read", e);
        } catch (IllegalArgumentException e) {
            // Without the parser's cause, which quotes the file: a key file named here by mistake must not be logged.
            throw new IllegalStateException("paztport.partner.reply-cert-path is not a reply certificate");
        }
        if (!cert.verifies(pin)) {
            throw new IllegalStateException(
                    "paztport.partner.reply-cert-path does not verify under paztport.policy-key-path");
        }
        if (!cert.svc().equals(service)) {
            throw new IllegalStateException("paztport.partner.reply-cert-path is not for paztport.service-name");
        }
        if (!cert.key().equals(entryKey)) {
            throw new IllegalStateException("paztport.partner.reply-cert-path is not for the key at paztport.key-path");
        }
        if (System.currentTimeMillis() > cert.notAfter()) {
            throw new IllegalStateException("paztport.partner.reply-cert-path has expired");
        }
        Set<String> clientKeys = new LinkedHashSet<>();
        p.getClientPolicyKeyPaths().forEach(path -> clientKeys.add(ConfigLoader.loadPolicyPin(Path.of(path))));
        long runMaxAgeMs = props.getRunMaxAgeMs() != null ? props.getRunMaxAgeMs() : props.getMaxAgeMs();
        return new PartnerSessions(
                ConfigLoader.loadSignedRoot(Path.of(props.getRootPath())),
                keyring,
                pin,
                service,
                serviceKey,
                cert,
                clientKeys,
                Set.copyOf(p.getClientOrigins()),
                p.getUnsafeDisabled(),
                new InMemoryNonceCache(nonceTtlMs(props.getMaxAgeMs())),
                System::currentTimeMillis,
                props.getMaxAgeMs(),
                runMaxAgeMs,
                p.getMaxSessionsPerPeer(),
                p.getSessionIdleMs());
    }

    /** Whether {@code key} is the private half of {@code publicKey}, by signing a probe; never throws. */
    private static boolean belongsTo(PrivateKey key, String publicKey) {
        byte[] probe = "paztport-partner-probe".getBytes(StandardCharsets.UTF_8);
        try {
            return Crypto.verify(Crypto.decodePublicKey(Base64Url.decode(publicKey)), probe, Crypto.sign(key, probe));
        } catch (RuntimeException e) {
            return false;
        }
    }

    @Bean
    @ConditionalOnProperty("paztport.partner.enabled")
    PartnerSessionController paztportPartnerSessionController(PartnerSessions sessions) {
        return new PartnerSessionController(sessions);
    }

    /**
     * The partner's filter, where the shop's would otherwise be: another organisation's calls verify in their
     * session, against what that session's handshake pinned, never against this organisation's own trust.
     */
    @Bean
    @ConditionalOnProperty("paztport.partner.enabled")
    FilterRegistrationBean<PartnerFilter> partnerFilterRegistration(
            PartnerSessions sessions, PaztportProperties props) {
        FilterRegistrationBean<PartnerFilter> registration =
                new FilterRegistrationBean<>(new PartnerFilter(sessions, props.getServiceName()));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.addUrlPatterns("/*");
        return registration;
    }

    /** The unsafe-session gate, as an interceptor so that it sees the handler Spring dispatched to. */
    @Bean
    @ConditionalOnProperty("paztport.partner.enabled")
    WebMvcConfigurer paztportPartnerGate(PartnerSessions sessions, PaztportProperties props) {
        PartnerGate gate = new PartnerGate(sessions, props.getServiceName());
        return new WebMvcConfigurer() {
            @Override
            public void addInterceptors(InterceptorRegistry registry) {
                registry.addInterceptor(gate);
            }
        };
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
     * than serving unverified requests it was meant to check. A partner's entry
     * has {@link PartnerFilter} instead.
     */
    @Bean
    @ConditionalOnProperty(name = "paztport.partner.enabled", havingValue = "false", matchIfMissing = true)
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
