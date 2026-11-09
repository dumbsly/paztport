// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.partner;

import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongSupplier;
import org.paztport.core.crypto.KeyFiles;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.VerifierConfig;
import org.paztport.http.PartnerSessions;
import org.paztport.http.boundary.BoundaryClient;
import org.paztport.http.boundary.BoundaryListener;
import org.paztport.spring.PaztportAutoConfiguration;
import org.paztport.spring.PaztportProperties;
import org.paztport.spring.internal.Durations;
import org.paztport.spring.internal.StartupMaterial;
import org.paztport.spring.outbound.PooledTlsClient;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * The beans for calls between organisations: the egress's {@link BoundaryClient}, and the partner entry's session
 * registry, handshake endpoint and unsafe-session gate. The partner's filter is registered beside the inbound
 * filter, in {@link PaztportAutoConfiguration}, which imports this; it is not for an application to use directly.
 */
@Configuration(proxyBeanMethods = false)
public class PartnerConfiguration {

    /**
     * The egress's client to the partner. Everything it needs is checked first, and the context fails naming
     * whatever is missing, rather than an egress starting that cannot sign, prove its route or open a session. A
     * partner URL that is not {@code https} fails it too, as does an idle period that is not positive (the client's
     * builder refuses both, {@link BoundaryClient.Builder#build}, and they are worded here in terms of the
     * property), or a boundary key that is not 32 bytes. It builds its own TLS client from
     * {@code paztport.boundary.tls-bundle}, never the shared one, so the partner's CA is trusted only on calls to
     * the partner; the bundle is read here, so a certificate that is missing or unreadable fails the context at
     * startup. The egress owns that client, and is the only holder of it. A {@link BoundaryListener} bean, if there
     * is one, is told what each attested call sends. With several, the one marked {@code @Primary} is told and the
     * others are not; with several and none primary, the context fails rather than pick one. The context closes the
     * client on shutdown.
     */
    @Bean
    @ConditionalOnProperty("paztport.boundary.url")
    BoundaryClient paztportBoundaryClient(PaztportProperties props, ObjectProvider<Stamper> stamper,
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
        URI partnerUrl = URI.create(b.getUrl());
        Duration readTimeout = Durations.readTimeout(props);
        byte[] blindingKey = BoundaryInfluence.loadKey(Path.of(b.getBlindingKeyPath()),
                "paztport.boundary.blinding-key-path");
        SslBundles bundles = ssl.getIfAvailable();
        if (bundles == null) {
            throw new IllegalStateException(
                    "paztport.boundary.tls-bundle is set but no SSL bundles are configured (spring.ssl.bundle.*)");
        }
        Path rootFile = Path.of(props.getRootPath());
        Path keyringFile = Path.of(props.getKeyringPath());
        SignedRoot ownRoot = StartupMaterial.loadRoot(rootFile);
        KeyringFile ownKeyring = StartupMaterial.loadKeyring(keyringFile);
        String ownPin = KeyFiles.loadPolicyPin(Path.of(props.getPolicyKeyPath()));
        StartupMaterial.require(ownKeyring, keyringFile, ownRoot, rootFile, ownPin, System.currentTimeMillis());
        Stamper stamping = stamper.getObject();
        ProofBundle proofs = bundle.getObject();
        String partnerPin = KeyFiles.loadPolicyPin(Path.of(b.getPartnerPolicyKeyPath()));
        BoundaryListener told = listener.getIfAvailable();
        // Last, after every lookup that can throw, so that nothing before it leaves the client open.
        HttpClient http = PooledTlsClient.of(bundles.getBundle(b.getTlsBundle()), readTimeout).httpClient();
        try {
            return BoundaryClient.builder()
                    .stamper(stamping)
                    .bundle(proofs)
                    .ownRoot(ownRoot)
                    .ownKeyring(ownKeyring)
                    .ownPolicyKey(ownPin)
                    .partner(b.getPartner())
                    .partnerUrl(partnerUrl)
                    .pinnedPartnerKey(partnerPin)
                    .blindingKey(blindingKey)
                    .listener(told)
                    .http(http)
                    .readTimeout(readTimeout)
                    .sessionIdleMs(b.getSessionIdleMs())
                    .build();
        } catch (RuntimeException e) {
            http.shutdownNow();
            throw e instanceof BoundaryClient.InvalidSetting invalid ? inTermsOfTheProperty(invalid, b) : e;
        }
    }

    /**
     * Worded in terms of the property where one property holds it; the rest are refused above, by the property's
     * own reader, or are the client's own words, as they always were.
     */
    private static RuntimeException inTermsOfTheProperty(BoundaryClient.InvalidSetting e,
            PaztportProperties.Boundary b) {
        return switch (e.fault()) {
            case NOT_HTTPS -> new IllegalStateException("paztport.boundary.url must be an https URL: " + b.getUrl());
            case IDLE_PERIOD -> new IllegalStateException("paztport.boundary.session-idle-ms must be positive");
            default -> e;
        };
    }

    /**
     * The partner's session registry. Everything it needs is checked first, and the context fails naming what is
     * wrong: a partner that also verifies as one of this organisation's services does, no clients pinned, no
     * origins allowed, or a session cap or idle period that is not positive. Its replies are signed by its own
     * entry service's key, never the policy key, so it also refuses to start, in this order, unless: its keyring and
     * root verify under its pin and are current ({@link StartupMaterial}, which names the property and the fix); the
     * keyring holds {@code paztport.service-name}; that entry is the key at {@code paztport.key-path}; the reply
     * certificate verifies under the pin, names that service and that key, and has not expired by the wall clock.
     * The checks after the first are {@link PartnerSessions.Builder#build}'s, worded here in terms of the property
     * at fault. Each would otherwise sign replies no client could accept. A certificate that expires while the
     * service runs is not caught here: replies then fail at the client, which falls back to an unsafe session, so
     * the certificate must be reissued and the service restarted before it expires. Its own keyring and root are
     * the other case: once either expires the partner keeps running and opens only unsafe sessions
     * ({@link PartnerSessions}). The time all of this is judged by, at startup and in every handshake and call
     * after it (stamp freshness included), is the system clock, fixed when the bean is made: an application bean
     * that looks like a clock cannot move it. No message carries key material.
     */
    @Bean
    @ConditionalOnProperty("paztport.partner.enabled")
    @ConditionalOnMissingBean(PartnerSessions.class)
    PartnerSessions paztportPartnerSessions(PaztportProperties props) {
        return partnerSessions(props, System::currentTimeMillis);
    }

    /**
     * The partner's session registry as {@link #paztportPartnerSessions} builds it, judged by {@code clock} (ms since
     * the epoch) at startup and from then on. Package-private, for tests, which move time. An application that
     * defines a {@link PartnerSessions} bean of its own, with {@link PartnerSessions#builder}, has it used in place
     * of this one, judged by whatever clock it gave the builder: that is a choice it makes in code, as it would be
     * for any other bean it replaces, and never one a stray clock bean makes for it.
     */
    static PartnerSessions partnerSessions(PaztportProperties props, LongSupplier clock) {
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
        String pin = KeyFiles.loadPolicyPin(Path.of(props.getPolicyKeyPath()));
        Path keyringFile = Path.of(props.getKeyringPath());
        Path rootFile = Path.of(props.getRootPath());
        KeyringFile keyring = StartupMaterial.loadKeyring(keyringFile);
        SignedRoot ownRoot = StartupMaterial.loadRoot(rootFile);
        StartupMaterial.require(keyring, keyringFile, ownRoot, rootFile, pin, clock.getAsLong());
        PrivateKey serviceKey = KeyFiles.loadPrivateKey(Path.of(props.getKeyPath()));
        ReplyCert cert;
        try {
            cert = StartupMaterial.loadReplyCert(Path.of(p.getReplyCertPath()));
        } catch (UncheckedIOException e) {
            throw new IllegalStateException("paztport.partner.reply-cert-path could not be read", e);
        }
        Set<String> clientKeys = new LinkedHashSet<>();
        p.getClientPolicyKeyPaths().forEach(path -> clientKeys.add(KeyFiles.loadPolicyPin(Path.of(path))));
        long runMaxAgeMs = props.getRunMaxAgeMs() != null ? props.getRunMaxAgeMs() : props.getMaxAgeMs();
        try {
            return PartnerSessions.builder()
                    .ownRoot(ownRoot)
                    .ownKeyring(keyring)
                    .ownPolicyKey(pin)
                    .ownService(service)
                    .ownServiceKey(serviceKey)
                    .ownReplyCert(cert)
                    .pinnedClientKeys(clientKeys)
                    .clientOrigins(Set.copyOf(p.getClientOrigins()))
                    .unsafeDisabled(p.getUnsafeDisabled())
                    .nonces(new InMemoryNonceCache(VerifierConfig.nonceTtlFor(props.getMaxAgeMs())))
                    .clock(clock)
                    .callMaxAgeMs(props.getMaxAgeMs())
                    .runMaxAgeMs(runMaxAgeMs)
                    .maxSessionsPerPeer(p.getMaxSessionsPerPeer())
                    .sessionIdleMs(p.getSessionIdleMs())
                    .build();
        } catch (PartnerSessions.InvalidMaterial e) {
            throw new IllegalStateException(message(e.fault()));
        }
    }

    /** What is wrong, in terms of the {@code paztport.*} property that holds it. */
    private static String message(PartnerSessions.Fault fault) {
        return switch (fault) {
            // Not reached: StartupMaterial.require has refused it already, with the property and the fix.
            case OWN_MATERIAL -> "paztport.keyring-path or paztport.root-path is not current under "
                    + "paztport.policy-key-path";
            case NO_ENTRY_KEY -> "paztport.keyring-path has no key for paztport.service-name";
            case KEY_MISMATCH ->
                    "paztport.key-path does not match the key paztport.keyring-path holds for paztport.service-name";
            case CERT_UNVERIFIED -> "paztport.partner.reply-cert-path does not verify under paztport.policy-key-path";
            case CERT_WRONG_SERVICE -> "paztport.partner.reply-cert-path is not for paztport.service-name";
            case CERT_WRONG_KEY -> "paztport.partner.reply-cert-path is not for the key at paztport.key-path";
            case CERT_EXPIRED -> "paztport.partner.reply-cert-path has expired";
        };
    }

    @Bean
    @ConditionalOnProperty("paztport.partner.enabled")
    PartnerSessionController paztportPartnerSessionController(PartnerSessions sessions) {
        return new PartnerSessionController(sessions);
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
}
