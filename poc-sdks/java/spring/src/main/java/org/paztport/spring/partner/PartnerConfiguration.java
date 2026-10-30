// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.partner;

import java.io.UncheckedIOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
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
import org.paztport.core.crypto.Crypto;
import org.paztport.core.crypto.KeyFiles;
import org.paztport.core.encoding.Base64Url;
import org.paztport.core.influence.BoundaryInfluence;
import org.paztport.core.policy.KeyringFile;
import org.paztport.core.policy.ProofBundle;
import org.paztport.core.policy.SignedRoot;
import org.paztport.core.session.ReplyCert;
import org.paztport.core.stamp.StamperV3;
import org.paztport.core.verify.InMemoryNonceCache;
import org.paztport.core.verify.VerifierConfigV3;
import org.paztport.spring.PaztportAutoConfiguration;
import org.paztport.spring.PaztportProperties;
import org.paztport.spring.internal.Durations;
import org.paztport.spring.internal.OwnMaterial;
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
        Duration readTimeout = Durations.readTimeout(props);
        byte[] blindingKey = BoundaryInfluence.loadKey(Path.of(b.getBlindingKeyPath()),
                "paztport.boundary.blinding-key-path");
        SslBundles bundles = ssl.getIfAvailable();
        if (bundles == null) {
            throw new IllegalStateException(
                    "paztport.boundary.tls-bundle is set but no SSL bundles are configured (spring.ssl.bundle.*)");
        }
        SignedRoot ownRoot = SignedRoot.load(Path.of(props.getRootPath()));
        KeyringFile ownKeyring = KeyringFile.load(Path.of(props.getKeyringPath()));
        String ownPin = KeyFiles.loadPolicyPin(Path.of(props.getPolicyKeyPath()));
        OwnMaterial.require(ownKeyring, Path.of(props.getKeyringPath()), ownRoot, Path.of(props.getRootPath()),
                ownPin, System.currentTimeMillis());
        return new BoundaryClient(
                stamper.getObject(),
                bundle.getObject(),
                ownRoot,
                ownKeyring,
                ownPin,
                b.getPartner(),
                partnerUrl,
                KeyFiles.loadPolicyPin(Path.of(b.getPartnerPolicyKeyPath())),
                blindingKey,
                listener.getIfAvailable(),
                PooledTlsClient.of(bundles.getBundle(b.getTlsBundle()), readTimeout),
                b.getSessionIdleMs());
    }

    /**
     * The partner's session registry. Everything it needs is checked first, and the context fails naming what is
     * wrong: a partner that also verifies as a shop service does, no clients pinned, no origins allowed, or a session
     * cap or idle period that is not positive. Its replies are signed by its own entry service's key, never the
     * policy key, so it also refuses to start, in this order, unless: its keyring and root verify under its pin and
     * are in the new form and current ({@link OwnMaterial}, which names the property and the fix); the
     * keyring holds {@code paztport.service-name}; that entry is the key at {@code paztport.key-path}; the reply
     * certificate verifies under the pin, names that service and that key, and has not expired by the wall clock.
     * Each would otherwise sign replies no client could accept. A certificate that expires while the service runs
     * is not caught here: replies then fail at the client, which falls back to an unsafe session, so the
     * certificate must be reissued and the service restarted before it expires. Its own keyring and root are the
     * other case: once either expires the partner keeps running and opens only unsafe sessions
     * ({@link PartnerSessions}). The time all of this is judged by, at startup and in every handshake and call
     * after it (stamp freshness included), is the system clock, fixed when the bean is made: an ordinary application
     * bean cannot move it. No message carries key material.
     */
    @Bean
    @ConditionalOnProperty("paztport.partner.enabled")
    @ConditionalOnMissingBean(PartnerSessions.class)
    PartnerSessions paztportPartnerSessions(PaztportProperties props) {
        return partnerSessions(props, System::currentTimeMillis);
    }

    /**
     * The partner's session registry as {@link #paztportPartnerSessions} builds it, judged by {@code clock} (ms since
     * the epoch) at startup and from then on. Only this package can call it, or build a {@link PartnerSessions} to
     * define in place of the one above, since this method and the type's constructor are package-private: tests do,
     * to move time. An application can name the type but cannot build one without reaching into this package (a
     * class of its own in it, or a bean definition registered by reflection), which is no accident; the module
     * system would close even that, and this starter does not use it.
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
        KeyringFile keyring = KeyringFile.load(Path.of(props.getKeyringPath()));
        SignedRoot ownRoot = SignedRoot.load(Path.of(props.getRootPath()));
        OwnMaterial.require(keyring, Path.of(props.getKeyringPath()), ownRoot, Path.of(props.getRootPath()), pin,
                clock.getAsLong());
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
        if (clock.getAsLong() > cert.notAfter()) {
            throw new IllegalStateException("paztport.partner.reply-cert-path has expired");
        }
        Set<String> clientKeys = new LinkedHashSet<>();
        p.getClientPolicyKeyPaths().forEach(path -> clientKeys.add(KeyFiles.loadPolicyPin(Path.of(path))));
        long runMaxAgeMs = props.getRunMaxAgeMs() != null ? props.getRunMaxAgeMs() : props.getMaxAgeMs();
        return new PartnerSessions(
                ownRoot,
                keyring,
                pin,
                service,
                serviceKey,
                cert,
                clientKeys,
                Set.copyOf(p.getClientOrigins()),
                p.getUnsafeDisabled(),
                new InMemoryNonceCache(VerifierConfigV3.nonceTtlFor(props.getMaxAgeMs())),
                clock,
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
