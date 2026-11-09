// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring;

import io.micrometer.observation.ObservationRegistry;
import org.paztport.core.stamp.Stamper;
import org.paztport.core.verify.Verifier;
import org.paztport.http.ModeHolder;
import org.paztport.http.PartnerSessions;
import org.paztport.http.PublicWrites;
import org.paztport.http.ReceivedRequestListener;
import org.paztport.http.boundary.BoundaryClient;
import org.paztport.http.event.EventPublisher;
import org.paztport.spring.event.EventConfiguration;
import org.paztport.spring.operation.OperationConfiguration;
import org.paztport.spring.operation.OperationResolver;
import org.paztport.spring.outbound.OutboundConfiguration;
import org.paztport.spring.outbound.PooledTlsClient;
import org.paztport.spring.partner.PartnerConfiguration;
import org.paztport.spring.trust.TrustConfiguration;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;

/**
 * Wires the inbound filter and outbound interceptor from {@code paztport.*}.
 * Beans appear only when their inputs are configured, so each service holds only
 * what its role requires: callers get a stamper and interceptor, a service with
 * a keyring, a root and the policy pin gets a Verifier, and every service gets
 * the inbound filter, which verifies requests only where {@code paztport.verify=true}.
 * Wherever there is a Verifier, the interceptor also checks every response it
 * gets, with a {@code ResponseVerifier} over the same material. A non-origin
 * service with both a stamper and a Verifier attests the responses it sends,
 * but only to requests whose chain verified there, and not while a service that
 * verifies requests is in {@code off} mode; an origin never attests.
 *
 * <p>The verifier is pinned: the keyring and the root must both verify under
 * {@code policy.pub}, or the context fails to start. Inside one mesh a request
 * tree is one call, so the session is empty and the run's age defaults to the
 * call's. Its replay cache forgets a key once it is older than the verifier
 * needs, at least twice the call window, so memory follows the traffic in that
 * window rather than every request and response ever checked. An application's
 * own {@code NonceCache} bean replaces the cache for requests only: responses
 * are checked with the starter's own, in memory, since only the replica that
 * sent a call can check its answer.
 *
 * <p>Under mutual TLS, {@code paztport.tls-bundle} names the SSL bundle this
 * service presents: on the shared {@code RestClient.Builder}, beside the
 * stamping interceptor, and on the responder client, which is built apart from
 * the shared builder so that events are never stamped. Both draw on one
 * {@link PooledTlsClient}, so their connections are pooled and reused rather
 * than opened per call. A bundle that does not exist fails the context at
 * startup. The calls have the read timeout {@code paztport.read-timeout-ms},
 * as do the egress's calls to the partner; events have their own short one,
 * {@code paztport.event-timeout-ms}, with a bundle or without. Either one that
 * is not positive fails the context at startup where it is used.
 *
 * <p>Setting {@code paztport.boundary.url} makes this service the egress to a
 * partner organisation, with a {@link BoundaryClient} that presents its own
 * bundle, {@code paztport.boundary.tls-bundle}. Setting {@code paztport.partner.enabled} makes this service the
 * partner's entry, which answers other organisations' session handshakes and verifies their calls with
 * {@link PartnerFilter} in place of the inbound filter, behind {@link org.paztport.spring.partner.PartnerGate}.
 *
 * <p>{@code paztport.operations.table-path} makes this service name its operations: the inbound filter then hands
 * the receiver the operation each request is dispatched to, from {@link OperationResolver}.
 * {@code paztport.operations.receiver-tables} makes its calls name their receivers' operations.
 * {@link OperationConfiguration} says what is checked at startup.
 *
 * <p>Each feature's beans are built by a configuration class of its own, which this imports. The request path's
 * own beans are defined here: the two filters, which adapt the receivers, and the public-writes rule.
 */
@AutoConfiguration
@EnableConfigurationProperties(PaztportProperties.class)
@Import({TrustConfiguration.class, OutboundConfiguration.class, PartnerConfiguration.class, EventConfiguration.class,
        OperationConfiguration.class})
public class PaztportAutoConfiguration {

    /**
     * The partner's filter, where this organisation's would otherwise be: another organisation's calls verify in their
     * session, against what that session's handshake pinned, never against this organisation's own trust.
     */
    @Bean
    @ConditionalOnProperty("paztport.partner.enabled")
    FilterRegistrationBean<PartnerFilter> paztportPartnerFilterRegistration(
            PartnerSessions sessions, PaztportProperties props, ObjectProvider<ObservationRegistry> observations) {
        FilterRegistrationBean<PartnerFilter> registration = new FilterRegistrationBean<>(new PartnerFilter(sessions,
                props.getServiceName(), observations.getIfAvailable(() -> ObservationRegistry.NOOP),
                props.getUnverifiedPaths()));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.addUrlPatterns("/*");
        return registration;
    }

    /** Always present: the rule needs no keys, only this service's name for its trace line. */
    @Bean
    PublicWrites paztportPublicWrites(PaztportProperties props) {
        return new PublicWrites(props.getServiceName());
    }

    /**
     * A service told to verify but given no trust paths fails to start, rather
     * than serving unverified requests it was meant to check. A partner's entry
     * has {@link PartnerFilter} instead.
     */
    @Bean
    @ConditionalOnProperty(name = "paztport.partner.enabled", havingValue = "false", matchIfMissing = true)
    FilterRegistrationBean<InboundFilter> paztportInboundFilterRegistration(
            PaztportProperties props,
            ObjectProvider<Verifier> verifier,
            ObjectProvider<ModeHolder> modeHolder,
            ObjectProvider<EventPublisher> publisher,
            ObjectProvider<ReceivedRequestListener> listener,
            ObjectProvider<Stamper> stamper,
            ObjectProvider<OperationResolver> operations,
            ObjectProvider<ObservationRegistry> observations) {
        Verifier shared = verifier.getIfAvailable();
        if (props.isVerify() && shared == null) {
            throw new IllegalStateException("paztport.verify is true but paztport.keyring-path, "
                    + "paztport.root-path and paztport.policy-key-path are not all set");
        }
        // The verifier goes to every service that has one: where requests are not verified, it decides attestation.
        InboundFilter filter = new InboundFilter(
                shared, props.isVerify(), props.isOrigin(), props.getServiceName(), modeHolder.getIfAvailable(),
                publisher.getIfAvailable(), listener.getIfAvailable(), stamper.getIfAvailable(),
                operations.getIfAvailable(), observations.getIfAvailable(() -> ObservationRegistry.NOOP),
                props.getUnverifiedPaths());
        FilterRegistrationBean<InboundFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        registration.addUrlPatterns("/*");
        return registration;
    }
}
