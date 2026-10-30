// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import jakarta.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.paztport.core.verify.Peer;

/**
 * The sender the TLS layer authenticated, as the verifier's peer. Under mutual TLS the container has already checked
 * the client certificate against the shop's CA before any request reaches the filter, so the certificate's subject
 * names a service the shop vouched for, and the chain's last signer must be that service.
 *
 * <p>The service is the subject's common name, but only when there is exactly one, counted value by value across
 * every RDN, and it is a DirectoryString: a certificate with none, with several, or with one of another type names
 * no service, so the peer's service is {@code ""} and the peer check fails closed rather than picking one. It is read
 * from the subject's encoding ({@link SubjectService}), not from a rendering of it. The instance is the TCP address
 * the request came from, which is what a responder acts against; it is not compared with the chain.
 */
public final class PeerIdentity {

    /** The servlet attribute where the container puts the client's certificate chain, leaf first. */
    private static final String CERTIFICATES = "jakarta.servlet.request.X509Certificate";

    private PeerIdentity() {
    }

    /** The authenticated sender, or null when no client certificate came with the request (plain HTTP, or no mTLS). */
    public static Peer from(HttpServletRequest request) {
        X509Certificate leaf = leaf(request);
        return leaf == null ? null : new Peer(commonName(leaf.getSubjectX500Principal()), request.getRemoteAddr());
    }

    /**
     * The client certificate's issuer, in RFC 2253, or null when no client certificate came with the request. A
     * partner keeps sessions by issuer as well as name: the container may trust more than one CA, and each could
     * issue a certificate with the same name, so the name alone does not tell their holders apart.
     */
    public static String issuer(HttpServletRequest request) {
        X509Certificate leaf = leaf(request);
        return leaf == null ? null : leaf.getIssuerX500Principal().getName(X500Principal.RFC2253);
    }

    private static X509Certificate leaf(HttpServletRequest request) {
        return request.getAttribute(CERTIFICATES) instanceof X509Certificate[] chain && chain.length > 0
                ? chain[0] : null;
    }

    /**
     * The service {@code subject} names: its one common name, read from its DER encoding by the spec's rule
     * ({@link SubjectService}), else {@code ""}.
     */
    public static String commonName(X500Principal subject) {
        return SubjectService.of(subject.getEncoded());
    }
}
