// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.spring.internal;

import jakarta.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import org.paztport.core.verify.Peer;
import org.paztport.http.PeerCert;

/**
 * The sender the TLS layer authenticated, read from the servlet request. Under mutual TLS the container has already
 * checked the client certificate against the shop's CA before any request reaches the filter; which service and
 * issuer the certificate names is {@link PeerCert}'s rule. The container gives the client's chain leaf first, and only
 * the leaf names the client.
 */
public final class PeerIdentity {

    /** The servlet attribute where the container puts the client's certificate chain, leaf first. */
    private static final String CERTIFICATES = "jakarta.servlet.request.X509Certificate";

    private PeerIdentity() {
    }

    /**
     * The authenticated sender's certificate, as the receivers read it, or null when no client certificate came with
     * the request (plain HTTP, or no mTLS).
     */
    public static PeerCert cert(HttpServletRequest request) {
        X509Certificate leaf = request.getAttribute(CERTIFICATES) instanceof X509Certificate[] chain && chain.length > 0
                ? chain[0] : null;
        return leaf == null ? null : PeerCert.of(leaf, request.getRemoteAddr());
    }

    /** The authenticated sender, or null when no client certificate came with the request (plain HTTP, or no mTLS). */
    public static Peer from(HttpServletRequest request) {
        PeerCert cert = cert(request);
        return cert == null ? null : cert.peer();
    }
}
