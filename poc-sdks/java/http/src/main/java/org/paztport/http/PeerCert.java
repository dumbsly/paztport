// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package org.paztport.http;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import javax.security.auth.x500.X500Principal;
import org.paztport.core.verify.Peer;

/**
 * The sender a client certificate names, as a receiver needs it: the {@link Peer} the verifier compares with the
 * chain, and the certificate's issuer, by which a partner keeps sessions. Under mutual TLS the transport has already
 * checked the certificate against the CAs it trusts, so its subject names a service one of them vouched for, and the
 * chain's last signer must be that service.
 *
 * <p>The service is the subject's common name, but only when there is exactly one, counted value by value across
 * every RDN, and it is a UTF8String or a PrintableString: a certificate with none, with several, or with one of
 * another type names no service, so the peer's service is {@code ""} and the peer check fails closed rather than
 * picking one. It is read from the subject's bytes as they stand in the certificate's {@code TBSCertificate}
 * ({@link SubjectService}), which the CA's signature covers and the TLS layer has verified. Neither a rendering of
 * the subject nor {@code X500Principal.getEncoded()} would do: the JDK can hand back an encoding rebuilt from its own
 * parse (JDK 25 and 27 do for a subject not in DER), so a subject the spec refuses would come back looking well
 * formed. The instance is the address the connection came from, which is what a responder acts against; it is not
 * compared with the chain.
 *
 * <p>The issuer is the certificate's issuer in RFC 2253. A partner keeps sessions by issuer as well as name: a
 * transport may trust more than one CA, and each could issue a certificate with the same name, so the name alone
 * does not tell their holders apart.
 *
 * @param peer the service the certificate names and the address the connection came from
 * @param issuer the certificate's issuer, RFC 2253
 */
public record PeerCert(Peer peer, String issuer) {

    public PeerCert {
        Objects.requireNonNull(peer, "peer");
        Objects.requireNonNull(issuer, "issuer");
    }

    /**
     * The peer {@code leaf}, the client's own certificate (not one of its CAs'), names, connected from
     * {@code remoteAddr}.
     */
    public static PeerCert of(X509Certificate leaf, String remoteAddr) {
        return new PeerCert(new Peer(service(leaf), remoteAddr),
                leaf.getIssuerX500Principal().getName(X500Principal.RFC2253));
    }

    /**
     * The service {@code certificate} names: its subject's one common name, read by the spec's rule from the subject
     * as the certificate encodes it ({@link SubjectService}), else {@code ""}. A certificate whose
     * {@code TBSCertificate} cannot be had names none.
     */
    public static String service(X509Certificate certificate) {
        try {
            return SubjectService.ofCertificate(certificate.getTBSCertificate());
        } catch (CertificateEncodingException e) {
            return "";
        }
    }
}
