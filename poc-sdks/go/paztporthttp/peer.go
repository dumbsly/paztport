// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import "github.com/dumbsly/paztport/poc-sdks/go/verify"

// PeerCert is the sender a client certificate names, as a receiver needs it: the [verify.Peer] the
// verifier compares with the chain's last signer, and the certificate's issuer, by which a partner keeps
// sessions. Under mutual TLS the transport has already checked the certificate against the CAs it
// trusts, so its subject names a service one of them vouched for.
//
// Make one with [PeerFromCertificate], so that the service it names is always the one the spec's rule
// reads from the certificate, never a name some code chose.
type PeerCert struct {
	// Peer is the service the certificate names, as ServiceOf reads it, and the address the connection
	// came from. A certificate that names no service is still a peer, with Svc "", so the peer check
	// runs and fails rather than being skipped.
	Peer verify.Peer
	// Issuer is the certificate's issuer as RFC 2253 text, or "" when the walk never reaches the issuer,
	// or the issuer does not read as a distinguished name, holds a part encoding/asn1 cannot render or is
	// empty: an issuer of "" opens no session and matches none. The issuer is read even when the subject
	// is not, but such a certificate names no service, so it opens no session either. A partner keeps
	// sessions by issuer as well as by service, since a transport may trust more than one CA and each
	// could issue a certificate with the same name. The text is the same every time for the same issuer,
	// which is all the partner that recorded it compares; it is not promised to match another
	// implementation's.
	Issuer string
}

// PeerFromCertificate returns the peer der names, connected from remoteAddr: der is the client's own
// certificate (the leaf, not one of its CAs'), in DER, as the TLS layer verified it, and remoteAddr the
// address the connection came from, without its port (for net/http, the host net.SplitHostPort gives of
// Request.RemoteAddr), which is the peer's Inst. It never panics, whatever der holds.
func PeerFromCertificate(der []byte, remoteAddr string) PeerCert {
	p := PeerCert{Peer: verify.Peer{Inst: remoteAddr}}
	n := certificateNames(der)
	if n.hasSubject {
		p.Peer.Svc = serviceOfName(n.subject)
	}
	if n.hasIssuer {
		p.Issuer = issuerText(n.issuer)
	}
	return p
}

// ServiceOf returns the service the DER certificate der names: its subject's one common name, when it
// has exactly one, counted value by value across every RDN, and that value is a UTF8String of UTF-8 or a
// PrintableString of printable characters. It returns "" for any other certificate, which names no
// service.
//
// The name is read from the subject's bytes as they stand in the certificate's TBSCertificate, the bytes
// the CA's signature covers, by a walk of the DER itself rather than through an X.509 parser, whose
// rendering or re-encoding of a subject could make one the spec refuses look well formed. Every header
// the walk passes, down to each attribute's value, must be in X.690's distinguished encoding: a definite
// length, in its shortest form, within its parent. Nothing inside an attribute's value is walked, nor
// anything after the subject. The text is returned as it is, with no case folding or other
// normalisation. ServiceOf never panics, whatever der holds.
func ServiceOf(der []byte) string {
	if n := certificateNames(der); n.hasSubject {
		return serviceOfName(n.subject)
	}
	return ""
}
