// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"encoding/hex"
	"testing"
	"unicode/utf8"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
)

// FuzzServiceOf reads any bytes as a client certificate, seeded with the rules' peer certificates. It
// never panics, PeerFromCertificate names the same service ServiceOf does, and a service or issuer it
// gives is UTF-8 text.
func FuzzServiceOf(f *testing.F) {
	vectors.Rules(f).Get("peerCertificates").Each(func(_ string, c vectors.Node) {
		der, err := hex.DecodeString(c.Get("certificate").Str())
		if err != nil {
			f.Fatalf("certificate: %v", err)
		}
		f.Add(der)
	})
	vectors.Rules(f).Get("peers").Each(func(name string, _ vectors.Node) {
		der, _ := vectors.RulesPeer(f, name)
		f.Add(der)
	})
	f.Fuzz(func(t *testing.T, der []byte) {
		svc := paztporthttp.ServiceOf(der)
		p := paztporthttp.PeerFromCertificate(der, "10.0.0.1")
		if p.Peer.Svc != svc || p.Peer.Inst != "10.0.0.1" {
			t.Fatalf("PeerFromCertificate = %+v, ServiceOf = %q", p, svc)
		}
		if !utf8.ValidString(svc) || !utf8.ValidString(p.Issuer) {
			t.Fatalf("the service %q or issuer %q is not UTF-8", svc, p.Issuer)
		}
	})
}
