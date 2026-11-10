// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/vectors"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
)

// Certificates built by hand in DER, so that each case is exactly the encoding it says, whatever an
// X.509 library would write or accept. Only the headers the spec's steps walk matter: the signature is
// made up, since the TLS layer has judged a certificate before its peer is read.

var (
	oidCN = []byte{0x55, 0x04, 0x03}
	oidO  = []byte{0x55, 0x04, 0x0A}
)

// tlv returns one DER element with identifier tag, its contents the parts, its length in the shortest
// form.
func tlv(tag byte, parts ...[]byte) []byte {
	contents := bytes.Join(parts, nil)
	n := len(contents)
	out := []byte{tag}
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, contents...)
}

func attribute(oid []byte, valueTag byte, value []byte) []byte {
	return tlv(0x30, tlv(0x06, oid), tlv(valueTag, value))
}

func rdn(attributes ...[]byte) []byte { return tlv(0x31, attributes...) }

func name(rdns ...[]byte) []byte { return tlv(0x30, rdns...) }

func cn(s string) []byte { return rdn(attribute(oidCN, 0x0C, []byte(s))) }

// longForm returns element, whose length fits in one octet, with that length written in the long form.
func longForm(t *testing.T, element []byte) []byte {
	t.Helper()
	if element[1] >= 0x80 || int(element[1]) != len(element)-2 {
		t.Fatal("longForm takes a short-form element")
	}
	return bytes.Join([][]byte{{element[0], 0x81, element[1]}, element[2:]}, nil)
}

// padLength returns element, whose length is in one long-form octet, with that length written in two
// octets, the first zero, so that it is not in its shortest form.
func padLength(t *testing.T, element []byte) []byte {
	t.Helper()
	if element[1] != 0x81 || int(element[2]) != len(element)-3 {
		t.Fatal("padLength takes an element whose length is in one long-form octet")
	}
	return bytes.Join([][]byte{{element[0], 0x82, 0x00, element[2]}, element[3:]}, nil)
}

// indefinite returns element, whose length fits in one octet, with an indefinite length, its contents
// closed by the end-of-contents octets.
func indefinite(t *testing.T, element []byte) []byte {
	t.Helper()
	if element[1] >= 0x80 {
		t.Fatal("indefinite takes a short-form element")
	}
	return bytes.Join([][]byte{{element[0], 0x80}, element[2:], {0, 0}}, nil)
}

var (
	algorithm = tlv(0x30, tlv(0x06, []byte{0x2B, 0x65, 0x70}))
	shopCA    = name(rdn(attribute(oidO, 0x0C, []byte("shop"))), cn("shop CA"))
	validity  = tlv(0x30, tlv(0x17, []byte("260101000000Z")), tlv(0x17, []byte("360101000000Z")))
	spki      = tlv(0x30, algorithm, tlv(0x03, make([]byte, 33)))
	version   = tlv(0xA0, tlv(0x02, []byte{2}))
	serial    = tlv(0x02, []byte{1})
	orders    = name(rdn(attribute(oidO, 0x0C, []byte("shop"))), cn("orders"))
)

// tbsOf returns a TBSCertificate of the fields given, the subject's public key after them.
func tbsOf(fields ...[]byte) []byte { return tlv(0x30, append(fields, spki)...) }

// certOf returns a certificate around tbs, with a made-up signature.
func certOf(tbs []byte) []byte {
	return tlv(0x30, tbs, algorithm, tlv(0x03, append([]byte{0}, make([]byte, 64)...)))
}

// certFor returns a v3 certificate from shop CA for subject.
func certFor(subject []byte) []byte {
	return certOf(tbsOf(version, serial, algorithm, shopCA, validity, subject))
}

// TestServiceOfOneCommonName reads the subject's one common name, a UTF8String or a PrintableString, as
// it is.
func TestServiceOfOneCommonName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		subject []byte
		want    string
	}{
		{"UTF8String after another attribute", orders, "orders"},
		{"UTF-8 past ASCII", name(rdn(attribute(oidCN, 0x0C, []byte("zahlung-\xc3\xbc")))), "zahlung-\xc3\xbc"},
		{"PrintableString", name(rdn(attribute(oidCN, 0x13, []byte("orders")))), "orders"},
		{"every printable character", name(rdn(attribute(oidCN, 0x13, []byte("Az09 '()+,-./:=?")))),
			"Az09 '()+,-./:=?"},
		{"case kept", name(cn("Orders")), "Orders"},
		{"an empty UTF8String", name(rdn(attribute(oidCN, 0x0C, nil))), ""},
	} {
		if got := paztporthttp.ServiceOf(certFor(tc.subject)); got != tc.want {
			t.Errorf("%s: ServiceOf = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestServiceOfOtherStringTypes names no service for a common name of any type but UTF8String and
// PrintableString, however readable its text: RFC 5280 has conforming CAs use those two for new certificates, and
// only a legacy name may keep TeletexString, BMPString or UniversalString.
func TestServiceOfOtherStringTypes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tag   byte
		value []byte
	}{
		{"TeletexString", 0x14, []byte("orders")},
		{"IA5String", 0x16, []byte("orders")},
		{"GeneralString", 0x1B, []byte("orders")},
		{"UniversalString", 0x1C, []byte{0, 0, 0, 'a', 0, 0, 0, 'b'}},
		{"BMPString", 0x1E, []byte{0, 'o', 0, 'r', 0, 'd', 0, 'e', 0, 'r', 0, 's'}},
		{"VisibleString", 0x1A, []byte("orders")},
		{"OCTET STRING", 0x04, []byte("orders")},
		{"a constructed UTF8String", 0x2C, tlv(0x0C, []byte("orders"))},
		{"a constructed PrintableString", 0x33, tlv(0x13, []byte("orders"))},
		{"a context-specific tag 12", 0x8C, []byte("orders")},
	} {
		if got := paztporthttp.ServiceOf(certFor(name(rdn(attribute(oidCN, tc.tag, tc.value))))); got != "" {
			t.Errorf("%s: ServiceOf = %q, want none", tc.name, got)
		}
	}
	// A high-tag-number form of tag 12 is read as a value, and is no UTF8String.
	high := name(rdn(tlv(0x30, tlv(0x06, oidCN), []byte{0x1F, 0x0C, 0x06, 'o', 'r', 'd', 'e', 'r', 's'})))
	if got := paztporthttp.ServiceOf(certFor(high)); got != "" {
		t.Errorf("a high-tag-number tag 12: ServiceOf = %q, want none", got)
	}
}

// TestServiceOfValueNotWellFormed names no service for a common name whose text is not well formed for
// its type.
func TestServiceOfValueNotWellFormed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tag   byte
		value []byte
	}{
		{"an overlong UTF-8 form", 0x0C, []byte{0xC0, 0x80}},
		{"an encoded surrogate", 0x0C, []byte{0xED, 0xA0, 0x80}},
		{"past U+10FFFF", 0x0C, []byte{0xF4, 0x90, 0x80, 0x80}},
		{"a sequence cut short", 0x0C, []byte{'a', 0xC3}},
		{"@ is not printable", 0x13, []byte("orders@shop")},
		{"_ is not printable", 0x13, []byte("orders_1")},
		{"a byte past ASCII", 0x13, []byte{'a', 0xE9}},
		{"a NUL", 0x13, []byte{'a', 0}},
		{"* is not printable", 0x13, []byte("orders*1")},
		{"& is not printable", 0x13, []byte("a&b")},
	} {
		if got := paztporthttp.ServiceOf(certFor(name(rdn(attribute(oidCN, tc.tag, tc.value))))); got != "" {
			t.Errorf("%s: ServiceOf = %q, want none", tc.name, got)
		}
	}
	// Every ASCII byte outside X.680's PrintableString set, among characters inside it, names no service.
	const printableSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"
	outside := 0
	for b := range 0x80 {
		if strings.IndexByte(printableSet, byte(b)) >= 0 {
			continue
		}
		outside++
		value := []byte{'a', byte(b), 'b'}
		if got := paztporthttp.ServiceOf(certFor(name(rdn(attribute(oidCN, 0x13, value))))); got != "" {
			t.Errorf("a PrintableString holding 0x%02X: ServiceOf = %q, want none", b, got)
		}
	}
	if outside != 128-74 {
		t.Fatalf("%d ASCII bytes lie outside the printable set, want %d", outside, 128-74)
	}
}

// TestServiceOfCountsEveryCommonName names no service unless there is exactly one common name, counted
// across every RDN and every value of a multi-valued RDN, whatever their types.
func TestServiceOfCountsEveryCommonName(t *testing.T) {
	for _, tc := range []struct {
		name    string
		subject []byte
	}{
		{"none", name(rdn(attribute(oidO, 0x0C, []byte("shop"))))},
		{"an empty Name", name()},
		{"two equal in two RDNs", name(cn("a"), cn("a"))},
		{"two equal in one RDN", name(rdn(attribute(oidCN, 0x0C, []byte("a")), attribute(oidCN, 0x0C, []byte("a"))))},
		{"a second of another type", name(cn("orders"), rdn(attribute(oidCN, 0x16, []byte("orders"))))},
		{"a second of another type first", name(rdn(attribute(oidCN, 0x16, []byte("orders"))), cn("orders"))},
		{"a second not well formed", name(cn("orders"), rdn(attribute(oidCN, 0x0C, []byte{0xC0, 0x80})))},
		{"a second in a multi-valued RDN with another attribute", name(cn("orders"),
			rdn(attribute(oidO, 0x0C, []byte("shop")), attribute(oidCN, 0x0C, []byte("b"))))},
	} {
		if got := paztporthttp.ServiceOf(certFor(tc.subject)); got != "" {
			t.Errorf("%s: ServiceOf = %q, want none", tc.name, got)
		}
	}
	multi := name(rdn(attribute(oidO, 0x0C, []byte("shop")), attribute(oidCN, 0x0C, []byte("orders"))))
	if got := paztporthttp.ServiceOf(certFor(multi)); got != "orders" {
		t.Errorf("one common name in a multi-valued RDN: ServiceOf = %q, want orders", got)
	}
}

// TestServiceOfCommonNameOID counts an attribute as a common name exactly when its OBJECT IDENTIFIER's
// contents are 55 04 03; any other contents, other spellings of 2.5.4.3 and malformed ones included, make
// some other attribute.
func TestServiceOfCommonNameOID(t *testing.T) {
	for _, tc := range []struct {
		name string
		oid  []byte
	}{
		{"a non-minimal 2.5.4.3", []byte{0x55, 0x04, 0x80, 0x03}},
		{"an empty OID", nil},
		{"2.5.4.3 with a trailing octet", []byte{0x55, 0x04, 0x03, 0x00}},
		{"2.5.4.10", oidO},
	} {
		subject := name(rdn(attribute(tc.oid, 0x0C, []byte("evil"))), cn("orders"))
		if got := paztporthttp.ServiceOf(certFor(subject)); got != "orders" {
			t.Errorf("%s is another attribute: ServiceOf = %q, want orders", tc.name, got)
		}
	}
	prefix := name(rdn(attribute([]byte{0x55, 0x04}, 0x0C, []byte("orders"))))
	if got := paztporthttp.ServiceOf(certFor(prefix)); got != "" {
		t.Errorf("a prefix of 2.5.4.3 is no common name: ServiceOf = %q", got)
	}
}

// TestServiceOfSubjectShape names no service for a subject that is not a well-formed DER Name: every
// header walked has its identifier, a definite length in its shortest form, and stays within its parent.
func TestServiceOfSubjectShape(t *testing.T) {
	ordersCN := attribute(oidCN, 0x0C, []byte("orders"))
	for _, tc := range []struct {
		name    string
		subject []byte
	}{
		{"an RDN that is not a SET", name(tlv(0x30, ordersCN))},
		{"an empty RDN", name(rdn(), cn("orders"))},
		{"an attribute that is not a SEQUENCE", name(rdn(tlv(0x31, tlv(0x06, oidCN), tlv(0x0C, []byte("orders")))))},
		{"a type that is not an OBJECT IDENTIFIER", name(rdn(tlv(0x30, tlv(0x04, oidCN), tlv(0x0C, []byte("orders")))))},
		{"an attribute with no value", name(rdn(tlv(0x30, tlv(0x06, oidCN))))},
		{"an attribute with two values", name(rdn(tlv(0x30, tlv(0x06, oidCN), tlv(0x0C, []byte("orders")),
			tlv(0x0C, []byte("x")))))},
		{"a trailing octet in the Name", tlv(0x30, cn("orders"), []byte{0})},
		{"a trailing octet in an RDN", name(tlv(0x31, ordersCN, []byte{0}))},
		{"a trailing octet in an attribute", name(rdn(tlv(0x30, tlv(0x06, oidCN), tlv(0x0C, []byte("orders")), []byte{0})))},
		{"the Name's length not shortest", longForm(t, name(cn("orders")))},
		{"an RDN's length not shortest", name(longForm(t, cn("orders")))},
		{"an attribute's length not shortest", name(rdn(longForm(t, ordersCN)))},
		{"the OID's length not shortest", name(rdn(tlv(0x30, longForm(t, tlv(0x06, oidCN)), tlv(0x0C, []byte("orders")))))},
		{"the value's length not shortest", name(rdn(tlv(0x30, tlv(0x06, oidCN), longForm(t, tlv(0x0C, []byte("orders"))))))},
		{"a long-form length with a leading zero octet", name(rdn(tlv(0x30, tlv(0x06, oidCN),
			append([]byte{0x0C, 0x82, 0x00, 0x06}, "orders"...))))},
		{"an indefinite Name", indefinite(t, name(cn("orders")))},
		{"an indefinite RDN", name(indefinite(t, cn("orders")))},
		{"an indefinite value", name(rdn(tlv(0x30, tlv(0x06, oidCN), []byte{0x2C, 0x80, 0x0C, 0x01, 'a', 0, 0})))},
		{"a value running past its attribute", name(rdn(tlv(0x30, tlv(0x06, oidCN),
			append([]byte{0x0C, 0x07}, "orders"...))))},
		{"a high tag never closed", name(rdn(tlv(0x30, tlv(0x06, oidCN), []byte{0x1F, 0x8C, 0x86})))},
	} {
		if got := paztporthttp.ServiceOf(certFor(tc.subject)); got != "" {
			t.Errorf("%s: ServiceOf = %q, want none", tc.name, got)
		}
	}
}

// TestServiceOfOtherValuesNotWalked never looks inside another attribute's value, however it is
// encoded, and lets that value have any identifier, the high-tag-number form included.
func TestServiceOfOtherValuesNotWalked(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value []byte
	}{
		{"a non-minimal length inside", tlv(0x30, []byte{0x04, 0x81, 0x01, 'x'})},
		{"an indefinite length inside", tlv(0x30, []byte{0x24, 0x80, 0x04, 0x01, 'x', 0x00, 0x00})},
		{"a string not well formed", tlv(0x0C, []byte{0xC0, 0x80})},
		{"a high-tag-number identifier", []byte{0x1F, 0x81, 0x00, 0x01, 'x'}},
		{"a high-tag-number identifier of one octet", []byte{0x5F, 0x05, 0x00}},
	} {
		subject := name(rdn(tlv(0x30, tlv(0x06, oidO), tc.value)), cn("orders"))
		if got := paztporthttp.ServiceOf(certFor(subject)); got != "orders" {
			t.Errorf("%s: ServiceOf = %q, want orders", tc.name, got)
		}
	}
}

// TestServiceOfFindsTheSubject reads the subject of a certificate with or without its version, passing
// over the fields before it by their headers alone.
func TestServiceOfFindsTheSubject(t *testing.T) {
	if got := paztporthttp.ServiceOf(certOf(tbsOf(serial, algorithm, shopCA, validity, orders))); got != "orders" {
		t.Errorf("a v1 certificate: ServiceOf = %q, want orders", got)
	}
	madeUp := tbsOf(tlv(0xA0, []byte{0xFF}), tlv(0x02, []byte{0x81, 0x01}), tlv(0x30, []byte{0x04, 0x81, 0x01, 'x'}),
		tlv(0x30), tlv(0x30, []byte{0x24, 0x80}), orders)
	if got := paztporthttp.ServiceOf(certOf(madeUp)); got != "orders" {
		t.Errorf("fields whose contents are made up: ServiceOf = %q, want orders", got)
	}
	// Nothing after the subject is read.
	bare := tlv(0x30, version, serial, algorithm, shopCA, validity, orders, []byte{0xFF, 0xFF})
	if got := paztporthttp.ServiceOf(certOf(bare)); got != "orders" {
		t.Errorf("anything after the subject: ServiceOf = %q, want orders", got)
	}
}

// TestServiceOfCannotWalk names no service for a certificate that cannot be walked as far as its
// subject.
func TestServiceOfCannotWalk(t *testing.T) {
	good := certFor(orders)
	if good[1] != 0x81 {
		t.Fatal("the control's length is not in one long-form octet, so the cases below are not the ones named")
	}
	tbs := tbsOf(version, serial, algorithm, shopCA, validity, orders)
	notSequence := bytes.Clone(good)
	notSequence[0] = 0x31
	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{"nothing", nil},
		{"a Name, not a certificate", orders},
		{"a TBSCertificate, not a certificate", tbs},
		{"a trailing octet after the certificate", append(bytes.Clone(good), 0)},
		{"cut short", good[:len(good)-1]},
		{"not a SEQUENCE", notSequence},
		{"a TBSCertificate that is not a SEQUENCE", certOf(append([]byte{0x31}, tbs[1:]...))},
		{"the certificate's length not shortest", bytes.Join([][]byte{{0x30, 0x82, 0x00, byte(len(good) - 3)},
			good[3:]}, nil)},
		{"no serial number", certOf(tbsOf(version, tlv(0x04, []byte{1}), algorithm, shopCA, validity, orders))},
		{"a version but no serial number", certOf(tbsOf(version, algorithm, shopCA, validity, orders))},
		{"two versions", certOf(tbsOf(version, version, serial, algorithm, shopCA, validity, orders))},
		{"a first field [1], not the version", certOf(tbsOf(tlv(0xA1, serial), serial, algorithm, shopCA, validity,
			orders))},
		{"no subject", certOf(tlv(0x30, version, serial, algorithm, shopCA, validity))},
		{"a subject that is not a SEQUENCE", certOf(tbsOf(version, serial, algorithm, shopCA, validity,
			tlv(0x31, cn("orders"))))},
		{"a validity that is not a SEQUENCE", certOf(tbsOf(serial, algorithm, shopCA, tlv(0x31, validity), orders))},
		{"an algorithm that is not a SEQUENCE", certOf(tbsOf(serial, tlv(0x31, algorithm[2:]), shopCA, validity, orders))},
		{"an indefinite issuer", certOf(tbsOf(serial, algorithm, indefinite(t, shopCA), validity, orders))},
		{"an issuer's length not shortest", certOf(tbsOf(serial, algorithm, longForm(t, shopCA), validity, orders))},
		{"an indefinite TBSCertificate", certOf(indefinite(t, tlv(0x30, serial, algorithm, shopCA, validity, orders)))},
		{"a validity running past the TBSCertificate", certOf(tlv(0x30, serial, algorithm, shopCA, []byte{0x30, 0x7F}))},
		{"the TBSCertificate's length not shortest", certOf(padLength(t, tbs))},
		{"a TBSCertificate running past its certificate", tlv(0x30, []byte{0x30, 0x82, 0x01, 0xFF}, tbs[3:],
			algorithm)},
		{"the version's length not shortest", certOf(tbsOf(longForm(t, version), serial, algorithm, shopCA, validity,
			orders))},
		{"the serial's length not shortest", certOf(tbsOf(version, longForm(t, serial), algorithm, shopCA, validity,
			orders))},
		{"the algorithm's length not shortest", certOf(tbsOf(serial, longForm(t, algorithm), shopCA, validity, orders))},
		{"an indefinite algorithm", certOf(tbsOf(serial, indefinite(t, algorithm), shopCA, validity, orders))},
		{"an algorithm running past the TBSCertificate", certOf(tlv(0x30, serial, []byte{0x30, 0x7F}))},
		{"the validity's length not shortest", certOf(tbsOf(serial, algorithm, shopCA, longForm(t, validity), orders))},
		{"an indefinite validity", certOf(tbsOf(serial, algorithm, shopCA, indefinite(t, validity), orders))},
		{"a subject longer than its TBSCertificate", certOf(tlv(0x30, serial, algorithm, shopCA, validity,
			[]byte{0x30, 0x7F}))},
	} {
		if got := paztporthttp.ServiceOf(tc.der); got != "" {
			t.Errorf("%s: ServiceOf = %q, want none", tc.name, got)
		}
	}
	if got := paztporthttp.ServiceOf(good); got != "orders" {
		t.Fatalf("the control: ServiceOf = %q, want orders", got)
	}
}

// TestPeerFromCertificate names the peer by the certificate's subject and the connection's address,
// and gives the issuer as RFC 2253 text.
func TestPeerFromCertificate(t *testing.T) {
	p := paztporthttp.PeerFromCertificate(certFor(orders), "172.18.0.5")
	if p.Peer.Svc != "orders" || p.Peer.Inst != "172.18.0.5" || p.Issuer != "CN=shop CA,O=shop" {
		t.Fatalf("PeerFromCertificate = %+v", p)
	}
	none := paztporthttp.PeerFromCertificate(certFor(name(rdn(attribute(oidO, 0x0C, []byte("shop"))))), "172.18.0.6")
	if none.Peer.Svc != "" || none.Peer.Inst != "172.18.0.6" || none.Issuer != "CN=shop CA,O=shop" {
		t.Fatalf("with no common name: PeerFromCertificate = %+v, want a peer naming no service", none)
	}
	// The issuer is read wherever the walk reaches it, whatever follows it.
	for _, tbs := range [][]byte{
		tbsOf(version, serial, algorithm, shopCA, validity, longForm(t, name(cn("orders")))),
		tbsOf(version, serial, algorithm, shopCA, tlv(0x31, validity), orders),
	} {
		p := paztporthttp.PeerFromCertificate(certOf(tbs), "172.18.0.8")
		if p.Peer.Svc != "" || p.Issuer != "CN=shop CA,O=shop" {
			t.Fatalf("with no subject the walk can read: PeerFromCertificate = %+v", p)
		}
	}
	bad := paztporthttp.PeerFromCertificate([]byte{0x30, 0x80}, "172.18.0.7")
	if bad.Peer.Svc != "" || bad.Peer.Inst != "172.18.0.7" || bad.Issuer != "" {
		t.Fatalf("a certificate that does not read: PeerFromCertificate = %+v", bad)
	}
}

// TestIssuerText gives the same issuer the same text, another issuer other text, and an issuer that
// does not read as a Name, or is empty, no text.
func TestIssuerText(t *testing.T) {
	issuer := func(peer string) string {
		der, addr := vectors.RulesPeer(t, peer)
		return paztporthttp.PeerFromCertificate(der, addr).Issuer
	}
	shop, unnamed, other, clinic := issuer("shop"), issuer("unnamed"), issuer("shop-other-ca"), issuer("clinic")
	if shop != "CN=shop CA,O=shop" || unnamed != shop {
		t.Errorf("shop CA's certificates give issuers %q and %q, want CN=shop CA,O=shop", shop, unnamed)
	}
	if other != "CN=other CA,O=elsewhere" || clinic != "CN=clinic CA,O=clinic" {
		t.Errorf("the other CAs give %q and %q", other, clinic)
	}

	for _, tc := range []struct {
		name   string
		issuer []byte
	}{
		{"an empty Name", name()},
		{"an empty RDN", name(rdn())},
		{"a Name holding no SET", tlv(0x30, tlv(0x04, []byte("x")))},
		{"an RDN holding no attribute", tlv(0x30, tlv(0x31, tlv(0x04, []byte("x"))))},
		{"an attribute with no value", name(rdn(tlv(0x30, tlv(0x06, oidCN))))},
		{"an OID that does not read", name(rdn(attribute(nil, 0x0C, []byte("x"))))},
		{"two empty RDNs", []byte{0x30, 0x04, 0x31, 0x00, 0x31, 0x00}},
		{"an empty RDN after a named one", name(cn("shop CA"), rdn())},
		{"a common name whose value is a SEQUENCE", name(cn("shop CA"), rdn(tlv(0x30, tlv(0x06, oidCN), tlv(0x30))))},
		{"an unknown attribute whose value is a SEQUENCE", name(rdn(tlv(0x30, tlv(0x06, []byte{0x2A, 0x03}),
			tlv(0x30, tlv(0x02, []byte{1})))))},
		{"a value with a high-tag-number identifier", name(rdn(tlv(0x30, tlv(0x06, oidO), []byte{0x1F, 0x22, 0x01, 'x'})))},
	} {
		p := paztporthttp.PeerFromCertificate(certOf(tbsOf(version, serial, algorithm, tc.issuer, validity, orders)), "a")
		if p.Issuer != "" || p.Peer.Svc != "orders" {
			t.Errorf("%s: PeerFromCertificate = %+v, want no issuer and the service", tc.name, p)
		}
	}
}
