// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"unicode/utf8"
)

// The DER walk that reads a client certificate's subject and issuer as the certificate encodes them,
// by the spec's steps, rather than through an X.509 parser: crypto/x509 refuses some encodings the spec
// reads, and any parser that re-encodes a subject could make one the steps refuse look well formed.

// Identifier octets the walk expects.
const (
	tagInteger    = 0x02
	tagOID        = 0x06
	tagUTF8       = 0x0C
	tagPrintable  = 0x13
	tagSequence   = 0x30
	tagSet        = 0x31
	tagVersion    = 0xA0 // a certificate's [0] EXPLICIT version: context-specific, constructed, tag 0
	tagHighNumber = -1   // an identifier in the high-tag-number form, which no element the walk names uses
)

// commonName is the contents of the DER OBJECT IDENTIFIER 2.5.4.3, id-at-commonName.
var commonName = []byte{0x55, 0x04, 0x03}

// element is one DER element: its identifier octet, or tagHighNumber, its whole encoding and its
// contents.
type element struct {
	tag           int
	raw, contents []byte
}

// derReader reads the elements of rest in turn. Each header must be X.690's distinguished encoding: a
// definite length in its shortest form, within rest.
type derReader struct {
	rest []byte
}

// atEnd reports whether every element has been read.
func (r *derReader) atEnd() bool { return len(r.rest) == 0 }

// next reads the next element, whatever its identifier, and reports whether its header reads.
func (r *derReader) next() (element, bool) {
	in := r.rest
	if len(in) == 0 {
		return element{}, false
	}
	tag, at := int(in[0]), 1
	if in[0]&0x1F == 0x1F {
		// The high-tag-number form: the tag number's octets run up to and including the first with its
		// top bit clear.
		for {
			if at == len(in) {
				return element{}, false
			}
			at++
			if in[at-1]&0x80 == 0 {
				break
			}
		}
		tag = tagHighNumber
	}
	if at == len(in) {
		return element{}, false
	}
	first := in[at]
	at++
	length := uint64(first)
	if first >= 0x80 {
		// The long form: first's low bits count the length octets, the first of them non-zero, and a
		// length under 0x80 belongs in the short form. A count of zero is the indefinite form; a count
		// over eight is a length past any input.
		count := int(first & 0x7F)
		if count == 0 || count > 8 || len(in)-at < count || in[at] == 0 {
			return element{}, false
		}
		length = 0
		for _, b := range in[at : at+count] {
			length = length<<8 | uint64(b)
		}
		at += count
		if length < 0x80 {
			return element{}, false
		}
	}
	if length > uint64(len(in)-at) {
		return element{}, false
	}
	end := at + int(length)
	r.rest = in[end:]
	return element{tag: tag, raw: in[:end], contents: in[at:end]}, true
}

// expect reads the next element, and reports whether its header reads and its identifier is tag.
func (r *derReader) expect(tag int) (element, bool) {
	e, ok := r.next()
	return e, ok && e.tag == tag
}

// only reads in as exactly one element with identifier tag, nothing after it.
func only(in []byte, tag int) (element, bool) {
	r := derReader{in}
	e, ok := r.expect(tag)
	return e, ok && r.atEnd()
}

// names is where a certificate's issuer and subject lie, as far as the walk could find them.
type names struct {
	issuer, subject       element
	hasIssuer, hasSubject bool
}

// certificateNames walks the DER certificate der to its TBSCertificate's issuer and subject, each
// element passed over checked by its header alone (the spec's step 1):
//
//	Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
//	TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature, issuer, validity,
//	                              subject, ... }
//
// The certificate is the whole of der. The issuer is found when the walk reaches it, whatever follows;
// the subject only when every field before it passes. What follows the TBSCertificate, and the subject,
// is not read.
func certificateNames(der []byte) names {
	var n names
	cert, ok := only(der, tagSequence)
	if !ok {
		return n
	}
	shell := derReader{cert.contents}
	tbs, ok := shell.expect(tagSequence)
	if !ok {
		return n
	}
	fields := derReader{tbs.contents}
	field, ok := fields.next()
	if ok && field.tag == tagVersion {
		field, ok = fields.next()
	}
	if !ok || field.tag != tagInteger {
		return n
	}
	if _, ok := fields.expect(tagSequence); !ok { // signature
		return n
	}
	if n.issuer, n.hasIssuer = fields.expect(tagSequence); !n.hasIssuer {
		return n
	}
	if _, ok := fields.expect(tagSequence); !ok { // validity
		return n
	}
	n.subject, n.hasSubject = fields.expect(tagSequence)
	return n
}

// serviceOfName returns the service the subject Name names: its one common name's text, by the spec's
// steps 2 to 4, or "" when it names none.
func serviceOfName(subject element) string {
	rdns := derReader{subject.contents}
	count := 0
	var svc string
	var readable bool
	for !rdns.atEnd() {
		set, ok := rdns.expect(tagSet)
		if !ok || len(set.contents) == 0 {
			return ""
		}
		attributes := derReader{set.contents}
		for !attributes.atEnd() {
			attr, ok := attributes.expect(tagSequence)
			if !ok {
				return ""
			}
			parts := derReader{attr.contents}
			oid, ok := parts.expect(tagOID)
			if !ok {
				return ""
			}
			value, ok := parts.next()
			if !ok || !parts.atEnd() {
				return ""
			}
			if bytes.Equal(oid.contents, commonName) {
				count++
				svc, readable = directoryText(value)
			}
		}
	}
	if count != 1 || !readable {
		return ""
	}
	return svc
}

// directoryText returns the text of value when it is a UTF8String of UTF-8 or a PrintableString of
// X.680's printable characters, and reports whether it is.
func directoryText(value element) (string, bool) {
	switch value.tag {
	case tagUTF8:
		return string(value.contents), utf8.Valid(value.contents)
	case tagPrintable:
		for _, b := range value.contents {
			if !printable(b) {
				return "", false
			}
		}
		return string(value.contents), true
	}
	return "", false
}

// printable reports whether b is one of X.680's PrintableString characters: letters, digits, space and
// '()+,-./:=?.
func printable(b byte) bool {
	switch {
	case 'A' <= b && b <= 'Z', 'a' <= b && b <= 'z', '0' <= b && b <= '9':
		return true
	}
	return bytes.IndexByte([]byte(" '()+,-./:=?"), b) >= 0
}

// issuerText returns the issuer Name as RFC 2253 text, or "" when it does not read as a Name or is
// empty. The walk has already held its header to DER; encoding/asn1 reads the rest.
func issuerText(issuer element) string {
	var name pkix.RDNSequence
	rest, err := asn1.Unmarshal(issuer.raw, &name)
	if err != nil || len(rest) != 0 || len(name) == 0 {
		return ""
	}
	return name.String()
}
