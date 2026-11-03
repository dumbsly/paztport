// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"context"
	"errors"
	"strings"
	"unicode"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// Receivers maps the host a call is sent to onto the receiver's policy name, where the host is not the
// name: an address, a load balancer's name, or a name inside another network. The name a call's stamp
// is addressed to is the deployment's configuration, never something the request or the destination
// says, so it is kept in a table the operator writes. Build one with [NewReceivers], which keeps each
// host with its ASCII letters in lower case, as [Receivers.Name] looks it up; the zero Receivers maps
// nothing. A host holding a byte outside ASCII has no name. A Receivers never changes once built.
type Receivers struct {
	byHost map[string]string // each host, its ASCII letters in lower case, to its policy name
}

// NewReceivers returns the mapping byHost gives, host to policy name, as its own copy. It refuses a
// blank host or name; a host that [Receivers.Name] could never match, one with a port, a colon outside
// an IPv6 address's brackets, or a byte outside ASCII; and two hosts that differ only in the case of
// their ASCII letters, since a host is matched in any case.
func NewReceivers(byHost map[string]string) (Receivers, error) {
	r := make(map[string]string, len(byHost))
	for host, name := range byHost {
		if blank(host) || blank(name) {
			return Receivers{}, errors.New("paztport http: a receiver's host and policy name must not be blank")
		}
		if !isASCII(host) {
			return Receivers{}, errors.New("paztport http: a receiver host must be ASCII")
		}
		if hostOf(host) != host {
			return Receivers{}, errors.New("paztport http: a receiver host must be a host alone, with no port")
		}
		key := lowerASCII(host)
		if _, dup := r[key]; dup {
			return Receivers{}, errors.New("paztport http: a receiver host is listed twice, in different cases")
		}
		r[key] = name
	}
	return Receivers{byHost: r}, nil
}

// blank reports whether s is empty or only white space.
func blank(s string) bool {
	return strings.TrimFunc(s, unicode.IsSpace) == ""
}

// isASCII reports whether every byte of s is below 0x80.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// lowerASCII returns s with its ASCII letters A to Z in lower case, and every other byte as it is.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// Name returns the receiver's policy name for a call to host, which may carry a port, and whether the
// host has one. A host holding a byte outside ASCII has no name, mapped or not, and the call is not
// stamped. Otherwise the name is the one the host is mapped to or, when it is mapped to none, the host
// itself with its ASCII letters in lower case. The port is ignored, and the host matched in any case, as
// DNS matches it, but otherwise exactly: an IPv6 address keeps its brackets ("[::1]:8443" is the host
// "[::1]") and a trailing dot is kept, so "orders." is not "orders". The name is also the call's target:
// its response must be stamped by it, and what the response adds to the influence comes from
// "http:<name>".
func (r Receivers) Name(host string) (string, bool) {
	host = hostOf(host)
	if !isASCII(host) {
		return "", false
	}
	host = lowerASCII(host)
	if name, ok := r.byHost[host]; ok {
		return name, true
	}
	return host, true
}

// hostOf returns hostport without its port: up to and including the closing bracket of an IPv6 address,
// and otherwise up to the first colon.
func hostOf(hostport string) string {
	if strings.HasPrefix(hostport, "[") {
		if end := strings.IndexByte(hostport, ']'); end >= 0 {
			return hostport[:end+1]
		}
		return hostport
	}
	host, _, _ := strings.Cut(hostport, ":")
	return host
}

// Caller is one service's caller over HTTP. It stamps each call the service makes, with [Caller.Stamp],
// and checks each response against the chain it sent, with [Caller.Check]. An adapter sets the headers
// Stamp returns on the call, sends it, reads the response whole, and hands it to Check before anything
// reads it.
//
// A Caller never changes itself, so it is safe for concurrent use when its Stamper and Verifier are.
type Caller struct {
	// Stamper is this service's stamper. Its Svc is the caller's own name, which every response stamp
	// must be addressed to. It is required.
	Stamper *stamp.Stamper
	// Bundle is this service's proof bundle; a call whose route it holds no proof for is sent without
	// one.
	Bundle policy.ProofBundle
	// Verifier is this service's verifier, pinned to its own policy material, or nil for a service that
	// holds none: it checks no response, so every response counts as one local-untrusted entry.
	Verifier *verify.Verifier
}

// Outbound is one call, stamped: the headers to send with it and what was stamped, which [Caller.Check]
// checks its response against.
type Outbound struct {
	// Headers are the headers to set on the call, in order: X-Path-Chain, then X-Path-Proof when the
	// bundle holds a proof for the route, then X-Path-Influence when the call was made under influence.
	// The adapter first removes every header the request carries that [wire.IsPaztport] names, all values,
	// then sets each one of these, replacing and never appending. A gateway's external processor also
	// removes every such header from the response it passes back.
	Headers []wire.Header
	// Sent is the chain sent, ending in this call's stamp, whose rcv is the receiver's policy name: the
	// response's target.
	Sent stamp.Chain
	// Proof is the proof sent with it, or nil for none.
	Proof *policy.Proof
}

// Received is what a response contributes to the request that made the call.
type Received struct {
	// Check is the check of the response's attestation, or nil when the caller has no verifier and
	// nothing was checked.
	Check *wire.ResponseCheck
	// Entries are the influence entries the response adds: one for each label of a response that
	// verified, so none for one that verified with no labels, and for any other response exactly one
	// local-untrusted entry. The embedder adds them to its request's influence.
	Entries []influence.Entry
}

// Stamp stamps a call to receiver, the receiver's policy name, after the chain inbound and committing
// to the influence infl that shaped it, and returns the headers to send it with. method and target are
// the request's as sent: target is the request target in origin form, the raw path, then "?" and the raw
// query, exactly as the transport writes it on the wire (for net/http's client, req.URL.RequestURI(); for
// a gateway's external processor, the :path header), never one received and then rebuilt from a parsed
// URL. body is the body, whole.
//
// inbound is the chain the request being served carried, nil where there is none; an origin starts a new
// chain and ignores it, and any other service needs it. infl is the influence so far, nil for none.
// Neither is changed.
//
// A gateway's external processor, an origin that stamps the requests it lets in, calls Stamp with
// inbound and infl nil: the headers are then X-Path-Chain, holding the one origin stamp, and X-Path-Proof
// when the bundle holds the route's proof. Whoever sends the call first removes every header the request
// carries that [wire.IsPaztport] names, all values, then sets each header Stamp returns, replacing and
// never appending; a gateway's external processor also removes them from the response it passes back.
//
// Stamp refuses a method or target that is not valid UTF-8, which has no binding (see [wire.Bind]), and
// whatever the stamper refuses.
func (c *Caller) Stamp(
	method, target, receiver string, body []byte, inbound stamp.Chain, infl []influence.Entry,
) (Outbound, error) {
	bind, err := wire.Bind(method, target, body)
	if err != nil {
		return Outbound{}, err
	}
	chain, proof, err := c.Stamper.Next(inbound, receiver, bind, infl, c.Bundle)
	if err != nil {
		return Outbound{}, err
	}
	chainTok, err := wire.EncodeChain(chain)
	if err != nil {
		return Outbound{}, err
	}
	headers := []wire.Header{{Name: wire.Chain, Value: chainTok}}
	if proof != nil {
		proofTok, err := wire.EncodeProof(*proof)
		if err != nil {
			return Outbound{}, err
		}
		headers = append(headers, wire.Header{Name: wire.Proof, Value: proofTok})
	}
	inflTok, err := wire.EncodeInfluence(infl)
	if err != nil {
		return Outbound{}, err
	}
	if inflTok != "" {
		headers = append(headers, wire.Header{Name: wire.Influence, Value: inflTok})
	}
	return Outbound{Headers: headers, Sent: chain, Proof: proof}, nil
}

// Check checks the response to the call o, with responseHeader, the X-Path-Response header's first value
// as received, "" when it is absent, status, and body whole, and returns what it contributes. With a
// verifier it runs [wire.CheckResponse] on the chain and proof o sent, as received by this service: a
// response that verifies adds one entry for each of its labels, with src "http:<receiver>", where the
// receiver is the rcv of o's last stamp, and h its result hash. Any other response, unattested, failing
// or a refusal, and any response to a caller with no verifier, adds exactly one local-untrusted entry with
// the same src and h, so content nobody vouched for still counts against later calls.
//
// ctx reaches only the verifier's nonce cache. The error is the cache's, when it could not answer, and
// comes with the zero Received; the response then counts for nothing it can vouch for, and the embedder
// fails the call.
func (c *Caller) Check(
	ctx context.Context, o Outbound, responseHeader string, status int, body []byte,
) (Received, error) {
	var receiver string
	if len(o.Sent) > 0 {
		receiver = o.Sent[len(o.Sent)-1].Rcv
	}
	src := "http:" + receiver
	if c.Verifier == nil {
		return Received{Entries: untrusted(src, wire.ResultHash(status, body))}, nil
	}
	rc, err := wire.CheckResponse(ctx, c.Verifier, o.Sent, o.Proof, responseHeader, status, body, c.Stamper.Svc)
	if err != nil {
		return Received{}, err
	}
	if !rc.Result.OK() {
		return Received{Check: &rc, Entries: untrusted(src, rc.ResultHash)}, nil
	}
	es := make([]influence.Entry, len(rc.Labels))
	for i, l := range rc.Labels {
		es[i] = l.Entry(src, rc.ResultHash)
	}
	return Received{Check: &rc, Entries: es}, nil
}

// untrusted returns the one entry a response nobody vouched for adds.
func untrusted(src, h string) []influence.Entry {
	return []influence.Entry{{Class: influence.LocalUntrusted, Src: src, H: h}}
}
