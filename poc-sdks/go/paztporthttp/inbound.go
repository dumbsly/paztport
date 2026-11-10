// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// InboundRequest is one request as a receiver reads it, taken from whatever server received it.
type InboundRequest struct {
	// Method is the request method, as sent.
	Method string
	// Target is the request target exactly as sent, in origin form: the raw path, then "?" and the raw
	// query when there is one, with nothing decoded, re-encoded or normalised, since the binding is over
	// what was sent (net/http: Request.RequestURI; a gateway's external processor: the :path header). It
	// is never one rebuilt from a parsed URL.
	Target string
	// Chain, Proof, Influence and Session are the values of the X-Path-* headers of those names, each as
	// received, or "" when the header is absent. A repeated header's first value is the one Paztport
	// reads; NewInboundRequest takes it.
	Chain, Proof, Influence, Session string
	// Body is the body, whole. The receiver binds it as given and never changes it. An adapter that
	// cannot hold the body whole, such as one that would have to truncate it, must refuse the request
	// itself rather than pass on part of it.
	Body []byte
}

// NewInboundRequest returns the request with method, target and body whose X-Path-* headers header
// looks up: header returns every value of the header called name, in the order received, and none when
// it is absent. Each header's first value is taken. The lookup is the adapter's, and so is matching names
// in any case; the Values method of net/http's Header is one as it stands. A nil header gives no headers.
func NewInboundRequest(method, target string, body []byte, header func(name string) []string) InboundRequest {
	first := func(name string) string {
		if header == nil {
			return ""
		}
		if vs := header(name); len(vs) > 0 {
			return vs[0]
		}
		return ""
	}
	return InboundRequest{
		Method:    method,
		Target:    target,
		Chain:     first(wire.Chain),
		Proof:     first(wire.Proof),
		Influence: first(wire.Influence),
		Session:   first(wire.Session),
		Body:      body,
	}
}

// requestInput reads req's chain and returns the live order's input for req at the service named
// receiver, with the chain it read, or nil when there is none or it does not read. The input is the
// spec's for a request at its receiver: receiver in the route, the expected binding req's own (none when
// it has none, which never matches), the tokens of its headers (an absent header none), the nonce key
// <rid>|<last svc>|<last rcv>|req from the chain (none when it does not read, which the verifier refuses
// first) and peer. Where the chain names a keyed operation, the receiver completes the input in readKey:
// the nonce key becomes <rid>|<last svc>|<last rcv>|<key value>|req, or, where the target gives no key
// value, the receiver is the service alone. The verifier reads the chain again for itself, as it must.
func requestInput(req InboundRequest, receiver string, peer *verify.Peer) (verify.Input, stamp.Chain) {
	in := verify.Input{Receiver: receiver, ReceiverInRoute: true, Peer: peer}
	if bind, err := wire.Bind(req.Method, req.Target, req.Body); err == nil {
		in.ExpectedBind = &bind
	}
	in.Proof = token(req.Proof)
	in.Influence = token(req.Influence)
	in.Chain = token(req.Chain)
	if in.Chain == nil {
		return in, nil
	}
	chain, code := stamp.ReadChain(*in.Chain)
	if code != reason.OK {
		return in, nil
	}
	last := chain[len(chain)-1]
	key := chain[0].RID + "|" + last.Svc + "|" + last.Rcv + "|req"
	in.NonceKey = &key
	return in, chain
}

// token returns the token a header value holds, or nil when the header is absent.
func token(header string) *string {
	if tok, ok := wire.HeaderValue(header); ok {
		return &tok
	}
	return nil
}

// readInfluence returns the entries of an X-Path-Influence header value, none when it is absent, and
// whether it reads. Influence that does not read must never be dropped.
func readInfluence(header string) ([]influence.Entry, bool) {
	tok := token(header)
	if tok == nil {
		return nil, true
	}
	es, err := influence.ReadEntries(*tok)
	return es, err == nil
}
