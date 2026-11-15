// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
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
	// Chain, Proof, Extensions and Session are the values of the X-Path-Chain, X-Path-Proof, X-Path-Extensions
	// and X-Path-Session headers, each as received, or "" when the header is absent. A repeated header's first
	// value is the one Paztport reads; NewInboundRequest takes it. A value that is blank, nothing but HTTP's
	// optional whitespace, is read as no header, so a blank X-Path-Extensions is one empty block per stamp, as an
	// absent one is.
	Chain, Proof, Extensions, Session string
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
		Method:     method,
		Target:     target,
		Chain:      first(wire.Chain),
		Proof:      first(wire.Proof),
		Extensions: first(wire.Extensions),
		Session:    first(wire.Session),
		Body:       body,
	}
}

// requestInput reads req's chain and returns the live order's input for req at the service named
// receiver, with the chain it read, or nil when there is none or it does not read. The input is the
// spec's for a request at its receiver (verification.md, HTTP requests and responses): receiver in the route,
// the expected binding req's own (none when it has none, which never matches), the tokens of its headers (an
// absent header none: no blocks token is one empty block per stamp), the nonce key from the chain, the JCS text
// of [rid, last svc, last rcv, "req"] (none when the chain does not read, which the verifier refuses first), and
// peer. Where the chain names a keyed operation, the receiver completes the input in readKey: the key value joins
// the nonce key, or, where the target gives no key value, the receiver is the service alone. The verifier reads
// the chain again for itself, as it must.
func requestInput(req InboundRequest, receiver string, peer *verify.Peer) (verify.Input, stamp.Chain) {
	in := verify.Input{Receiver: receiver, ReceiverInRoute: true, Peer: peer}
	if bind, err := wire.Bind(req.Method, req.Target, req.Body); err == nil {
		in.ExpectedBind = &bind
	}
	in.Proof = token(req.Proof)
	in.Blocks = token(req.Extensions)
	in.Chain = token(req.Chain)
	if in.Chain == nil {
		return in, nil
	}
	chain, code := stamp.ReadChain(*in.Chain)
	if code != reason.OK {
		return in, nil
	}
	last := chain[len(chain)-1]
	key := wire.RequestNonceKey(chain[0].RID, last.Svc, last.Rcv, "")
	in.NonceKey = &key
	return in, chain
}

// carried returns the blocks a request whose chain read and is to be served carries on with chain: those its
// token holds, or one empty block per stamp where it has none (wire.md, Blocks). It returns false where they do
// not read as one block per stamp, which check 9a has already refused on every path that calls it.
func carried(chain stamp.Chain, tok *string) (stamp.Blocks, bool) {
	if tok == nil {
		return make(stamp.Blocks, len(chain)), true
	}
	bs, err := stamp.ReadBlocks(*tok)
	if err != nil || len(bs) != len(chain) {
		return nil, false
	}
	return bs, true
}

// token returns the token a header value holds, or nil when the header is absent.
func token(header string) *string {
	if tok, ok := wire.HeaderValue(header); ok {
		return &tok
	}
	return nil
}
