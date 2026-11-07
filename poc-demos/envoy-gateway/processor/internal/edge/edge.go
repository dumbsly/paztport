// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"errors"
	"io"
	"strings"
	"time"
	"unicode"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"

	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/material"
	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/routes"
)

// InstEnv is the environment variable the edge's instance is read from: the pod's name, which Kubernetes
// sets from the downward API.
const InstEnv = "POD_NAME"

// Outcome is what became of one request. Its text is the label metrics count requests by.
type Outcome string

// The outcomes of a request.
const (
	// Stamped is a request the edge stamped and let go on.
	Stamped Outcome = "stamped"
	// RefusedRoute is a request whose route the edge could not name, or does not stamp for.
	RefusedRoute Outcome = "refused_route"
	// RefusedMaterial is a request refused because the edge's policy material has expired.
	RefusedMaterial Outcome = "refused_material"
	// RefusedBody is a request whose body the edge could not stamp whole: over the limit, or ending in
	// trailers.
	RefusedBody Outcome = "refused_body"
	// RefusedError is a request refused for anything else: a stream that is not one buffered request, no
	// single :method or :path, or a request the SDK would not stamp.
	RefusedError Outcome = "refused_error"
	// Abandoned is a request whose stream ended before the edge decided it. The edge cannot tell whether
	// the client went away, the body never arrived whole, or Envoy stopped waiting for the edge's answer.
	// It is not a refusal: the edge sent no answer that decides it.
	Abandoned Outcome = "abandoned"
)

// Observation is what the edge reports of one request, once it is decided.
type Observation struct {
	// Outcome is what became of the request.
	Outcome Outcome
	// StampDuration is how long stamping took, or 0 for a request not stamped.
	StampDuration time.Duration
	// BodyBytes is the size of the body received, whole or as far as it was read.
	BodyBytes int
	// RID is the rid of the request's stamp, or "" for a request not stamped.
	RID string
	// RequestID is Envoy's x-request-id for the request, or "" when the request's headers do not carry
	// exactly one, of 1 to 128 letters, digits and the marks - _ and .: Envoy's own is a UUID.
	RequestID string
}

// Config is what a [Processor] is built from.
type Config struct {
	// Material is the edge's policy material, loaded and checked. It is required.
	Material *material.Set
	// Inst is the instance the edge's stamps name: the pod's name, from [InstEnv]. It is required.
	Inst string
	// MaxBody is the most bytes of body the edge stamps; a longer one is refused. It is required.
	MaxBody int
	// Observe is told of each request once it is decided, or nil to tell nothing. It must be safe for
	// concurrent use: each stream calls it from its own goroutine.
	Observe func(Observation)
	// Now is the edge's clock, or nil for time.Now. It is what each stamp's time and the material's
	// readiness are judged by.
	Now func() time.Time
}

// Processor is the edge's external processor: Envoy's ext_proc filter streams each request to it, and it
// stamps the request as the origin service edge, for the receiver its HTTPRoute maps to, or refuses it.
// It is safe for concurrent use, one stream per request.
type Processor struct {
	set     *material.Set
	caller  *paztporthttp.Caller
	maxBody int
	now     func() time.Time
	observe func(Observation)
}

// New returns a processor over cfg. It refuses a config with no material, a blank instance or a body
// limit below one byte.
func New(cfg Config) (*Processor, error) {
	switch {
	case cfg.Material == nil:
		return nil, errors.New("edge: no policy material")
	case strings.TrimFunc(cfg.Inst, unicode.IsSpace) == "":
		return nil, errors.New("edge: the instance is blank")
	case cfg.MaxBody < 1:
		return nil, errors.New("edge: the body limit is below one byte")
	}
	p := &Processor{set: cfg.Material, maxBody: cfg.MaxBody, now: cfg.Now, observe: cfg.Observe}
	if p.now == nil {
		p.now = time.Now
	}
	if p.observe == nil {
		p.observe = func(Observation) {}
	}
	p.caller = &paztporthttp.Caller{
		Stamper: &stamp.Stamper{
			Svc: material.Service, Inst: cfg.Inst, Key: cfg.Material.Key(), Origin: true,
			NewRID: NewRID, Now: func() int64 { return p.now().UnixMilli() },
		},
		Bundle: cfg.Material.Bundle(),
	}
	return p, nil
}

// Process serves one ext_proc stream: one request and its response.
//
// The filter must send the request headers, with the attribute xds.route_metadata, and buffer the request
// body (processing mode request body Buffered), which Envoy reports in the first message's protocol
// configuration. Then Envoy holds the request headers until the body is answered, and sends the body
// whole, in one message, once it has all of it. The one exception is a request that ends in trailers with
// no body: with request trailers skipped, Envoy lets it on when the trailers arrive, without asking. So
// the filter must also allow mode overrides, which the processor uses to have those trailers sent to it.
//
// At the request headers, Process names the receiver from the route metadata alone (see
// [routes.FromAttributes]) and refuses a route its routes do not map. When the headers end the stream it
// stamps there. Otherwise it answers them with no stamp, only removing every Paztport header the client
// sent, so that a request Envoy lets on unanswered carries none and its receiver refuses it as unstamped,
// and with a mode override that sends the request's trailers; then it waits for the message that ends the
// stream, answers no body message before that one, and stamps over the whole body. The stamp's answer
// removes every Paztport header the request carries but the ones it sets, and sets each of those,
// replacing every value.
//
// Process refuses, with Envoy's immediate response, its own status and a plain-text body, and never a
// Paztport refusal: 403 for a route it does not stamp for, 413 for a body over the limit, and 500 for
// anything else: route metadata it cannot read, material that has expired, a request that ends in
// trailers, a stream that is not one buffered request, or a request the SDK would not stamp. It never
// lets a request go on without the stamp. A body that never ends is never answered: Envoy v1.40.2 starts
// no message timer while it buffers a body, so the stream's end decides the request abandoned.
//
// At the response headers and trailers, it removes every Paztport header; it passes the response body as
// it is. Response headers that arrive before the stamp are passed on in the same way: while Envoy honours
// the mode override they are Envoy's own local reply, such as its 413 for a body over its buffer limit,
// and the request never went on (see [request.localReply] for what they are otherwise).
func (p *Processor) Process(stream extprocv3.ExternalProcessor_ProcessServer) error {
	r := &request{p: p}
	for {
		msg, err := stream.Recv()
		if err != nil {
			r.ended()
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		resp, done := r.handle(msg)
		if resp != nil {
			if err := stream.Send(resp); err != nil {
				r.ended()
				return err
			}
		}
		if done {
			return nil
		}
	}
}

// phase is where a request's stream has reached.
type phase int

const (
	awaitingHeaders phase = iota // nothing received yet
	awaitingBody                 // headers answered; waiting for the message that ends the stream
	passed                       // stamped and let go on; the response may follow
	localReply                   // Envoy answered the request itself, before it was stamped; its reply follows
)

// request is one stream's state.
type request struct {
	p        *Processor
	phase    phase
	decided  bool
	method   string
	target   string
	receiver string
	paztport []string // the Paztport header names the client sent, in lower case, each once
	body     []byte
	id       string // Envoy's x-request-id, or ""
}

// handle answers one message, and reports whether the stream is over for the processor.
func (r *request) handle(msg *extprocv3.ProcessingRequest) (*extprocv3.ProcessingResponse, bool) {
	switch m := msg.GetRequest().(type) {
	case *extprocv3.ProcessingRequest_RequestHeaders:
		if r.phase != awaitingHeaders {
			return r.refuse(RefusedError, refusedOther)
		}
		return r.requestHeaders(msg, m.RequestHeaders)
	case *extprocv3.ProcessingRequest_RequestBody:
		if r.phase != awaitingBody {
			return r.refuse(RefusedError, refusedOther)
		}
		return r.requestBody(m.RequestBody)
	case *extprocv3.ProcessingRequest_RequestTrailers:
		if r.phase != awaitingBody {
			return r.refuse(RefusedError, refusedOther)
		}
		// The answer to trailers can no longer set the request's headers.
		return r.refuse(RefusedBody, refusedOther)
	case *extprocv3.ProcessingRequest_ResponseHeaders:
		if r.phase != passed {
			r.localReply(m.ResponseHeaders.GetHeaders())
		}
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseHeaders{
			ResponseHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{
				HeaderMutation: removeOnly(paztportNames(m.ResponseHeaders.GetHeaders())),
			}},
		}}, false
	case *extprocv3.ProcessingRequest_ResponseBody:
		if r.phase != passed && r.phase != localReply {
			return r.refuse(RefusedError, refusedOther)
		}
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseBody{
			ResponseBody: &extprocv3.BodyResponse{},
		}}, false
	case *extprocv3.ProcessingRequest_ResponseTrailers:
		if r.phase != passed && r.phase != localReply {
			return r.refuse(RefusedError, refusedOther)
		}
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ResponseTrailers{
			ResponseTrailers: &extprocv3.TrailersResponse{
				HeaderMutation: removeOnly(paztportNames(m.ResponseTrailers.GetTrailers())),
			},
		}}, false
	default:
		return r.refuse(RefusedError, refusedOther)
	}
}

// localReply takes response headers that arrive before the request was stamped. While Envoy honours the
// processor's mode override and the body mode Buffered, they can only be Envoy's own local reply: until the
// processor answers, Envoy holds the request's headers back from the router, so no upstream has the
// request. Envoy sends such a reply here when it refuses a body over its buffer limit (413) while the body
// is awaited, and, before the request's headers were ever sent, when a filter ahead of ext_proc refused the
// request (Envoy Gateway places its security filters and its request buffer there). The reply is passed on,
// with its Paztport headers removed, rather than replaced with the processor's 500; a request whose body was
// awaited is decided refused, for its body when the reply is a 413.
//
// Were Envoy to ignore the mode override (a filter that does not allow overrides), a request of headers and
// trailers with no body would go on without the stamp and with its Paztport headers removed, so its
// receiver refuses it as unstamped; that refusal's headers then arrive here while the body is awaited, and
// the request is decided refused for an error. It still never reaches a receiver stamped.
func (r *request) localReply(hs *corev3.HeaderMap) {
	if r.phase == awaitingBody {
		outcome := RefusedError
		if s, ok := only(hs, ":status"); ok && s == "413" {
			outcome = RefusedBody
		}
		r.decide(Observation{Outcome: outcome, BodyBytes: len(r.body)})
	}
	r.phase = localReply
}

// only returns the value of the header name, which must be in lower case, when hs carry it exactly once, in
// any case. Envoy sends each header's value in raw_value, and that alone is read.
func only(hs *corev3.HeaderMap, name string) (string, bool) {
	var value string
	n := 0
	for _, h := range hs.GetHeaders() {
		if lowerASCII(h.GetKey()) == name {
			value = string(h.GetRawValue())
			n++
		}
	}
	if n != 1 {
		return "", false
	}
	return value, true
}

// requestHeaders answers the request's headers: it refuses the request, stamps it when the headers end
// the stream, or else strips the client's Paztport headers and waits for the body.
func (r *request) requestHeaders(
	msg *extprocv3.ProcessingRequest, h *extprocv3.HttpHeaders,
) (*extprocv3.ProcessingResponse, bool) {
	r.id = requestID(h.GetHeaders())
	// Only a buffered body holds the headers until the body is answered: under any other mode they would
	// go on unstamped once answered here.
	if msg.GetProtocolConfig().GetRequestBodyMode() != extprocfilterv3.ProcessingMode_BUFFERED {
		return r.refuse(RefusedError, refusedOther)
	}
	ns, name, err := routes.FromAttributes(msg.GetAttributes())
	if err != nil {
		return r.refuse(RefusedRoute, refusedOther)
	}
	rcv, ok := r.p.set.Routes().Receiver(ns, name)
	if !ok {
		return r.refuse(RefusedRoute, refusedRoute)
	}
	method, target, ok := methodAndTarget(h.GetHeaders())
	if !ok {
		return r.refuse(RefusedError, refusedOther)
	}
	r.method, r.target, r.receiver = method, target, rcv
	r.paztport = paztportNames(h.GetHeaders())
	if h.GetEndOfStream() {
		return r.stamp(func(m *extprocv3.HeaderMutation) *extprocv3.ProcessingResponse {
			return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestHeaders{
				RequestHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{HeaderMutation: m}},
			}}
		})
	}
	// No stamp yet; but the client's Paztport headers go now, so that if Envoy ever lets these headers
	// on without the body's answer they carry no Paztport header at all. And the answer asks for the
	// request's trailers: a request that ends in trailers with no body is then sent here, and refused,
	// where with trailers skipped Envoy would let it on unasked.
	r.phase = awaitingBody
	return &extprocv3.ProcessingResponse{
		Response: &extprocv3.ProcessingResponse_RequestHeaders{
			RequestHeaders: &extprocv3.HeadersResponse{Response: &extprocv3.CommonResponse{
				HeaderMutation: removeOnly(r.paztport),
			}},
		},
		ModeOverride: sendTrailers,
	}, false
}

// sendTrailers is the processing mode the answer to headers a body follows sets for the rest of the
// request: request trailers sent, and every other mode as the processor expects it. Envoy v1.40.2 applies
// a mode_override before it handles the headers answer it comes with, when the filter allows overrides
// (ext_proc.cc:1900-1922), and takes both body modes from the override as given, the header and trailer
// modes only when not DEFAULT (ext_proc.cc:1759-1778); so the body modes are restated here.
var sendTrailers = &extprocfilterv3.ProcessingMode{
	RequestTrailerMode: extprocfilterv3.ProcessingMode_SEND,
	RequestBodyMode:    extprocfilterv3.ProcessingMode_BUFFERED,
	ResponseHeaderMode: extprocfilterv3.ProcessingMode_SEND,
	ResponseBodyMode:   extprocfilterv3.ProcessingMode_NONE,
}

// requestBody takes one body message: it refuses a body over the limit, stamps at the message that ends
// the stream, and answers no other.
func (r *request) requestBody(b *extprocv3.HttpBody) (*extprocv3.ProcessingResponse, bool) {
	if len(r.body)+len(b.GetBody()) > r.p.maxBody {
		r.body = append(r.body, b.GetBody()...)
		return r.refuse(RefusedBody, refusedLarge)
	}
	r.body = append(r.body, b.GetBody()...)
	if !b.GetEndOfStream() {
		return nil, false
	}
	return r.stamp(func(m *extprocv3.HeaderMutation) *extprocv3.ProcessingResponse {
		return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_RequestBody{
			RequestBody: &extprocv3.BodyResponse{Response: &extprocv3.CommonResponse{HeaderMutation: m}},
		}}
	})
}

// stamp stamps the whole request and answers with answer's response, carrying the stamp's header
// mutation, or refuses it.
func (r *request) stamp(
	answer func(*extprocv3.HeaderMutation) *extprocv3.ProcessingResponse,
) (*extprocv3.ProcessingResponse, bool) {
	if r.p.set.Ready(r.p.now().UnixMilli()) != nil {
		return r.refuse(RefusedMaterial, refusedOther)
	}
	start := time.Now()
	out, err := r.p.caller.Stamp(r.method, r.target, r.receiver, r.body, nil, nil)
	took := time.Since(start)
	if err != nil {
		return r.refuse(RefusedError, refusedOther)
	}
	m := &extprocv3.HeaderMutation{}
	set := make(map[string]bool, len(out.Headers))
	for _, h := range out.Headers {
		name := lowerASCII(h.Name)
		set[name] = true
		m.SetHeaders = append(m.SetHeaders, &corev3.HeaderValueOption{
			Header:       &corev3.HeaderValue{Key: name, RawValue: []byte(h.Value)},
			AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
		})
	}
	for _, name := range r.paztport {
		if !set[name] {
			m.RemoveHeaders = append(m.RemoveHeaders, name)
		}
	}
	r.phase = passed
	var rid string
	if n := len(out.Sent); n > 0 {
		rid = out.Sent[n-1].RID
	}
	r.decide(Observation{Outcome: Stamped, StampDuration: took, BodyBytes: len(r.body), RID: rid})
	return answer(m), false
}

// The processor's own refusals: a status, and a plain-text body that names nothing of Paztport's.
var (
	refusedRoute = refusal{typev3.StatusCode_Forbidden, "The edge does not serve this route.\n"}
	refusedLarge = refusal{typev3.StatusCode_PayloadTooLarge, "The request body is too large.\n"}
	refusedOther = refusal{typev3.StatusCode_InternalServerError, "The edge could not stamp this request.\n"}
)

// refusal is one of the processor's own refusals.
type refusal struct {
	code typev3.StatusCode
	text string
}

// refuse decides the request refused for outcome, if it is not yet decided, and answers with Envoy's
// immediate response carrying ref's status and text; the stream is then over for the processor.
func (r *request) refuse(outcome Outcome, ref refusal) (*extprocv3.ProcessingResponse, bool) {
	r.decide(Observation{Outcome: outcome, BodyBytes: len(r.body)})
	return &extprocv3.ProcessingResponse{Response: &extprocv3.ProcessingResponse_ImmediateResponse{
		ImmediateResponse: &extprocv3.ImmediateResponse{
			Status: &typev3.HttpStatus{Code: ref.code},
			Headers: &extprocv3.HeaderMutation{SetHeaders: []*corev3.HeaderValueOption{{
				Header:       &corev3.HeaderValue{Key: "content-type", RawValue: []byte("text/plain; charset=utf-8")},
				AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
			}}},
			Body:    []byte(ref.text),
			Details: "paztport_edge_" + string(outcome),
		},
	}}, true
}

// ended decides a request whose stream ended before it was decided, after the headers were answered, as
// abandoned: the edge sent no answer that decides it, and cannot tell why the stream ended. A stream that ended before any
// message carried no request.
func (r *request) ended() {
	if r.phase == awaitingBody {
		r.decide(Observation{Outcome: Abandoned, BodyBytes: len(r.body)})
	}
}

// decide reports the request's observation, with Envoy's x-request-id, the first time only.
func (r *request) decide(o Observation) {
	if !r.decided {
		r.decided = true
		o.RequestID = r.id
		r.p.observe(o)
	}
}

// maxRequestID is the longest x-request-id the edge reports. Envoy's own is a UUID, of 36.
const maxRequestID = 128

// requestID returns the request's x-request-id when hs carry exactly one, of 1 to [maxRequestID] letters,
// digits and the marks - _ and ., and "" otherwise. Envoy sets it, as a UUID; the form is checked all the
// same, since it is logged.
func requestID(hs *corev3.HeaderMap) string {
	id, ok := only(hs, "x-request-id")
	if !ok || len(id) == 0 || len(id) > maxRequestID {
		return ""
	}
	for _, c := range []byte(id) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_' ||
			c == '.') {
			return ""
		}
	}
	return id
}

// methodAndTarget returns the request's :method and :path, each of which must appear once, not empty.
func methodAndTarget(hs *corev3.HeaderMap) (method, target string, ok bool) {
	method, okMethod := only(hs, ":method")
	target, okTarget := only(hs, ":path")
	if !okMethod || !okTarget || method == "" || target == "" {
		return "", "", false
	}
	return method, target, true
}

// paztportNames returns the names in hs that [wire.IsPaztport] names, in lower case, each once, in the
// order they first appear.
func paztportNames(hs *corev3.HeaderMap) []string {
	var names []string
	seen := make(map[string]bool)
	for _, h := range hs.GetHeaders() {
		if !wire.IsPaztport(h.GetKey()) {
			continue
		}
		name := lowerASCII(h.GetKey())
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

// removeOnly returns a mutation that removes names, every value of each, or nil when there are none.
func removeOnly(names []string) *extprocv3.HeaderMutation {
	if len(names) == 0 {
		return nil
	}
	return &extprocv3.HeaderMutation{RemoveHeaders: names}
}

// lowerASCII returns s with its ASCII letters A to Z in lower case, and every other byte as it is, as
// Envoy lower-cases a header name.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
