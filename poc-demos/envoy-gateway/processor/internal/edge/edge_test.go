// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package edge_test

import (
	"context"
	"errors"
	"io"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/edge"
	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/material/materialtest"
)

// now is the processor's clock in these tests: a second after the material was made.
const now = materialtest.Now + 1000

// header is one header as Envoy sends it to the processor.
type header struct{ name, value string }

// fakeStream is the processor's side of one ext_proc stream: Recv hands out the requests in turn, then
// end; Send records each response.
type fakeStream struct {
	grpc.ServerStream
	in  []*extprocv3.ProcessingRequest
	out []*extprocv3.ProcessingResponse
	end error
}

func (f *fakeStream) Context() context.Context { return context.Background() }

func (f *fakeStream) Recv() (*extprocv3.ProcessingRequest, error) {
	if len(f.in) == 0 {
		if f.end != nil {
			return nil, f.end
		}
		return nil, io.EOF
	}
	r := f.in[0]
	f.in = f.in[1:]
	return r, nil
}

func (f *fakeStream) Send(r *extprocv3.ProcessingResponse) error {
	f.out = append(f.out, r)
	return nil
}

// fixture is one processor over test material, with what it reports.
type fixture struct {
	m   *materialtest.Material
	p   *edge.Processor
	obs []edge.Observation
}

// newFixture returns a processor over new material, at the clock now, mapping the HTTPRoute shop/orders
// to orders, with a body limit of 1024 bytes.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{m: materialtest.New(t)}
	f.p = f.processor(t, func(c *edge.Config) {})
	return f
}

// processor returns a processor over f's material, with the config change applies to.
func (f *fixture) processor(t *testing.T, change func(*edge.Config)) *edge.Processor {
	t.Helper()
	cfg := edge.Config{
		Material: f.m.Load(t),
		Inst:     "edge-7f9c",
		MaxBody:  1024,
		Now:      func() time.Time { return time.UnixMilli(now) },
		Observe:  func(o edge.Observation) { f.obs = append(f.obs, o) },
	}
	change(&cfg)
	p, err := edge.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// run streams reqs to the processor, then end (io.EOF when nil), and returns its responses and what
// Process returned.
func (f *fixture) run(end error, reqs ...*extprocv3.ProcessingRequest) ([]*extprocv3.ProcessingResponse, error) {
	s := &fakeStream{in: reqs, end: end}
	err := f.p.Process(s)
	return s.out, err
}

// observed fails the test unless the processor reported exactly one request, with outcome want.
func (f *fixture) observed(t *testing.T, want edge.Outcome) edge.Observation {
	t.Helper()
	if len(f.obs) != 1 || f.obs[0].Outcome != want {
		t.Fatalf("observed %+v, want one %s", f.obs, want)
	}
	return f.obs[0]
}

// routeMetadata returns the xds.route_metadata attribute for the HTTPRoute ns/name, in the text form the
// captured fixture in the routes package shows, with no policies attached.
func routeMetadata(ns, name string) string {
	return `filter_metadata { key: "envoy-gateway" value { fields { key: "resources" value { list_value { ` +
		`values { struct_value { fields { key: "kind" value { string_value: "HTTPRoute" } } ` +
		`fields { key: "name" value { string_value: "` + name + `" } } ` +
		`fields { key: "namespace" value { string_value: "` + ns + `" } } } } } } } } } `
}

// attributes returns the ext_proc attributes with metadata as xds.route_metadata.
func attributes(metadata string) map[string]*structpb.Struct {
	return map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
		"xds.route_metadata": structpb.NewStringValue(metadata),
	}}}
}

// headerMap returns hs as Envoy sends them: each value in raw_value.
func headerMap(hs []header) *corev3.HeaderMap {
	m := &corev3.HeaderMap{}
	for _, h := range hs {
		m.Headers = append(m.Headers, &corev3.HeaderValue{Key: h.name, RawValue: []byte(h.value)})
	}
	return m
}

// requestHeaders returns the first message of a request to shop/orders in Buffered mode: its headers,
// with the route's metadata and the protocol configuration.
func requestHeaders(endOfStream bool, hs ...header) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: headerMap(hs), EndOfStream: endOfStream,
		}},
		Attributes: attributes(routeMetadata("shop", "orders")),
		ProtocolConfig: &extprocv3.ProtocolConfiguration{
			RequestBodyMode:  extprocfilterv3.ProcessingMode_BUFFERED,
			ResponseBodyMode: extprocfilterv3.ProcessingMode_NONE,
		},
	}
}

// requestBody returns a request_body message.
func requestBody(body string, endOfStream bool) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
		RequestBody: &extprocv3.HttpBody{Body: []byte(body), EndOfStream: endOfStream},
	}}
}

// responseHeaders returns a response_headers message.
func responseHeaders(hs ...header) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseHeaders{
		ResponseHeaders: &extprocv3.HttpHeaders{Headers: headerMap(hs)},
	}}
}

// get and post are the pseudo-headers of a GET and a POST to an orders path.
var (
	get  = []header{{":method", "GET"}, {":path", "/orders/7?x=%2F"}, {":authority", "shop.example"}, {":scheme", "https"}}
	post = []header{{":method", "POST"}, {":path", "/orders"}, {":authority", "shop.example"}, {":scheme", "https"}}
)

// with returns base followed by more, as a new slice.
func with(base []header, more ...header) []header {
	return slices.Concat(base, more)
}

// apply returns hs after m, as Envoy v1.39.1's ext_proc applies a header mutation: every value of each
// removed name, in any case, then each set header, replacing every value of its name. It fails the test on
// a set header that would append, or that carries its value anywhere but raw_value, which is where Envoy
// reads it.
func apply(t *testing.T, hs []header, m *extprocv3.HeaderMutation) []header {
	t.Helper()
	out := slices.Clone(hs)
	for _, name := range m.GetRemoveHeaders() {
		out = slices.DeleteFunc(out, func(h header) bool { return strings.EqualFold(h.name, name) })
	}
	for _, o := range m.GetSetHeaders() {
		//lint:ignore SA1019 Envoy v1.39.1's ext_proc decides append or replace by this field alone.
		appends := o.GetAppend()
		if appends != nil || o.GetAppendAction() != corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD {
			t.Fatalf("set header %q does not overwrite: append %v, action %v", o.GetHeader().GetKey(), appends, o.GetAppendAction())
		}
		if o.GetHeader().GetValue() != "" {
			t.Fatalf("set header %q carries its value in value, which Envoy ignores", o.GetHeader().GetKey())
		}
		name := o.GetHeader().GetKey()
		out = slices.DeleteFunc(out, func(h header) bool { return strings.EqualFold(h.name, name) })
		out = append(out, header{strings.ToLower(name), string(o.GetHeader().GetRawValue())})
	}
	return out
}

// values returns every value of the header name in hs, matching the name in any case.
func values(hs []header, name string) []string {
	var vs []string
	for _, h := range hs {
		if strings.EqualFold(h.name, name) {
			vs = append(vs, h.value)
		}
	}
	return vs
}

// paztportNames returns the names in hs that are Paztport's, in lower case.
func paztportNames(hs []header) []string {
	var names []string
	for _, h := range hs {
		if wire.IsPaztport(h.name) {
			names = append(names, strings.ToLower(h.name))
		}
	}
	return names
}

// unique returns names with each kept at its first place only.
func unique(names []string) []string {
	var out []string
	for _, n := range names {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// headersMutation returns the header mutation of a response that lets the request headers go on, and
// fails the test on any other response.
func headersMutation(t *testing.T, r *extprocv3.ProcessingResponse) *extprocv3.HeaderMutation {
	t.Helper()
	h, ok := r.GetResponse().(*extprocv3.ProcessingResponse_RequestHeaders)
	if !ok {
		t.Fatalf("response %v is not a request headers response", r)
	}
	common := h.RequestHeaders.GetResponse()
	if common.GetStatus() != extprocv3.CommonResponse_CONTINUE || common.GetBodyMutation() != nil {
		t.Fatalf("headers response %v does more than mutate headers", common)
	}
	return common.GetHeaderMutation()
}

// bodyMutation returns the header mutation of a response that lets the request body go on, and fails
// the test on any other response.
func bodyMutation(t *testing.T, r *extprocv3.ProcessingResponse) *extprocv3.HeaderMutation {
	t.Helper()
	b, ok := r.GetResponse().(*extprocv3.ProcessingResponse_RequestBody)
	if !ok {
		t.Fatalf("response %v is not a request body response", r)
	}
	common := b.RequestBody.GetResponse()
	if common.GetStatus() != extprocv3.CommonResponse_CONTINUE || common.GetBodyMutation() != nil {
		t.Fatalf("body response %v does more than mutate headers", common)
	}
	return common.GetHeaderMutation()
}

// waitsForTheBody fails the test unless r answers request headers by letting them go on, with no stamp
// and with every Paztport header in hs removed, and nothing else changed.
func waitsForTheBody(t *testing.T, r *extprocv3.ProcessingResponse, hs []header) {
	t.Helper()
	m := headersMutation(t, r)
	if m.GetSetHeaders() != nil {
		t.Fatalf("the headers answer sets %v before the body arrived", m.GetSetHeaders())
	}
	want := unique(paztportNames(hs))
	if got := m.GetRemoveHeaders(); !slices.Equal(got, want) && !(len(got) == 0 && len(want) == 0) {
		t.Fatalf("the headers answer removes %q, want %q", got, want)
	}
}

// refused fails the test unless out ends in the processor's own refusal with code, after nothing but the
// headers answer that waits for a body (when waited), and returns the refusal's body. The requests
// refused after waiting carry no Paztport header.
func refused(t *testing.T, out []*extprocv3.ProcessingResponse, waited bool, code typev3.StatusCode) string {
	t.Helper()
	want := 1
	if waited {
		want = 2
	}
	if len(out) != want {
		t.Fatalf("got %d responses, want %d: %v", len(out), want, out)
	}
	if waited {
		waitsForTheBody(t, out[0], nil)
	}
	ir := out[len(out)-1].GetImmediateResponse()
	if ir == nil {
		t.Fatalf("the last response %v is not a refusal", out[len(out)-1])
	}
	if ir.GetStatus().GetCode() != code {
		t.Fatalf("refused with %v, want %v", ir.GetStatus().GetCode(), code)
	}
	ct := ir.GetHeaders().GetSetHeaders()
	if len(ct) != 1 || ct[0].GetHeader().GetKey() != "content-type" ||
		string(ct[0].GetHeader().GetRawValue()) != "text/plain; charset=utf-8" {
		t.Fatalf("the refusal's headers are %v, want only a plain-text content type", ir.GetHeaders())
	}
	body := string(ir.GetBody())
	if body == "" || strings.ContainsAny(body, "{}") || strings.Contains(strings.ToLower(body), "reason") {
		t.Fatalf("the refusal's body %q is not the processor's own plain text", body)
	}
	for _, c := range refusalCodes {
		if strings.Contains(body, string(c)) {
			t.Fatalf("the refusal's body %q names the Paztport reason %s", body, c)
		}
	}
	return body
}

// refusalCodes are the reasons a Paztport receiver refuses with, none of which the processor's refusals
// name.
var refusalCodes = []reason.Code{
	reason.ChainMissing, reason.BadOrigin, reason.BadSignature, reason.BrokenLink, reason.Expired,
	reason.RIDMismatch, reason.BindingMismatch, reason.Replay, reason.PathNotAllowed, reason.SessionUnknown,
	reason.InfluenceMismatch, reason.PeerMismatch, reason.PolicyExpired,
}

// verifier returns the verifier orders would hold, pinned to m's keyring and root, at the clock now.
func verifier(t *testing.T, m *materialtest.Material) *verify.Verifier {
	t.Helper()
	cfg, err := verify.Pinned([]policy.KeyringFile{m.Keyring}, []policy.Root{m.Root}, m.Pin, verify.Config{
		AllowedOrigins: []string{"edge"},
		Nonces:         verify.NewMemoryNonceCache(verify.NonceTTLMs),
		Now:            func() int64 { return now },
		CallMaxAgeMs:   verify.CallMaxAgeMs,
		RunMaxAgeMs:    verify.RunMaxAgeMs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verify.New(cfg)
}

// acceptedByOrders reports whether orders, enforcing, accepts the request hs and body, as it reaches it,
// and the reason when it refuses.
func acceptedByOrders(t *testing.T, m *materialtest.Material, hs []header, body string) (bool, reason.Code) {
	t.Helper()
	method, path := values(hs, ":method"), values(hs, ":path")
	if len(method) != 1 || len(path) != 1 {
		t.Fatalf("the request reaching orders has :method %q and :path %q", method, path)
	}
	req := paztporthttp.NewInboundRequest(method[0], path[0], []byte(body), func(name string) []string {
		return values(hs, name)
	})
	r := &paztporthttp.Receiver{Name: "orders", Verifier: verifier(t, m)}
	a, err := r.Accept(t.Context(), req, &verify.Peer{Svc: "edge", Inst: "10.0.0.9"}, paztporthttp.ModeEnforce)
	if err != nil {
		t.Fatal(err)
	}
	if a.Refusal != nil {
		return false, a.Result.Reason
	}
	return a.Result.OK(), a.Result.Reason
}

// sentChain returns the chain the request hs carries to the backend.
func sentChain(t *testing.T, hs []header) stamp.Chain {
	t.Helper()
	vs := values(hs, wire.Chain)
	if len(vs) != 1 {
		t.Fatalf("the request carries %d chain headers", len(vs))
	}
	c, code := stamp.ReadChain(vs[0])
	if code != reason.OK {
		t.Fatalf("the chain does not read: %s", code)
	}
	return c
}

// TestStampsAHeadersOnlyRequestAtItsHeaders stamps a request whose headers end the stream in the answer
// to its headers, as the origin edge, for orders, over the empty body; orders accepts it.
func TestStampsAHeadersOnlyRequestAtItsHeaders(t *testing.T) {
	f := newFixture(t)
	out, err := f.run(nil, requestHeaders(true, get...))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d responses, want 1", len(out))
	}
	sent := apply(t, get, headersMutation(t, out[0]))
	if got := paztportNames(sent); !slices.Equal(got, []string{"x-path-chain", "x-path-proof"}) {
		t.Fatalf("the request carries the Paztport headers %q, want the chain then the proof", got)
	}
	c := sentChain(t, sent)
	s := c[0]
	if len(c) != 1 || s.Svc != "edge" || s.Inst != "edge-7f9c" || s.TS != now || s.Rcv != "orders" || s.Sess != "" || s.Prev != "" {
		t.Fatalf("the chain is %+v, want one origin stamp by edge for orders", c)
	}
	if ok, code := acceptedByOrders(t, f.m, sent, ""); !ok {
		t.Fatalf("orders refuses the stamped request: %s", code)
	}
	o := f.observed(t, edge.Stamped)
	if o.BodyBytes != 0 || o.StampDuration <= 0 {
		t.Fatalf("observed %+v, want no body and a stamp duration", o)
	}
}

// TestStampsABodyRequestOnceAtTheEndOfItsBody answers the headers of a request with a body without
// stamping them, waits for the body, and stamps once, in the answer to the message that ends the stream,
// binding the whole body: orders accepts it with that body and refuses it with any other.
func TestStampsABodyRequestOnceAtTheEndOfItsBody(t *testing.T) {
	f := newFixture(t)
	body := `{"item":"tea","qty":2}`
	out, err := f.run(nil, requestHeaders(false, post...), requestBody(body, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d responses, want 2", len(out))
	}
	waitsForTheBody(t, out[0], post)
	sent := apply(t, post, bodyMutation(t, out[1]))
	if ok, code := acceptedByOrders(t, f.m, sent, body); !ok {
		t.Fatalf("orders refuses the stamped request: %s", code)
	}
	if ok, code := acceptedByOrders(t, f.m, sent, `{"item":"tea","qty":20}`); ok || code != reason.BindingMismatch {
		t.Fatalf("orders, given another body, answers %t, %s, want BINDING_MISMATCH", ok, code)
	}
	if o := f.observed(t, edge.Stamped); o.BodyBytes != len(body) {
		t.Fatalf("observed a body of %d bytes, want %d", o.BodyBytes, len(body))
	}
}

// TestStampsABodyInChunksOnceOverTheWholeBody answers no chunk that does not end the stream, and stamps
// once, at the one that does, over every chunk in order.
func TestStampsABodyInChunksOnceOverTheWholeBody(t *testing.T) {
	f := newFixture(t)
	chunks := []string{`{"item":`, `"tea",`, `"qty":2}`}
	out, err := f.run(nil, requestHeaders(false, post...),
		requestBody(chunks[0], false), requestBody(chunks[1], false), requestBody(chunks[2], true))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d responses, want the headers answer and one stamp", len(out))
	}
	waitsForTheBody(t, out[0], post)
	sent := apply(t, post, bodyMutation(t, out[1]))
	whole := strings.Join(chunks, "")
	if ok, code := acceptedByOrders(t, f.m, sent, whole); !ok {
		t.Fatalf("orders refuses the request with the whole body: %s", code)
	}
	if ok, _ := acceptedByOrders(t, f.m, sent, chunks[2]); ok {
		t.Fatal("orders accepts the request with only the last chunk")
	}
	if o := f.observed(t, edge.Stamped); o.BodyBytes != len(whole) {
		t.Fatalf("observed a body of %d bytes, want %d", o.BodyBytes, len(whole))
	}
}

// TestNeverAnswersABodyThatNeverCompletes leaves a body whose stream never ends unanswered, so Envoy's
// message timeout refuses it, and reports it refused, whether the stream closes or is cancelled.
func TestNeverAnswersABodyThatNeverCompletes(t *testing.T) {
	for _, end := range []error{nil, status.Error(codes.Canceled, "context canceled")} {
		f := newFixture(t)
		out, err := f.run(end, requestHeaders(false, post...), requestBody(`{"item":`, false))
		if end != nil && !errors.Is(err, end) {
			t.Errorf("Process = %v, want %v", err, end)
		}
		if len(out) != 1 {
			t.Fatalf("got %d responses, want only the headers answer", len(out))
		}
		waitsForTheBody(t, out[0], post)
		f.observed(t, edge.RefusedBody)
	}
}

// TestRefusesARequestWithTrailers refuses a request whose stream ends in trailers, whose answer can no
// longer set the request's headers.
func TestRefusesARequestWithTrailers(t *testing.T) {
	f := newFixture(t)
	trailers := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestTrailers{
		RequestTrailers: &extprocv3.HttpTrailers{Trailers: headerMap([]header{{"grpc-status", "0"}})},
	}}
	out, err := f.run(nil, requestHeaders(false, post...), requestBody(`{}`, false), trailers)
	if err != nil {
		t.Fatal(err)
	}
	refused(t, out, true, typev3.StatusCode_InternalServerError)
	f.observed(t, edge.RefusedBody)
}

// requestTrailers returns a request_trailers message.
func requestTrailers() *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestTrailers{
		RequestTrailers: &extprocv3.HttpTrailers{Trailers: headerMap([]header{{"x-checksum", "1"}})},
	}}
}

// TestTheHeadersAnswerAsksForTrailers overrides the processing mode in the answer to headers a body
// follows: request trailers sent, the body still buffered, and the response modes as the processor
// expects them, so that Envoy sends a request that ends in trailers with no body to the processor. A
// request whose headers end the stream needs no override.
func TestTheHeadersAnswerAsksForTrailers(t *testing.T) {
	f := newFixture(t)
	out, err := f.run(nil, requestHeaders(false, post...))
	if err != nil || len(out) != 1 {
		t.Fatalf("Process = %v, with %d responses", err, len(out))
	}
	want := &extprocfilterv3.ProcessingMode{
		RequestTrailerMode: extprocfilterv3.ProcessingMode_SEND,
		RequestBodyMode:    extprocfilterv3.ProcessingMode_BUFFERED,
		ResponseHeaderMode: extprocfilterv3.ProcessingMode_SEND,
		ResponseBodyMode:   extprocfilterv3.ProcessingMode_NONE,
	}
	if got := out[0].GetModeOverride(); !proto.Equal(got, want) {
		t.Fatalf("mode_override = %v, want %v", got, want)
	}

	f = newFixture(t)
	out, err = f.run(nil, requestHeaders(true, get...))
	if err != nil || len(out) != 1 || out[0].GetModeOverride() != nil {
		t.Fatalf("a request with no body: Process = %v, responses %v", err, out)
	}
}

// TestRefusesTrailersAfterHeadersWithNoBody refuses a request that ends in trailers with no body, which
// the mode override makes Envoy send to the processor.
func TestRefusesTrailersAfterHeadersWithNoBody(t *testing.T) {
	f := newFixture(t)
	out, err := f.run(nil, requestHeaders(false, with(post, header{"x-path-chain", "forged"})...), requestTrailers())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("got %d responses, want the headers answer and a refusal", len(out))
	}
	waitsForTheBody(t, out[0], with(post, header{"x-path-chain", "forged"}))
	if ir := out[1].GetImmediateResponse(); ir.GetStatus().GetCode() != typev3.StatusCode_InternalServerError {
		t.Fatalf("the trailers' answer is %v, want the processor's 500", out[1])
	}
	refused(t, out[1:], false, typev3.StatusCode_InternalServerError)
	f.observed(t, edge.RefusedBody)
}

// TestStripsTheClientsPaztportHeaders removes every Paztport header the client sent, every value and in
// any case, but for the names the stamp sets, which it overwrites; other headers stay. It does so for a
// request with no body, one with a body, and one whose only header is a Paztport one.
func TestStripsTheClientsPaztportHeaders(t *testing.T) {
	client := []header{
		{"X-Path-Chain", "forged-1"}, {"x-path-chain", "forged-2"}, {"x-path-proof", "forged"},
		{"X-PATH-Anything", "a"}, {"x-path-anything", "b"}, {"X-Path-Influence", "i"}, {"x-path-session", "s"},
		{"x-pathology", "kept"}, {"x-path", "kept"}, {"accept", "application/json"},
	}
	check := func(t *testing.T, m *extprocv3.HeaderMutation, before []header) []header {
		t.Helper()
		if got := m.GetRemoveHeaders(); !slices.Equal(got, []string{"x-path-anything", "x-path-influence", "x-path-session"}) {
			t.Fatalf("remove_headers = %q, want each other Paztport name once, in lower case", got)
		}
		if got := m.GetSetHeaders(); len(got) != 2 || got[0].GetHeader().GetKey() != "x-path-chain" ||
			got[1].GetHeader().GetKey() != "x-path-proof" {
			t.Fatalf("set_headers = %v, want the chain then the proof", got)
		}
		sent := apply(t, before, m)
		if got := paztportNames(sent); !slices.Equal(got, []string{"x-path-chain", "x-path-proof"}) {
			t.Fatalf("the request carries the Paztport headers %q", got)
		}
		if vs := values(sent, "x-pathology"); !slices.Equal(vs, []string{"kept"}) {
			t.Fatalf("x-pathology is %q", vs)
		}
		if vs := values(sent, "x-path"); !slices.Equal(vs, []string{"kept"}) {
			t.Fatalf("x-path is %q", vs)
		}
		return sent
	}

	t.Run("no body", func(t *testing.T) {
		f := newFixture(t)
		hs := with(get, client...)
		out, err := f.run(nil, requestHeaders(true, hs...))
		if err != nil || len(out) != 1 {
			t.Fatalf("Process = %v, with %d responses", err, len(out))
		}
		sent := check(t, headersMutation(t, out[0]), hs)
		if ok, code := acceptedByOrders(t, f.m, sent, ""); !ok {
			t.Fatalf("orders refuses it: %s", code)
		}
	})
	t.Run("a body", func(t *testing.T) {
		f := newFixture(t)
		hs := with(post, client...)
		out, err := f.run(nil, requestHeaders(false, hs...), requestBody(`{}`, true))
		if err != nil || len(out) != 2 {
			t.Fatalf("Process = %v, with %d responses", err, len(out))
		}
		// The headers answer already removes every Paztport name, the chain and proof included, so
		// headers Envoy lets on without the body's answer carry none.
		waitsForTheBody(t, out[0], hs)
		if got := paztportNames(apply(t, hs, headersMutation(t, out[0]))); len(got) != 0 {
			t.Fatalf("after the headers answer the request carries %q", got)
		}
		sent := check(t, bodyMutation(t, out[1]), apply(t, hs, headersMutation(t, out[0])))
		if ok, code := acceptedByOrders(t, f.m, sent, `{}`); !ok {
			t.Fatalf("orders refuses it: %s", code)
		}
	})
	t.Run("only a Paztport header", func(t *testing.T) {
		f := newFixture(t)
		hs := with(get, header{"X-Path-Response", "forged"})
		out, err := f.run(nil, requestHeaders(true, hs...))
		if err != nil || len(out) != 1 {
			t.Fatalf("Process = %v, with %d responses", err, len(out))
		}
		m := headersMutation(t, out[0])
		if got := m.GetRemoveHeaders(); !slices.Equal(got, []string{"x-path-response"}) {
			t.Fatalf("remove_headers = %q", got)
		}
		if got := paztportNames(apply(t, hs, m)); !slices.Equal(got, []string{"x-path-chain", "x-path-proof"}) {
			t.Fatalf("the request carries the Paztport headers %q", got)
		}
	})
}

// TestStripsPaztportHeadersFromTheResponse removes every Paztport header, every value and in any case,
// from the response's headers and trailers, and passes its body unchanged.
func TestStripsPaztportHeadersFromTheResponse(t *testing.T) {
	f := newFixture(t)
	hs := []header{{":status", "200"}, {"X-Path-Response", "r"}, {"x-path-chain", "c1"}, {"X-PATH-CHAIN", "c2"},
		{"content-type", "application/json"}}
	trailers := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseTrailers{
		ResponseTrailers: &extprocv3.HttpTrailers{Trailers: headerMap([]header{{"x-path-proof", "p"}, {"grpc-status", "0"}})},
	}}
	body := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
		ResponseBody: &extprocv3.HttpBody{Body: []byte(`{}`), EndOfStream: false},
	}}
	out, err := f.run(nil, requestHeaders(true, get...), responseHeaders(hs...), body, trailers)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 4 {
		t.Fatalf("got %d responses, want 4", len(out))
	}
	rh := out[1].GetResponseHeaders().GetResponse()
	if rh == nil || rh.GetStatus() != extprocv3.CommonResponse_CONTINUE || rh.GetHeaderMutation().GetSetHeaders() != nil {
		t.Fatalf("the response headers answer is %v", out[1])
	}
	if got := rh.GetHeaderMutation().GetRemoveHeaders(); !slices.Equal(got, []string{"x-path-response", "x-path-chain"}) {
		t.Fatalf("remove_headers = %q, want each Paztport name once, in lower case", got)
	}
	if got := paztportNames(apply(t, hs, rh.GetHeaderMutation())); len(got) != 0 {
		t.Fatalf("the response keeps %q", got)
	}
	rb := out[2].GetResponseBody()
	if rb == nil || rb.GetResponse().GetBodyMutation() != nil || rb.GetResponse().GetHeaderMutation() != nil {
		t.Fatalf("the response body answer is %v", out[2])
	}
	rt := out[3].GetResponseTrailers()
	if rt == nil || !slices.Equal(rt.GetHeaderMutation().GetRemoveHeaders(), []string{"x-path-proof"}) {
		t.Fatalf("the response trailers answer is %v", out[3])
	}
	f.observed(t, edge.Stamped)
}

// TestRefusesWhatRouteMetadataDoesNotMap refuses, with the processor's own status and plain body, a
// request whose route metadata is absent, malformed or names two resources (500), or names an HTTPRoute
// the routes do not map (403); never with a Paztport refusal.
func TestRefusesWhatRouteMetadataDoesNotMap(t *testing.T) {
	two := strings.Replace(routeMetadata("shop", "orders"), `values { struct_value`,
		`values { struct_value { fields { key: "kind" value { string_value: "HTTPRoute" } } `+
			`fields { key: "name" value { string_value: "pay" } } `+
			`fields { key: "namespace" value { string_value: "shop" } } } } values { struct_value`, 1)
	for _, tc := range []struct {
		name  string
		attrs map[string]*structpb.Struct
		code  typev3.StatusCode
	}{
		{"absent", nil, typev3.StatusCode_InternalServerError},
		{"malformed", attributes(`filter_metadata { key: `), typev3.StatusCode_InternalServerError},
		{"two resources", attributes(two), typev3.StatusCode_InternalServerError},
		{"unmapped", attributes(routeMetadata("shop", "pay")), typev3.StatusCode_Forbidden},
		{"mapped in another namespace", attributes(routeMetadata("billing", "orders")), typev3.StatusCode_Forbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			req := requestHeaders(false, with(post, header{"x-path-chain", "forged"})...)
			req.Attributes = tc.attrs
			out, err := f.run(nil, req, requestBody(`{}`, true))
			if err != nil {
				t.Fatal(err)
			}
			refused(t, out, false, tc.code)
			f.observed(t, edge.RefusedRoute)
		})
	}
}

// TestTakesTheReceiverFromTheRouteAlone addresses the stamp to the receiver the route maps to, whatever
// the request's authority, host or path names.
func TestTakesTheReceiverFromTheRouteAlone(t *testing.T) {
	f := newFixture(t)
	hs := []header{{":method", "GET"}, {":path", "/payment"}, {":authority", "payment"}, {":scheme", "https"},
		{"host", "payment"}, {"x-forwarded-host", "payment"}}
	out, err := f.run(nil, requestHeaders(true, hs...))
	if err != nil || len(out) != 1 {
		t.Fatalf("Process = %v, with %d responses", err, len(out))
	}
	if c := sentChain(t, apply(t, hs, headersMutation(t, out[0]))); c[0].Rcv != "orders" {
		t.Fatalf("the stamp is addressed to %q, want orders, the route's receiver", c[0].Rcv)
	}
}

// TestRefusesAStampingError refuses a request the SDK cannot stamp: a target that is not UTF-8.
func TestRefusesAStampingError(t *testing.T) {
	f := newFixture(t)
	out, err := f.run(nil, requestHeaders(true, header{":method", "GET"}, header{":path", "/orders/\xff"}))
	if err != nil {
		t.Fatal(err)
	}
	refused(t, out, false, typev3.StatusCode_InternalServerError)
	f.observed(t, edge.RefusedError)
}

// TestRefusesUnderExpiredMaterial refuses rather than stamps once the material has expired, with or
// without a body.
func TestRefusesUnderExpiredMaterial(t *testing.T) {
	f := newFixture(t)
	late := func(c *edge.Config) {
		c.Now = func() time.Time { return time.UnixMilli(materialtest.Now + materialtest.Lifetime + 1) }
	}
	f.p = f.processor(t, late)
	out, err := f.run(nil, requestHeaders(true, get...))
	if err != nil {
		t.Fatal(err)
	}
	refused(t, out, false, typev3.StatusCode_InternalServerError)
	f.observed(t, edge.RefusedMaterial)

	f.obs = nil
	out, err = f.run(nil, requestHeaders(false, post...), requestBody(`{}`, true))
	if err != nil {
		t.Fatal(err)
	}
	refused(t, out, true, typev3.StatusCode_InternalServerError)
	f.observed(t, edge.RefusedMaterial)
}

// TestRefusesABodyOverTheLimit refuses, 413, a body over the limit, in one message or across chunks, and
// stamps one at the limit.
func TestRefusesABodyOverTheLimit(t *testing.T) {
	f := newFixture(t)
	f.p = f.processor(t, func(c *edge.Config) { c.MaxBody = 8 })
	out, err := f.run(nil, requestHeaders(false, post...), requestBody("123456789", true))
	if err != nil {
		t.Fatal(err)
	}
	refused(t, out, true, typev3.StatusCode_PayloadTooLarge)
	f.observed(t, edge.RefusedBody)

	f.obs = nil
	out, err = f.run(nil, requestHeaders(false, post...), requestBody("12345", false), requestBody("6789", true))
	if err != nil {
		t.Fatal(err)
	}
	refused(t, out, true, typev3.StatusCode_PayloadTooLarge)
	if o := f.observed(t, edge.RefusedBody); o.BodyBytes != 9 {
		t.Fatalf("observed a body of %d bytes, want 9", o.BodyBytes)
	}

	f.obs = nil
	out, err = f.run(nil, requestHeaders(false, post...), requestBody("12345678", true))
	if err != nil || len(out) != 2 || out[1].GetRequestBody() == nil {
		t.Fatalf("a body at the limit: Process = %v, responses %v", err, out)
	}
	f.observed(t, edge.Stamped)
}

// TestRefusesABodyModeOtherThanBuffered refuses a request whose filter does not buffer the body whole,
// or that does not say how it sends it: its headers answer would let them go on unstamped.
func TestRefusesABodyModeOtherThanBuffered(t *testing.T) {
	for _, mode := range []*extprocv3.ProtocolConfiguration{
		nil,
		{RequestBodyMode: extprocfilterv3.ProcessingMode_NONE},
		{RequestBodyMode: extprocfilterv3.ProcessingMode_STREAMED},
		{RequestBodyMode: extprocfilterv3.ProcessingMode_BUFFERED_PARTIAL},
		{RequestBodyMode: extprocfilterv3.ProcessingMode_FULL_DUPLEX_STREAMED},
	} {
		f := newFixture(t)
		req := requestHeaders(false, post...)
		req.ProtocolConfig = mode
		out, err := f.run(nil, req, requestBody(`{}`, true))
		if err != nil {
			t.Fatal(err)
		}
		refused(t, out, false, typev3.StatusCode_InternalServerError)
		f.observed(t, edge.RefusedError)
	}
}

// TestRefusesARequestWithoutOneMethodAndPath refuses a request with no :method or :path, two of either,
// or one carried in value rather than raw_value, where Envoy never puts it.
func TestRefusesARequestWithoutOneMethodAndPath(t *testing.T) {
	inValue := requestHeaders(true, header{":method", "GET"})
	inValue.GetRequestHeaders().Headers.Headers = append(inValue.GetRequestHeaders().Headers.Headers,
		&corev3.HeaderValue{Key: ":path", Value: "/orders"})
	for name, req := range map[string]*extprocv3.ProcessingRequest{
		"no method":       requestHeaders(true, header{":path", "/orders"}),
		"no path":         requestHeaders(true, header{":method", "GET"}),
		"an empty path":   requestHeaders(true, header{":method", "GET"}, header{":path", ""}),
		"two paths":       requestHeaders(true, header{":method", "GET"}, header{":path", "/a"}, header{":path", "/b"}),
		"two methods":     requestHeaders(true, header{":method", "GET"}, header{":method", "POST"}, header{":path", "/a"}),
		"path in value":   inValue,
		"no headers kept": {Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{EndOfStream: true}}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if req.Attributes == nil {
				req.Attributes = attributes(routeMetadata("shop", "orders"))
				req.ProtocolConfig = &extprocv3.ProtocolConfiguration{RequestBodyMode: extprocfilterv3.ProcessingMode_BUFFERED}
			}
			out, err := f.run(nil, req)
			if err != nil {
				t.Fatal(err)
			}
			refused(t, out, false, typev3.StatusCode_InternalServerError)
			f.observed(t, edge.RefusedError)
		})
	}
}

// TestRefusesMessagesOutOfOrder refuses a stream that does not open with the request's headers, or that
// sends request headers twice, or a response body or trailers before the request was stamped.
func TestRefusesMessagesOutOfOrder(t *testing.T) {
	for name, reqs := range map[string][]*extprocv3.ProcessingRequest{
		"a body first":           {requestBody(`{}`, true)},
		"request trailers first": {requestTrailers()},
		"a response body before a stamp": {requestHeaders(false, post...), {Request: &extprocv3.ProcessingRequest_ResponseBody{
			ResponseBody: &extprocv3.HttpBody{Body: []byte(`{}`), EndOfStream: true}}}},
		"response trailers before a stamp": {requestHeaders(false, post...), {Request: &extprocv3.ProcessingRequest_ResponseTrailers{
			ResponseTrailers: &extprocv3.HttpTrailers{Trailers: headerMap([]header{{"grpc-status", "0"}})}}}},
		"headers twice":    {requestHeaders(false, post...), requestHeaders(true, post...)},
		"an empty message": {{}},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			out, err := f.run(nil, reqs...)
			if err != nil {
				t.Fatal(err)
			}
			if len(out) == 0 || out[len(out)-1].GetImmediateResponse().GetStatus().GetCode() != typev3.StatusCode_InternalServerError {
				t.Fatalf("responses %v, want a refusal last", out)
			}
			for _, r := range out[:len(out)-1] {
				if m := headersMutation(t, r); m != nil {
					t.Fatalf("before the refusal, a response mutates %v", m)
				}
			}
			f.observed(t, edge.RefusedError)
		})
	}
}

// TestPassesEnvoysLocalReplyBeforeTheStamp passes on, with its Paztport headers removed, response headers that
// arrive before the request was stamped: Envoy's own local reply, such as its 413 for a body over the buffer
// limit, or a refusal by a filter before ext_proc. The request never went on, so the reply is let through as
// Envoy made it, never replaced by the processor's 500; a request whose body was awaited is decided refused,
// for its body when the reply is a 413.
func TestPassesEnvoysLocalReplyBeforeTheStamp(t *testing.T) {
	reply := func(status string) []header {
		return []header{{":status", status}, {"x-path-response", "r"}, {"X-Path-Chain", "c"}, {"content-type", "text/plain"}}
	}
	body := &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_ResponseBody{
		ResponseBody: &extprocv3.HttpBody{Body: []byte("Payload Too Large"), EndOfStream: true},
	}}
	for _, tc := range []struct {
		name     string
		reqs     func(hs []header) []*extprocv3.ProcessingRequest
		status   string
		observed []edge.Outcome
	}{
		{"a 413 while the body is awaited", func(hs []header) []*extprocv3.ProcessingRequest {
			return []*extprocv3.ProcessingRequest{requestHeaders(false, post...), responseHeaders(hs...), body}
		}, "413", []edge.Outcome{edge.RefusedBody}},
		{"a 408 while the body is awaited", func(hs []header) []*extprocv3.ProcessingRequest {
			return []*extprocv3.ProcessingRequest{requestHeaders(false, post...), responseHeaders(hs...), body}
		}, "408", []edge.Outcome{edge.RefusedError}},
		{"a 401 before the request's headers", func(hs []header) []*extprocv3.ProcessingRequest {
			return []*extprocv3.ProcessingRequest{responseHeaders(hs...), body}
		}, "401", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			hs := reply(tc.status)
			out, err := f.run(nil, tc.reqs(hs)...)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range out {
				if r.GetImmediateResponse() != nil {
					t.Fatalf("responses %v: the local reply was replaced", out)
				}
			}
			rh := out[len(out)-2].GetResponseHeaders().GetResponse()
			if rh == nil || rh.GetHeaderMutation().GetSetHeaders() != nil {
				t.Fatalf("the response headers answer is %v", out[len(out)-2])
			}
			if got := paztportNames(apply(t, hs, rh.GetHeaderMutation())); len(got) != 0 {
				t.Fatalf("the local reply keeps %q", got)
			}
			if rb := out[len(out)-1].GetResponseBody(); rb == nil || rb.GetResponse().GetBodyMutation() != nil {
				t.Fatalf("the response body answer is %v", out[len(out)-1])
			}
			var got []edge.Outcome
			for _, o := range f.obs {
				got = append(got, o.Outcome)
			}
			if !slices.Equal(got, tc.observed) {
				t.Fatalf("observed %v, want %v", got, tc.observed)
			}
		})
	}
}

// TestRefusesARequestAfterEnvoysLocalReply refuses any request message after Envoy's local reply: Envoy has
// answered the request itself, so a request message then is not a stream the processor may stamp. Each case ends
// in the processor's refusal, with no answer before it that sets a header, and no request observed stamped.
func TestRefusesARequestAfterEnvoysLocalReply(t *testing.T) {
	tooLarge := []*extprocv3.ProcessingRequest{requestHeaders(false, post...), responseHeaders(header{":status", "413"})}
	unauthorised := []*extprocv3.ProcessingRequest{responseHeaders(header{":status", "401"})}
	for name, reqs := range map[string][]*extprocv3.ProcessingRequest{
		"a 413, then request headers":         append(slices.Clone(tooLarge), requestHeaders(true, get...)),
		"a 413, then a request body":          append(slices.Clone(tooLarge), requestBody(`{}`, true)),
		"a 413, then request trailers":        append(slices.Clone(tooLarge), requestTrailers()),
		"a 401, then request headers":         append(slices.Clone(unauthorised), requestHeaders(true, get...)),
		"a 401, then headers and then a body": append(slices.Clone(unauthorised), requestHeaders(false, post...), requestBody(`{}`, true)),
		"a 401, then a request body":          append(slices.Clone(unauthorised), requestBody(`{}`, true)),
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			out, err := f.run(nil, reqs...)
			if err != nil {
				t.Fatal(err)
			}
			if len(out) == 0 || out[len(out)-1].GetImmediateResponse() == nil {
				t.Fatalf("responses %v, want a refusal last", out)
			}
			for _, r := range out[:len(out)-1] {
				for _, m := range []*extprocv3.HeaderMutation{
					r.GetRequestHeaders().GetResponse().GetHeaderMutation(),
					r.GetRequestBody().GetResponse().GetHeaderMutation(),
					r.GetResponseHeaders().GetResponse().GetHeaderMutation(),
				} {
					if len(m.GetSetHeaders()) > 0 {
						t.Fatalf("before the refusal, an answer sets %v", m.GetSetHeaders())
					}
				}
			}
			for _, o := range f.obs {
				if o.Outcome == edge.Stamped {
					t.Fatalf("observed %+v, want no request stamped", f.obs)
				}
			}
		})
	}
}

// TestRefusesARequestAfterItWasStamped refuses any request message after the stamp: there is none in a
// stream Envoy sends, so one means the stream is not what the processor stamped.
func TestRefusesARequestAfterItWasStamped(t *testing.T) {
	f := newFixture(t)
	out, err := f.run(nil, requestHeaders(true, get...), requestBody(`{}`, true))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[1].GetImmediateResponse() == nil {
		t.Fatalf("responses %v, want the stamp and then a refusal", out)
	}
	f.observed(t, edge.Stamped)
}

// TestReportsNothingForAnEmptyStream reports no request for a stream that closes before any message.
func TestReportsNothingForAnEmptyStream(t *testing.T) {
	f := newFixture(t)
	if out, err := f.run(nil); err != nil || len(out) != 0 || len(f.obs) != 0 {
		t.Fatalf("Process = %v, responses %v, observed %v", err, out, f.obs)
	}
}

// TestNewRefuses refuses a processor with no material, no instance or no body limit.
func TestNewRefuses(t *testing.T) {
	m := materialtest.New(t)
	set := m.Load(t)
	for name, cfg := range map[string]edge.Config{
		"no material":      {Inst: "edge-1", MaxBody: 1},
		"no instance":      {Material: set, Inst: " ", MaxBody: 1},
		"no body limit":    {Material: set, Inst: "edge-1"},
		"a negative limit": {Material: set, Inst: "edge-1", MaxBody: -1},
	} {
		if p, err := edge.New(cfg); err == nil {
			t.Errorf("%s: New = %v, want an error", name, p)
		}
	}
}

// TestInstFromEnv reads the instance from POD_NAME, and refuses it unset or blank.
func TestInstFromEnv(t *testing.T) {
	t.Setenv("POD_NAME", "edge-5d8f-x2")
	if got, err := edge.InstFromEnv(); err != nil || got != "edge-5d8f-x2" {
		t.Fatalf("InstFromEnv = %q, %v", got, err)
	}
	t.Setenv("POD_NAME", "  ")
	if got, err := edge.InstFromEnv(); err == nil {
		t.Fatalf("InstFromEnv with POD_NAME blank = %q", got)
	}
}

// uuidV4 is the text of a random UUID: lower-case hex, version 4, variant 10.
var uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// TestNewRIDIsARandomUUID gives a version 4 UUID each time, 10 000 of them all distinct, and the
// processor's stamps carry one.
func TestNewRIDIsARandomUUID(t *testing.T) {
	seen := make(map[string]bool, 10000)
	for range 10000 {
		rid := edge.NewRID()
		if !uuidV4.MatchString(rid) {
			t.Fatalf("NewRID = %q, not a version 4 UUID", rid)
		}
		if seen[rid] {
			t.Fatalf("NewRID repeated %q", rid)
		}
		seen[rid] = true
	}
	f := newFixture(t)
	out, err := f.run(nil, requestHeaders(true, get...))
	if err != nil || len(out) != 1 {
		t.Fatalf("Process = %v, with %d responses", err, len(out))
	}
	if rid := sentChain(t, apply(t, get, headersMutation(t, out[0])))[0].RID; !uuidV4.MatchString(rid) {
		t.Fatalf("the stamp's rid %q is not a version 4 UUID", rid)
	}
}

// TestOutcomesAreTheirMetricLabels keeps each outcome's text, which metrics label requests with.
func TestOutcomesAreTheirMetricLabels(t *testing.T) {
	var got []string
	for _, o := range []edge.Outcome{edge.Stamped, edge.RefusedRoute, edge.RefusedMaterial, edge.RefusedBody, edge.RefusedError} {
		got = append(got, string(o))
	}
	if want := "stamped refused_route refused_material refused_body refused_error"; strings.Join(got, " ") != want {
		t.Fatalf("outcomes %q, want %q", got, want)
	}
}

// TestObservesTheStampsRID reports a stamped request with the rid its stamp carries, and a refused one
// with none.
func TestObservesTheStampsRID(t *testing.T) {
	f := newFixture(t)
	out, err := f.run(nil, requestHeaders(true, get...))
	if err != nil || len(out) != 1 {
		t.Fatalf("Process = %v, with %d responses", err, len(out))
	}
	rid := sentChain(t, apply(t, get, headersMutation(t, out[0])))[0].RID
	if o := f.observed(t, edge.Stamped); o.RID != rid {
		t.Fatalf("observed the rid %q, want the stamp's %q", o.RID, rid)
	}

	f = newFixture(t)
	req := requestHeaders(true, get...)
	req.Attributes = attributes(routeMetadata("shop", "pay"))
	if _, err := f.run(nil, req); err != nil {
		t.Fatal(err)
	}
	if o := f.observed(t, edge.RefusedRoute); o.RID != "" {
		t.Fatalf("observed the rid %q for a refused request, want none", o.RID)
	}
}

// TestObservesEnvoysRequestID reports Envoy's x-request-id with each request, stamped or refused, when
// it is one value of the form Envoy gives it, and nothing otherwise: it is logged, and a value of any
// other form is not Envoy's.
func TestObservesEnvoysRequestID(t *testing.T) {
	const id = "0f8b2c1e-6a4d-4b7e-9c3f-2d5e8a1b7c40"
	for _, tc := range []struct {
		name  string
		route string
		hs    []header
		want  edge.Outcome
		id    string
	}{
		{"stamped", "orders", with(get, header{"x-request-id", id}), edge.Stamped, id},
		{"refused", "pay", with(get, header{"x-request-id", id}), edge.RefusedRoute, id},
		{"in another case", "orders", with(get, header{"X-Request-Id", id}), edge.Stamped, id},
		{"absent", "orders", get, edge.Stamped, ""},
		{"twice", "orders", with(get, header{"x-request-id", id}, header{"x-request-id", id}), edge.Stamped, ""},
		{"empty", "orders", with(get, header{"x-request-id", ""}), edge.Stamped, ""},
		{"with a space", "orders", with(get, header{"x-request-id", "a b"}), edge.Stamped, ""},
		{"with a quote", "orders", with(get, header{"x-request-id", `a"b`}), edge.Stamped, ""},
		{"too long", "orders", with(get, header{"x-request-id", strings.Repeat("a", 129)}), edge.Stamped, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			req := requestHeaders(true, tc.hs...)
			req.Attributes = attributes(routeMetadata("shop", tc.route))
			if _, err := f.run(nil, req); err != nil {
				t.Fatal(err)
			}
			if o := f.observed(t, tc.want); o.RequestID != tc.id {
				t.Fatalf("observed the request id %q, want %q", o.RequestID, tc.id)
			}
		})
	}
}
