// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/dumbsly/paztport/poc-sdks/go/keys"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/material/materialtest"
	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/server"
)

// oidCommonName is the attribute type of a subject's common name (CN).
var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// authority is a test certificate authority.
type authority struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

// newAuthority returns a new self-signed certificate authority named name.
func newAuthority(t *testing.T, name string) *authority {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          serial(t),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &authority{cert: cert, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// leaf is a certificate the authority issued, with its key, in memory and as PEM.
type leaf struct {
	tls       tls.Certificate
	certPEM   []byte
	keyPEM    []byte
	certPath  string
	keyPath   string
	authority *authority
}

// issue returns a leaf for both server and client use, with the subject given and the SAN DNS name
// paztport-processor and IP 127.0.0.1, written to two files in dir.
func (a *authority) issue(t *testing.T, dir, file string, subject pkix.Name) *leaf {
	t.Helper()
	return a.issueWith(t, dir, file, func(c *x509.Certificate) { c.Subject = subject })
}

// issueWith returns a leaf as issue does, with CN=edge, after change has changed its template.
func (a *authority) issueWith(t *testing.T, dir, file string, change func(*x509.Certificate)) *leaf {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "edge"},
		SerialNumber: serial(t),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"paztport-processor"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	change(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	l := &leaf{
		certPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:    pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		certPath:  filepath.Join(dir, file+".crt"),
		keyPath:   filepath.Join(dir, file+".key"),
		authority: a,
	}
	if l.tls, err = tls.X509KeyPair(l.certPEM, l.keyPEM); err != nil {
		t.Fatal(err)
	}
	writeFile(t, l.certPath, l.certPEM)
	writeFile(t, l.keyPath, l.keyPEM)
	return l
}

// cn returns a subject of the common names given, each in its own RDN, in order.
func cn(names ...string) pkix.Name {
	var n pkix.Name
	for _, name := range names {
		n.ExtraNames = append(n.ExtraNames, pkix.AttributeTypeAndValue{Type: oidCommonName, Value: name})
	}
	return n
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func serial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func writeFile(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// logBuffer is a log's output, safe to write from the server's goroutines and read from the test's.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// harness is one running server over test material and test certificates.
type harness struct {
	m         *materialtest.Material
	cfg       server.Config
	ca        *authority
	edge      *leaf
	clock     atomic.Int64
	logs      *logBuffer
	grpcAddr  string
	adminAddr string
}

// start serves a processor over new material, mapping the HTTPRoute shop/orders to orders, at the clock
// a second after the material was made, on two loopback ports; its server certificate and the client
// certificate edge are issued by the authority it trusts for clients. change, when not nil, changes the
// config first.
func start(t *testing.T, change func(*server.Config)) *harness {
	t.Helper()
	h := &harness{m: materialtest.New(t), logs: &logBuffer{}}
	h.clock.Store(materialtest.Now + 1000)
	dir := t.TempDir()
	h.ca = newAuthority(t, "mesh CA")
	srv := h.ca.issue(t, dir, "paztport-processor", pkix.Name{CommonName: "paztport-processor"})
	h.edge = h.ca.issue(t, dir, "edge", pkix.Name{CommonName: "edge"})
	writeFile(t, filepath.Join(dir, "ca.crt"), h.ca.pem)
	h.cfg = server.Config{
		Listen:      "127.0.0.1:0",
		AdminListen: "127.0.0.1:0",
		TLSCert:     srv.certPath,
		TLSKey:      srv.keyPath,
		ClientCA:    filepath.Join(dir, "ca.crt"),
		Key:         h.m.Config.KeyPath,
		Pin:         h.m.Config.PinPath,
		Keyrings:    h.m.Config.KeyringPaths,
		Roots:       h.m.Config.RootPaths,
		Bundle:      h.m.Config.BundlePath,
		Routes:      filepath.Join(h.m.Dir, "routes.txt"),
		BodyLimit:   1024,
		Inst:        "edge-7f9c",
	}
	if change != nil {
		change(&h.cfg)
	}
	log := slog.New(slog.NewJSONHandler(h.logs, nil))
	s, err := server.New(h.cfg, log, func() time.Time { return time.UnixMilli(h.clock.Load()) })
	if err != nil {
		t.Fatal(err)
	}
	grpcLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	adminLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.grpcAddr, h.adminAddr = grpcLis.Addr().String(), adminLis.Addr().String()
	served := make(chan error, 1)
	go func() { served <- s.Serve(grpcLis, adminLis) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown = %v", err)
		}
		if err := <-served; err != nil {
			t.Errorf("Serve = %v", err)
		}
	})
	return h
}

// clientTLS returns the TLS config of a client presenting cert, or none when cert is nil, that trusts the
// harness's authority for the server paztport-processor. It sends cert whatever the server asks for: Go's
// client would otherwise withhold a certificate the server's list of CAs does not name, and the server's
// own refusal would go untested.
func (h *harness) clientTLS(cert *leaf) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(h.ca.cert)
	c := &tls.Config{RootCAs: pool, ServerName: "paztport-processor", NextProtos: []string{"h2"}}
	if cert != nil {
		c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert.tls, nil }
	}
	return c
}

// rdn returns the DER of a subject of one relative distinguished name holding the common names given: a
// multi-valued RDN such as CN=orders+CN=edge.
func rdn(t *testing.T, names ...string) []byte {
	t.Helper()
	var set []pkix.AttributeTypeAndValue
	for _, name := range names {
		set = append(set, pkix.AttributeTypeAndValue{Type: oidCommonName, Value: name})
	}
	der, err := asn1.Marshal(pkix.RDNSequence{set})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// handshake connects to the gRPC port as a client with c, and returns nil once the server has accepted
// it and sent its first HTTP/2 frame, or the error the connection ended in. Under TLS 1.3 the server
// checks the client's certificate after the client's side of the handshake is done, so its refusal
// arrives as an alert on the first read.
func (h *harness) handshake(t *testing.T, c *tls.Config) error {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", h.grpcAddr, c)
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")); err != nil {
		return err
	}
	var b [1]byte
	_, err = conn.Read(b[:])
	return err
}

// process sends reqs on one ext_proc stream as a client presenting cert, closes its side, and returns
// every response, or the error the stream ended in.
func (h *harness) process(
	t *testing.T, cert *leaf, reqs ...*extprocv3.ProcessingRequest,
) ([]*extprocv3.ProcessingResponse, error) {
	t.Helper()
	conn, err := grpc.NewClient(h.grpcAddr, grpc.WithTransportCredentials(credentials.NewTLS(h.clientTLS(cert))))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := extprocv3.NewExternalProcessorClient(conn).Process(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range reqs {
		if err := stream.Send(r); err != nil {
			break // the error is the stream's, which Recv returns
		}
	}
	if err := stream.CloseSend(); err != nil {
		return nil, err
	}
	var out []*extprocv3.ProcessingResponse
	for {
		r, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, r)
	}
}

// get fetches path from the admin port, and returns its status and body.
func (h *harness) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := http.Get("http://" + h.adminAddr + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// header is one header as Envoy sends it.
type header struct{ name, value string }

// request returns the first message of a request to the HTTPRoute shop/<route> in Buffered mode, with the
// headers hs; endOfStream says whether the headers end it.
func request(route string, endOfStream bool, hs ...header) *extprocv3.ProcessingRequest {
	m := &corev3.HeaderMap{}
	for _, h := range hs {
		m.Headers = append(m.Headers, &corev3.HeaderValue{Key: h.name, RawValue: []byte(h.value)})
	}
	metadata := `filter_metadata { key: "envoy-gateway" value { fields { key: "resources" value { list_value { ` +
		`values { struct_value { fields { key: "kind" value { string_value: "HTTPRoute" } } ` +
		`fields { key: "name" value { string_value: "` + route + `" } } ` +
		`fields { key: "namespace" value { string_value: "shop" } } } } } } } } } `
	return &extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: m, EndOfStream: endOfStream,
		}},
		Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
			"xds.route_metadata": structpb.NewStringValue(metadata),
		}}},
		ProtocolConfig: &extprocv3.ProtocolConfiguration{
			RequestBodyMode:  extprocfilterv3.ProcessingMode_BUFFERED,
			ResponseBodyMode: extprocfilterv3.ProcessingMode_NONE,
		},
	}
}

// body returns the request body message that ends the stream.
func body(b []byte) *extprocv3.ProcessingRequest {
	return &extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
		RequestBody: &extprocv3.HttpBody{Body: b, EndOfStream: true},
	}}
}

// get and post are the pseudo-headers of a GET and a POST.
var (
	get  = []header{{":method", "GET"}, {":path", "/orders/7"}, {":authority", "shop.example"}, {":scheme", "https"}}
	post = []header{{":method", "POST"}, {":path", "/orders"}, {":authority", "shop.example"}, {":scheme", "https"}}
)

// stampedChain returns the chain header a stamp answer sets, failing the test for any other answer.
func stampedChain(t *testing.T, r *extprocv3.ProcessingResponse) string {
	t.Helper()
	var c *extprocv3.CommonResponse
	switch {
	case r.GetRequestHeaders() != nil:
		c = r.GetRequestHeaders().GetResponse()
	case r.GetRequestBody() != nil:
		c = r.GetRequestBody().GetResponse()
	default:
		t.Fatalf("the answer %v is not a stamp", r)
	}
	for _, o := range c.GetHeaderMutation().GetSetHeaders() {
		if o.GetHeader().GetKey() == "x-path-chain" {
			return string(o.GetHeader().GetRawValue())
		}
	}
	t.Fatalf("the answer %v sets no chain", r)
	return ""
}

// TestAcceptsTheEdge serves a client whose certificate, from the client CA, names the subject CN=edge
// alone: its request is stamped.
func TestAcceptsTheEdge(t *testing.T) {
	h := start(t, nil)
	if err := h.handshake(t, h.clientTLS(h.edge)); err != nil {
		t.Fatalf("the handshake as edge failed: %v", err)
	}
	out, err := h.process(t, h.edge, request("orders", true, get...))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || stampedChain(t, out[0]) == "" {
		t.Fatalf("responses %v, want one stamp", out)
	}
}

// TestRefusesEveryClientButTheEdge refuses the connection of a client with no certificate; with one from
// the client CA naming anything but CN=edge alone, expired, a CA, or not for client authentication; or with
// one naming CN=edge from another CA, even a CA of the same name. Each client sends its certificate
// whatever the server asks for, so each refusal is the server's. No request on it reaches the processor.
func TestRefusesEveryClientButTheEdge(t *testing.T) {
	h := start(t, nil)
	dir := t.TempDir()
	other := newAuthority(t, "other CA")
	sameName := newAuthority(t, "mesh CA")
	for _, tc := range []struct {
		name string
		cert *leaf
	}{
		{"no certificate", nil},
		{"CN=orders", h.ca.issue(t, dir, "orders", pkix.Name{CommonName: "orders"})},
		{"CN=edge from another CA", other.issue(t, dir, "other-edge", pkix.Name{CommonName: "edge"})},
		{"CN=orders then CN=edge", h.ca.issue(t, dir, "orders-edge", cn("orders", "edge"))},
		{"CN=edge twice", h.ca.issue(t, dir, "edge-edge", cn("edge", "edge"))},
		{"CN=Edge", h.ca.issue(t, dir, "Edge", pkix.Name{CommonName: "Edge"})},
		{"no CN, O=edge", h.ca.issue(t, dir, "o-edge", pkix.Name{Organization: []string{"edge"}})},
		{"CN=edge from another CA of the same name", sameName.issue(t, dir, "same-name-edge", pkix.Name{CommonName: "edge"})},
		{"CN=edge, expired", h.ca.issueWith(t, dir, "expired-edge", func(c *x509.Certificate) {
			c.NotBefore, c.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
		})},
		{"CN=edge, for server authentication only", h.ca.issueWith(t, dir, "server-edge", func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		})},
		{"CN=orders+CN=edge in one RDN", h.ca.issueWith(t, dir, "rdn-edge", func(c *x509.Certificate) {
			c.RawSubject = rdn(t, "orders", "edge")
		})},
		{"CN=edge, a CA", h.ca.issueWith(t, dir, "ca-edge", func(c *x509.Certificate) {
			c.BasicConstraintsValid, c.IsCA = true, true
		})},
		{"CN=edge, no extended key usage", h.ca.issueWith(t, dir, "no-eku-edge", func(c *x509.Certificate) {
			c.ExtKeyUsage = nil
		})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := h.handshake(t, h.clientTLS(tc.cert)); err == nil {
				t.Fatal("the server accepted the client")
			}
			out, err := h.process(t, tc.cert, request("orders", true, get...))
			if status.Code(err) != codes.Unavailable {
				t.Fatalf("Process = %v, %v; want the stream unavailable", out, err)
			}
		})
	}
	if strings.Contains(h.logs.String(), `"msg":"request"`) {
		t.Fatalf("a refused client's request reached the processor:\n%s", h.logs)
	}
}

// TestServesOnlyTLS13 refuses the edge over TLS 1.2.
func TestServesOnlyTLS13(t *testing.T) {
	h := start(t, nil)
	c := h.clientTLS(h.edge)
	c.MaxVersion = tls.VersionTLS12
	if err := h.handshake(t, c); err == nil {
		t.Fatal("the server accepted TLS 1.2")
	}
}

// TestReadyFollowsTheMaterial reports ready while the material is current and not ready once it has
// expired, while staying live.
func TestReadyFollowsTheMaterial(t *testing.T) {
	h := start(t, nil)
	if code, _ := h.get(t, "/readyz"); code != http.StatusOK {
		t.Fatalf("/readyz = %d with current material, want 200", code)
	}
	if code, _ := h.get(t, "/livez"); code != http.StatusOK {
		t.Fatalf("/livez = %d, want 200", code)
	}
	h.clock.Store(materialtest.Now + materialtest.Lifetime + 1)
	if code, _ := h.get(t, "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz = %d with expired material, want 503", code)
	}
	if code, _ := h.get(t, "/livez"); code != http.StatusOK {
		t.Fatalf("/livez = %d with expired material, want 200", code)
	}
}

// hasLine reports whether the metrics text holds the line want.
func hasLine(metrics, want string) bool {
	for _, line := range strings.Split(metrics, "\n") {
		if line == want {
			return true
		}
	}
	return false
}

// TestMetricsMoveWithEachRequest counts a stamped request and a refused one by outcome, times the stamp,
// sizes both bodies, and reports how long the material has left.
func TestMetricsMoveWithEachRequest(t *testing.T) {
	h := start(t, nil)
	_, before := h.get(t, "/metrics")
	for _, want := range []string{
		`paztport_edge_requests_total{outcome="stamped"} 0`,
		`paztport_edge_requests_total{outcome="refused_route"} 0`,
		`paztport_edge_requests_total{outcome="refused_material"} 0`,
		`paztport_edge_requests_total{outcome="refused_body"} 0`,
		`paztport_edge_requests_total{outcome="refused_error"} 0`,
		`paztport_edge_stamp_seconds_count 0`,
		`paztport_edge_body_bytes_count 0`,
		`paztport_edge_material_seconds_left 3599`,
	} {
		if !hasLine(before, want) {
			t.Errorf("before any request, /metrics lacks %q", want)
		}
	}

	order := []byte(`{"item":"tea","qty":2}`)
	if out, err := h.process(t, h.edge, request("orders", false, post...), body(order)); err != nil || len(out) != 2 {
		t.Fatalf("Process = %v, %v; want the headers answer and the stamp", out, err)
	}
	if out, err := h.process(t, h.edge, request("pay", true, get...)); err != nil || len(out) != 1 ||
		out[0].GetImmediateResponse() == nil {
		t.Fatalf("Process = %v, %v; want a refusal", out, err)
	}
	h.clock.Add(1000)

	_, after := h.get(t, "/metrics")
	for _, want := range []string{
		`paztport_edge_requests_total{outcome="stamped"} 1`,
		`paztport_edge_requests_total{outcome="refused_route"} 1`,
		`paztport_edge_requests_total{outcome="refused_material"} 0`,
		`paztport_edge_stamp_seconds_count 1`,
		`paztport_edge_body_bytes_count 2`,
		`paztport_edge_body_bytes_sum 22`,
		`paztport_edge_material_seconds_left 3598`,
	} {
		if !hasLine(after, want) {
			t.Errorf("after a stamped and a refused request, /metrics lacks %q", want)
		}
	}
	if t.Failed() {
		t.Logf("/metrics:\n%s", after)
	}
}

// TestMetricsCountRequestsAfterTheMaterialExpires counts a request refused under expired material, and
// reports the material's time as gone.
func TestMetricsCountRequestsAfterTheMaterialExpires(t *testing.T) {
	h := start(t, nil)
	h.clock.Store(materialtest.Now + materialtest.Lifetime + 2000)
	if out, err := h.process(t, h.edge, request("orders", true, get...)); err != nil || len(out) != 1 ||
		out[0].GetImmediateResponse() == nil {
		t.Fatalf("Process = %v, %v; want a refusal", out, err)
	}
	_, metrics := h.get(t, "/metrics")
	for _, want := range []string{
		`paztport_edge_requests_total{outcome="refused_material"} 1`,
		`paztport_edge_material_seconds_left -2`,
	} {
		if !hasLine(metrics, want) {
			t.Errorf("/metrics lacks %q", want)
		}
	}
}

// TestLogsEachRequestWithoutWhatItCarries logs each request's outcome, rid and Envoy's x-request-id, and
// never its body, its Paztport headers or any other header the client sent, nor the edge's key.
func TestLogsEachRequestWithoutWhatItCarries(t *testing.T) {
	h := start(t, nil)
	const id = "3c9a7e52-1b0d-4f6a-8e2c-5d7b9a0f1e34"
	probes := []string{"probe-authorization-6e1f", "probe-chain-2b8d", "probe-cookie-9a4c", "probe-body-7d3e"}
	hs := append(append([]header{}, post...),
		header{"authorization", "Bearer " + probes[0]},
		header{"x-path-chain", probes[1]},
		header{"cookie", "session=" + probes[2]},
		header{"x-request-id", id})
	out, err := h.process(t, h.edge, request("orders", false, hs...), body([]byte(`{"note":"`+probes[3]+`"}`)))
	if err != nil || len(out) != 2 {
		t.Fatalf("Process = %v, %v; want the headers answer and the stamp", out, err)
	}
	if _, err := h.process(t, h.edge, request("pay", false, hs...), body([]byte(probes[3]))); err != nil {
		t.Fatal(err)
	}

	logs := h.logs.String()
	for _, p := range probes {
		if strings.Contains(logs, p) {
			t.Errorf("the log holds %q, which the client sent:\n%s", p, logs)
		}
	}
	if k := keys.EncodePrivate(h.m.EdgeKey); strings.Contains(logs, k) {
		t.Errorf("the log holds the edge's private key:\n%s", logs)
	}
	var stamped, refused bool
	for _, line := range strings.Split(strings.TrimSpace(logs), "\n") {
		if !strings.Contains(line, `"msg":"request"`) {
			continue
		}
		if !strings.Contains(line, `"x_request_id":"`+id+`"`) {
			t.Errorf("the request's line lacks Envoy's x-request-id: %s", line)
		}
		switch {
		case strings.Contains(line, `"outcome":"stamped"`) && strings.Contains(line, `"rid":"`):
			stamped = true
		case strings.Contains(line, `"outcome":"refused_route"`) && !strings.Contains(line, `"rid"`):
			refused = true
		}
	}
	if !stamped || !refused {
		t.Fatalf("the log lacks a line for the stamped request with its rid, or the refused one without:\n%s", logs)
	}
}

// TestStampsABodyLargerThanGRPCsDefaultMessage takes a body up to the body limit in one message, past
// gRPC's default limit of 4 MiB a message.
func TestStampsABodyLargerThanGRPCsDefaultMessage(t *testing.T) {
	const limit = 5 << 20
	h := start(t, func(c *server.Config) { c.BodyLimit = limit })
	out, err := h.process(t, h.edge, request("orders", false, post...), body(bytes.Repeat([]byte("a"), limit)))
	if err != nil || len(out) != 2 {
		t.Fatalf("Process = %d responses, %v; want the headers answer and the stamp", len(out), err)
	}
	stampedChain(t, out[1])
}

// TestNewRefusesWhatItCannotServe refuses to start on material that does not load or TLS files that do
// not, naming what failed.
func TestNewRefusesWhatItCannotServe(t *testing.T) {
	m := materialtest.New(t)
	dir := t.TempDir()
	ca := newAuthority(t, "mesh CA")
	srv := ca.issue(t, dir, "paztport-processor", pkix.Name{CommonName: "paztport-processor"})
	writeFile(t, filepath.Join(dir, "ca.crt"), ca.pem)
	writeFile(t, filepath.Join(dir, "empty.crt"), []byte("no certificate here\n"))
	good := server.Config{
		Listen: ":9002", AdminListen: ":9090",
		TLSCert: srv.certPath, TLSKey: srv.keyPath, ClientCA: filepath.Join(dir, "ca.crt"),
		Key: m.Config.KeyPath, Pin: m.Config.PinPath, Keyrings: m.Config.KeyringPaths, Roots: m.Config.RootPaths,
		Bundle: m.Config.BundlePath, Routes: filepath.Join(m.Dir, "routes.txt"), BodyLimit: 1024, Inst: "edge-1",
	}
	now := func() time.Time { return time.UnixMilli(materialtest.Now + 1000) }
	for _, tc := range []struct {
		name   string
		change func(*server.Config)
		now    func() time.Time
		want   string
	}{
		{"no server key", func(c *server.Config) { c.TLSKey = filepath.Join(dir, "absent.key") }, now, "server certificate"},
		{"a client CA with no certificate", func(c *server.Config) { c.ClientCA = filepath.Join(dir, "empty.crt") }, now,
			"client CA"},
		{"no routes", func(c *server.Config) { c.Routes = filepath.Join(dir, "absent.txt") }, now, "routes"},
		{"expired material", func(c *server.Config) {},
			func() time.Time { return time.UnixMilli(materialtest.Now + materialtest.Lifetime + 1) }, "notAfter"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := good
			tc.change(&cfg)
			s, err := server.New(cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)), tc.now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("New = %v, %v; want an error naming %q", s, err, tc.want)
			}
		})
	}
	if _, err := server.New(good, slog.New(slog.NewJSONHandler(io.Discard, nil)), now); err != nil {
		t.Fatalf("New with good config = %v", err)
	}
}

// TestRunStopsWhenItsContextEnds serves until its context ends, then stops cleanly.
func TestRunStopsWhenItsContextEnds(t *testing.T) {
	h := start(t, nil)
	cfg := h.cfg
	cfg.Listen, cfg.AdminListen = "127.0.0.1:0", "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Run(ctx, cfg, slog.New(slog.NewJSONHandler(io.Discard, nil)), h.now) }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// now is the harness's clock.
func (h *harness) now() time.Time { return time.UnixMilli(h.clock.Load()) }
