// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Command edgecheck is a client the proof of concept's checks use for the two requests curl cannot make. It is
// not part of the processor's image.
//
//	edgecheck trailers <host:port> <authority> <path>
//
// sends, over HTTP/2 without TLS, a POST of request headers and then trailers, with no body between them, and
// prints the response's status.
//
//	edgecheck stamp <host:port> <ca> <cert> <key> <namespace>/<httproute> <method> <path> <body>
//
// calls the processor as Envoy would, over mutual TLS with the client certificate cert and key, checking the
// processor's certificate against ca for the name paztport-processor: it sends the request's headers with the
// route metadata Envoy Gateway writes for the HTTPRoute, then the body, and prints each header the processor sets
// as one "name: value" line. A refused handshake, or any answer but the stamp, is an error.
//
// Each exits 1, with one line on standard error, when the request cannot be made.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extprocfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/types/known/structpb"
)

// timeout bounds each command.
const timeout = 10 * time.Second

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "edgecheck:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	switch {
	case len(args) == 4 && args[0] == "trailers":
		status, err := trailers(args[1], args[2], args[3])
		if err != nil {
			return err
		}
		fmt.Println(status)
		return nil
	case len(args) == 9 && args[0] == "stamp":
		headers, err := stamp(args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8])
		if err != nil {
			return err
		}
		for _, h := range headers {
			fmt.Printf("%s: %s\n", h.GetKey(), h.GetRawValue())
		}
		return nil
	default:
		return errors.New("usage: edgecheck trailers <host:port> <authority> <path> | " +
			"edgecheck stamp <host:port> <ca> <cert> <key> <namespace>/<httproute> <method> <path> <body>")
	}
}

// trailers sends a POST to path at addr, over HTTP/2 with prior knowledge and no TLS, as one HEADERS frame without
// END_STREAM and then a trailers HEADERS frame with it, so that the request has trailers and no body, and returns
// the response's :status.
func trailers(addr, authority, path string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		return "", err
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		return "", err
	}
	block := func(fields ...string) []byte {
		var b bytes.Buffer
		enc := hpack.NewEncoder(&b)
		for i := 0; i < len(fields); i += 2 {
			_ = enc.WriteField(hpack.HeaderField{Name: fields[i], Value: fields[i+1]})
		}
		return b.Bytes()
	}
	const stream = 1
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: stream, EndHeaders: true,
		BlockFragment: block(":method", "POST", ":scheme", "http", ":authority", authority, ":path", path,
			"te", "trailers"),
	}); err != nil {
		return "", err
	}
	if err := fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: stream, EndHeaders: true, EndStream: true, BlockFragment: block("x-check-trailer", "1"),
	}); err != nil {
		return "", err
	}
	dec := hpack.NewDecoder(4096, nil)
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return "", err
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				if err := fr.WriteSettingsAck(); err != nil {
					return "", err
				}
			}
		case *http2.HeadersFrame:
			if f.StreamID != stream {
				continue
			}
			fields, err := dec.DecodeFull(f.HeaderBlockFragment())
			if err != nil {
				return "", err
			}
			for _, hf := range fields {
				if hf.Name == ":status" {
					return hf.Value, nil
				}
			}
			return "", errors.New("the response's headers carry no :status")
		case *http2.RSTStreamFrame:
			if f.StreamID == stream {
				return "", fmt.Errorf("the stream was reset: %v", f.ErrCode)
			}
		case *http2.GoAwayFrame:
			return "", fmt.Errorf("the connection was closed: %v", f.ErrCode)
		}
	}
}

// stamp asks the processor at addr to stamp a request on the HTTPRoute route, and returns the headers it sets.
func stamp(addr, caFile, certFile, keyFile, route, method, path, body string) ([]*corev3.HeaderValue, error) {
	ns, name, ok := strings.Cut(route, "/")
	if !ok {
		return nil, errors.New("the route is not <namespace>/<httproute>")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("the CA file holds no certificate")
	}
	creds := credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: pool,
		ServerName: "paztport-processor",
	})
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	s, err := extprocv3.NewExternalProcessorClient(conn).Process(ctx)
	if err != nil {
		return nil, err
	}
	metadata, err := routeMetadata(ns, name)
	if err != nil {
		return nil, err
	}
	if err := s.Send(&extprocv3.ProcessingRequest{
		Request: &extprocv3.ProcessingRequest_RequestHeaders{RequestHeaders: &extprocv3.HttpHeaders{
			Headers: &corev3.HeaderMap{Headers: []*corev3.HeaderValue{
				{Key: ":method", RawValue: []byte(method)},
				{Key: ":path", RawValue: []byte(path)},
				{Key: "content-type", RawValue: []byte("application/json")},
			}},
		}},
		Attributes: map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
			"xds.route_metadata": structpb.NewStringValue(metadata),
		}}},
		ProtocolConfig: &extprocv3.ProtocolConfiguration{RequestBodyMode: extprocfilterv3.ProcessingMode_BUFFERED},
	}); err != nil {
		return nil, err
	}
	if _, err := expect[*extprocv3.ProcessingResponse_RequestHeaders](s); err != nil {
		return nil, err
	}
	if err := s.Send(&extprocv3.ProcessingRequest{Request: &extprocv3.ProcessingRequest_RequestBody{
		RequestBody: &extprocv3.HttpBody{Body: []byte(body), EndOfStream: true},
	}}); err != nil {
		return nil, err
	}
	answer, err := expect[*extprocv3.ProcessingResponse_RequestBody](s)
	if err != nil {
		return nil, err
	}
	var set []*corev3.HeaderValue
	for _, h := range answer.RequestBody.GetResponse().GetHeaderMutation().GetSetHeaders() {
		set = append(set, h.GetHeader())
	}
	if len(set) == 0 {
		return nil, errors.New("the processor set no header")
	}
	return set, nil
}

// expect receives the processor's next answer, and refuses any answer but a T.
func expect[T any](s extprocv3.ExternalProcessor_ProcessClient) (T, error) {
	var zero T
	resp, err := s.Recv()
	if err != nil {
		return zero, err
	}
	answer, ok := resp.GetResponse().(T)
	if !ok {
		return zero, fmt.Errorf("the processor answered %T", resp.GetResponse())
	}
	return answer, nil
}

// routeMetadata returns the route metadata Envoy Gateway writes for the HTTPRoute ns/name, in the text form Envoy
// sends it in.
func routeMetadata(ns, name string) (string, error) {
	resources, err := structpb.NewStruct(map[string]any{"resources": []any{
		map[string]any{"kind": "HTTPRoute", "name": name, "namespace": ns},
	}})
	if err != nil {
		return "", err
	}
	b, err := prototext.Marshal(&corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{"envoy-gateway": resources}})
	return string(b), err
}
