// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// serve sends one request to the handler and returns the response.
func serve(t *testing.T, h http.Handler, method, host, path string, header http.Header, body io.Reader) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, "http://"+host+path, body)
	for name, values := range header {
		req.Header[name] = values
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestCountsEachHostsStampedAndUnstampedRequests(t *testing.T) {
	h := newEcho()
	stamped := http.Header{"X-Path-Chain": {"anything"}}
	for _, header := range []http.Header{stamped, nil} {
		res := serve(t, h, http.MethodPost, "a", "/orders", header, strings.NewReader(`{}`))
		if res.StatusCode != http.StatusOK {
			t.Fatalf("POST /orders: status %d, want 200", res.StatusCode)
		}
		if b, _ := io.ReadAll(res.Body); len(b) != 0 {
			t.Fatalf("POST /orders: body %q, want none", b)
		}
	}
	serve(t, h, http.MethodGet, "b", "/", nil, nil)

	res := serve(t, h, http.MethodGet, "anyone", "/counts", nil, nil)
	got, _ := io.ReadAll(res.Body)
	want := "a stamped=1 unstamped=1\nb stamped=0 unstamped=1\n"
	if res.StatusCode != http.StatusOK || string(got) != want {
		t.Fatalf("GET /counts: status %d, body %q; want 200, %q", res.StatusCode, got, want)
	}
}

// countingReader counts the bytes read from it.
type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

func TestReadsALargeBodyWhole(t *testing.T) {
	const size = 300 << 10
	body := &countingReader{r: bytes.NewReader(make([]byte, size))}
	res := serve(t, newEcho(), http.MethodPost, "a", "/orders", nil, body)
	if res.StatusCode != http.StatusOK || body.n != size {
		t.Fatalf("a %d-byte body: status %d, %d bytes read; want 200 and every byte read", size, res.StatusCode, body.n)
	}
}
