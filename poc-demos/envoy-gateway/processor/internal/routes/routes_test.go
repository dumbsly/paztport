// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package routes_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/routes"
)

// attributes returns the attributes Envoy's ext_proc filter sends with xds.route_metadata as the text
// metadata, under the filter's own name.
func attributes(metadata string) map[string]*structpb.Struct {
	return map[string]*structpb.Struct{
		"envoy.filters.http.ext_proc": {Fields: map[string]*structpb.Value{
			"xds.route_metadata": structpb.NewStringValue(metadata),
		}},
	}
}

// metadataText returns the text form of route metadata whose envoy-gateway namespace holds fields.
func metadataText(t *testing.T, fields map[string]any) string {
	t.Helper()
	s, err := structpb.NewStruct(fields)
	if err != nil {
		t.Fatal(err)
	}
	md := &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{"envoy-gateway": s}}
	b, err := prototext.Marshal(md)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// httpRoute returns the resource Envoy Gateway writes for an HTTPRoute.
func httpRoute(namespace, name string) map[string]any {
	return map[string]any{"kind": "HTTPRoute", "name": name, "namespace": namespace}
}

// TestFromAttributesReadsACapturedRoute reads the route from route metadata exactly as Envoy v1.39.1 sent it
// to the processor under Envoy Gateway v1.9.2, for the HTTPRoute paztport/orders with the
// BackendTrafficPolicy orders-routes attached: one line, ending in a space, with the attached policies listed
// before the route's resources. On Envoy Gateway v1.10.0 the processor still reads the route: the cluster's
// check 1, through a mapped route, passes.
func TestFromAttributesReadsACapturedRoute(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", "route-metadata.captured.txtpb"))
	if err != nil {
		t.Fatal(err)
	}
	ns, name, err := routes.FromAttributes(attributes(string(b)))
	if err != nil || ns != "paztport" || name != "orders" {
		t.Fatalf("FromAttributes = %q, %q, %v, want paztport, orders", ns, name, err)
	}
}

// TestFromAttributesIgnoresWhatItDoesNotRead reads the route beside a rule's section name, annotations,
// attached policies, other filters' metadata and other attributes.
func TestFromAttributesIgnoresWhatItDoesNotRead(t *testing.T) {
	res := httpRoute("shop", "orders")
	res["sectionName"] = "create"
	res["annotations"] = map[string]any{"gateway.envoyproxy.io/team": "payments"}
	s, err := structpb.NewStruct(map[string]any{
		"resources": []any{res},
		"policies":  []any{map[string]any{"kind": "BackendTrafficPolicy", "name": "p", "namespace": "shop"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	other, err := structpb.NewStruct(map[string]any{
		"resources": []any{httpRoute("x", "y"), httpRoute("x", "z")},
	})
	if err != nil {
		t.Fatal(err)
	}
	md := &corev3.Metadata{FilterMetadata: map[string]*structpb.Struct{
		"envoy-gateway": s, "another-filter": other,
	}}
	b, err := prototext.Marshal(md)
	if err != nil {
		t.Fatal(err)
	}
	attrs := attributes(string(b))
	attrs["envoy.filters.http.ext_proc"].Fields["request.path"] = structpb.NewStringValue("/orders")
	ns, name, err := routes.FromAttributes(attrs)
	if err != nil || ns != "shop" || name != "orders" {
		t.Fatalf("FromAttributes = %q, %q, %v, want shop, orders", ns, name, err)
	}
}

// TestFromAttributesRefuses refuses route metadata that is absent, malformed or names anything but one
// HTTPRoute.
func TestFromAttributesRefuses(t *testing.T) {
	text := func(fields map[string]any) map[string]*structpb.Struct {
		return attributes(metadataText(t, fields))
	}
	for _, tc := range []struct {
		name  string
		attrs map[string]*structpb.Struct
	}{
		{"no attributes", nil},
		{"no ext_proc attributes", map[string]*structpb.Struct{"other": {}}},
		{"a nil attribute struct", map[string]*structpb.Struct{"envoy.filters.http.ext_proc": nil}},
		{"no route metadata", map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {
			Fields: map[string]*structpb.Value{"request.path": structpb.NewStringValue("/")}}}},
		{"route metadata that is not a string", map[string]*structpb.Struct{"envoy.filters.http.ext_proc": {
			Fields: map[string]*structpb.Value{"xds.route_metadata": structpb.NewNumberValue(1)}}}},
		{"route metadata that is not text proto", attributes(`filter_metadata { key: "envoy-gateway" `)},
		{"route metadata naming a field Metadata lacks", attributes(`route_name: "orders"`)},
		{"empty route metadata", attributes("")},
		{"no envoy-gateway metadata", attributes(`filter_metadata { key: "other" value { } }`)},
		{"no resources", text(map[string]any{"policies": []any{}})},
		{"resources that are not a list", text(map[string]any{"resources": httpRoute("shop", "orders")})},
		{"no resource", text(map[string]any{"resources": []any{}})},
		{"two resources", text(map[string]any{"resources": []any{
			httpRoute("shop", "orders"), httpRoute("shop", "pay")}})},
		{"two copies of one resource", text(map[string]any{"resources": []any{
			httpRoute("shop", "orders"), httpRoute("shop", "orders")}})},
		{"a resource that is not a struct", text(map[string]any{"resources": []any{"shop/orders"}})},
		{"a GRPCRoute", text(map[string]any{"resources": []any{
			map[string]any{"kind": "GRPCRoute", "name": "orders", "namespace": "shop"}}})},
		{"a kind in another case", text(map[string]any{"resources": []any{
			map[string]any{"kind": "httproute", "name": "orders", "namespace": "shop"}}})},
		{"no kind", text(map[string]any{"resources": []any{
			map[string]any{"name": "orders", "namespace": "shop"}}})},
		{"no name", text(map[string]any{"resources": []any{
			map[string]any{"kind": "HTTPRoute", "namespace": "shop"}}})},
		{"no namespace", text(map[string]any{"resources": []any{
			map[string]any{"kind": "HTTPRoute", "name": "orders"}}})},
		{"an empty name", text(map[string]any{"resources": []any{httpRoute("shop", "")}})},
		{"an empty namespace", text(map[string]any{"resources": []any{httpRoute("", "orders")}})},
		{"a name that is not a string", text(map[string]any{"resources": []any{
			map[string]any{"kind": "HTTPRoute", "name": 7.0, "namespace": "shop"}}})},
	} {
		ns, name, err := routes.FromAttributes(tc.attrs)
		if err == nil {
			t.Errorf("%s: FromAttributes = %q, %q, want an error", tc.name, ns, name)
		}
		if ns != "" || name != "" {
			t.Errorf("%s: with an error, FromAttributes gave %q, %q", tc.name, ns, name)
		}
	}
}

// writeRoutes writes text to a routes file in a new directory and returns its path.
func writeRoutes(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "routes.txt")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestLoadReadsEachRoute reads one route a line, skipping comments and blank lines and the white space
// around each part, and gives no receiver for a route it does not map.
func TestLoadReadsEachRoute(t *testing.T) {
	m, err := routes.Load(writeRoutes(t, "# routes the edge stamps\n\nshop/orders=orders\n"+
		"  shop/orders-v2 = orders \r\n\t# a comment\nbilling/pay.api=payment\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ns, name, want string }{
		{"shop", "orders", "orders"}, {"shop", "orders-v2", "orders"}, {"billing", "pay.api", "payment"},
	} {
		if got, ok := m.Receiver(tc.ns, tc.name); !ok || got != tc.want {
			t.Errorf("Receiver(%q, %q) = %q, %t, want %q", tc.ns, tc.name, got, ok, tc.want)
		}
	}
	for _, tc := range []struct{ ns, name string }{
		{"shop", "pay.api"}, {"billing", "orders"}, {"", ""}, {"shop/orders", ""},
	} {
		if got, ok := m.Receiver(tc.ns, tc.name); ok || got != "" {
			t.Errorf("Receiver(%q, %q) = %q, %t, want none", tc.ns, tc.name, got, ok)
		}
	}
	if got := m.Receivers(); !slices.Equal(got, []string{"orders", "payment"}) {
		t.Errorf("Receivers = %q, want each receiver once, sorted", got)
	}
}

// TestLoadRefuses refuses a routes file that maps nothing, maps one route twice, maps a route to what
// is not a route node, or holds a line that is not a route, naming the line.
func TestLoadRefuses(t *testing.T) {
	for _, tc := range []struct{ name, text, want string }{
		{"an empty file", "", "maps no route"},
		{"only comments", "# nothing\n\n", "maps no route"},
		{"a route twice", "shop/orders=orders\nshop/orders=payment\n", "line 2"},
		{"a route twice, spaced differently", "shop/orders=orders\n shop/orders =orders\n", "line 2"},
		{"a receiver with a slash", "shop/orders=orders/v2\n", "line 1"},
		{"a receiver of a dot", "shop/orders=.\n", "line 1"},
		{"a receiver with a bar", "shop/orders=a|b\n", "line 1"},
		{"no receiver", "shop/orders=\n", "line 1"},
		{"no equals sign", "# routes\nshop/orders orders\n", "line 2"},
		{"two equals signs", "shop/orders=orders=x\n", "line 1"},
		{"no namespace", "orders=orders\n", "line 1"},
		{"an empty namespace", "/orders=orders\n", "line 1"},
		{"an empty name", "shop/=orders\n", "line 1"},
		{"two slashes", "shop/orders/v2=orders\n", "line 1"},
		{"a namespace in capitals", "Shop/orders=orders\n", "line 1"},
		{"a name with a space", "shop/my orders=orders\n", "line 1"},
		{"a namespace with a dot", "shop.eu/orders=orders\n", "line 1"},
		{"a name ending in a hyphen", "shop/orders-=orders\n", "line 1"},
		{"a namespace over 63 characters", strings.Repeat("a", 64) + "/orders=orders\n", "line 1"},
		{"a name over 253 characters", "shop/" + strings.Repeat("a", 254) + "=orders\n", "line 1"},
	} {
		m, err := routes.Load(writeRoutes(t, tc.text))
		if err == nil {
			t.Errorf("%s: Load = %v, want an error", tc.name, m)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: the error %q does not say %q", tc.name, err, tc.want)
		}
	}
	if _, err := routes.Load(filepath.Join(t.TempDir(), "absent.txt")); err == nil {
		t.Error("Load of a missing file gave no error")
	}
}

// TestZeroMapMapsNothing gives no receiver from the zero Map.
func TestZeroMapMapsNothing(t *testing.T) {
	var m routes.Map
	if got, ok := m.Receiver("shop", "orders"); ok || got != "" {
		t.Fatalf("Receiver = %q, %t", got, ok)
	}
	if got := m.Receivers(); len(got) != 0 {
		t.Fatalf("Receivers = %q", got)
	}
}
