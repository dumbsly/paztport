// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"errors"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	// filterAttributes is the key Envoy's ext_proc filter sends its attributes under: the filter's type
	// name, whatever the filter instance is called.
	filterAttributes = "envoy.filters.http.ext_proc"
	// routeMetadata is the attribute holding the matched route's metadata.
	routeMetadata = "xds.route_metadata"
	// gatewayNamespace is the filter metadata namespace Envoy Gateway describes a route's resources in.
	gatewayNamespace = "envoy-gateway"
	// httpRouteKind is the kind Envoy Gateway names an HTTPRoute by.
	httpRouteKind = "HTTPRoute"
)

// FromAttributes returns the namespace and name of the HTTPRoute that Envoy Gateway built the matched
// route from, read from the attributes of an ext_proc request that asked for xds.route_metadata.
//
// Envoy's ext_proc filter sends the attributes it evaluates in one Struct under its own type name,
// envoy.filters.http.ext_proc. A CEL value that is a message, such as the route's Metadata, is sent as a
// string: the message in protobuf text format, on one line. Envoy Gateway writes each route's Metadata
// with a filter_metadata entry "envoy-gateway" whose "resources" list holds one resource, a Struct of the
// resource's kind, name and namespace, with its annotations and the rule's section name when there are
// any.
//
// FromAttributes refuses attributes that do not hold that: no route metadata, or metadata that is not a
// string of text-format Metadata; no envoy-gateway entry or resources list; and any resources list but
// one of a single HTTPRoute with a name and a namespace. The edge stamps for a route only as its
// configuration maps it, so a route it cannot name is never stamped.
func FromAttributes(attrs map[string]*structpb.Struct) (ns, name string, err error) {
	v, ok := attrs[filterAttributes].GetFields()[routeMetadata]
	if !ok {
		return "", "", errors.New("routes: the request carries no route metadata")
	}
	text, ok := v.GetKind().(*structpb.Value_StringValue)
	if !ok {
		return "", "", errors.New("routes: the route metadata is not text")
	}
	var md corev3.Metadata
	if err := prototext.Unmarshal([]byte(text.StringValue), &md); err != nil {
		return "", "", errors.New("routes: the route metadata is not text-format Metadata")
	}
	fields := md.GetFilterMetadata()[gatewayNamespace].GetFields()
	resources, ok := fields["resources"].GetKind().(*structpb.Value_ListValue)
	if !ok {
		return "", "", errors.New("routes: the route metadata lists no Envoy Gateway resources")
	}
	if n := len(resources.ListValue.GetValues()); n != 1 {
		return "", "", errors.New("routes: the route metadata does not name exactly one resource")
	}
	res := resources.ListValue.GetValues()[0].GetStructValue().GetFields()
	kind, name, ns := stringField(res, "kind"), stringField(res, "name"), stringField(res, "namespace")
	if kind != httpRouteKind || name == "" || ns == "" {
		return "", "", errors.New("routes: the route metadata does not name an HTTPRoute by namespace and name")
	}
	return ns, name, nil
}

// stringField returns the string fields holds under key, or "" when it holds none.
func stringField(fields map[string]*structpb.Value, key string) string {
	if s, ok := fields[key].GetKind().(*structpb.Value_StringValue); ok {
		return s.StringValue
	}
	return ""
}
