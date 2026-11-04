// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/server"
)

// env is a full environment for the processor, without its two optional listen addresses.
func env() map[string]string {
	return map[string]string{
		"PROCESSOR_TLS_CERT":   "/tls/tls.crt",
		"PROCESSOR_TLS_KEY":    "/tls/tls.key",
		"PROCESSOR_CLIENT_CA":  "/tls/ca.crt",
		"PROCESSOR_KEY":        "/keys/edge.key",
		"PROCESSOR_KEYRINGS":   "/policy/keyring.json",
		"PROCESSOR_ROOTS":      "/policy/root.json",
		"PROCESSOR_PIN":        "/policy/policy.pub",
		"PROCESSOR_BUNDLE":     "/policy/proofs-edge.json",
		"PROCESSOR_ROUTES":     "/routes/routes.txt",
		"PROCESSOR_BODY_LIMIT": "1048576",
		"POD_NAME":             "edge-processor-5d8f-x2",
	}
}

func lookup(e map[string]string) func(string) string {
	return func(k string) string { return e[k] }
}

// TestConfigFromEnv reads every setting, with the two listen addresses' defaults.
func TestConfigFromEnv(t *testing.T) {
	got, err := server.FromEnv(lookup(env()))
	if err != nil {
		t.Fatal(err)
	}
	want := server.Config{
		Listen: ":9002", AdminListen: ":9090",
		TLSCert: "/tls/tls.crt", TLSKey: "/tls/tls.key", ClientCA: "/tls/ca.crt",
		Key: "/keys/edge.key", Pin: "/policy/policy.pub",
		Keyrings: []string{"/policy/keyring.json"}, Roots: []string{"/policy/root.json"},
		Bundle: "/policy/proofs-edge.json", Routes: "/routes/routes.txt",
		BodyLimit: 1048576, Inst: "edge-processor-5d8f-x2",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FromEnv =\n%+v\nwant\n%+v", got, want)
	}
}

// TestConfigFromEnvReadsListsAndAddresses splits the keyrings and roots on commas, trimming the space
// around each, and takes the listen addresses given.
func TestConfigFromEnvReadsListsAndAddresses(t *testing.T) {
	e := env()
	e["PROCESSOR_KEYRINGS"] = "/policy/old/keyring.json, /policy/new/keyring.json"
	e["PROCESSOR_ROOTS"] = " /policy/old/root.json,/policy/new/root.json "
	e["PROCESSOR_LISTEN"] = "0.0.0.0:7002"
	e["PROCESSOR_ADMIN_LISTEN"] = "0.0.0.0:7090"
	got, err := server.FromEnv(lookup(e))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/policy/old/keyring.json", "/policy/new/keyring.json"}
	if !reflect.DeepEqual(got.Keyrings, want) {
		t.Errorf("Keyrings = %q, want %q", got.Keyrings, want)
	}
	if want := []string{"/policy/old/root.json", "/policy/new/root.json"}; !reflect.DeepEqual(got.Roots, want) {
		t.Errorf("Roots = %q, want %q", got.Roots, want)
	}
	if got.Listen != "0.0.0.0:7002" || got.AdminListen != "0.0.0.0:7090" {
		t.Errorf("Listen, AdminListen = %q, %q", got.Listen, got.AdminListen)
	}
}

// TestConfigFromEnvRefuses refuses a missing or blank setting, naming it, an empty entry in a list, a
// body limit that is not a whole number of bytes from 1 to 1 GiB, and the admin port on the gRPC port.
func TestConfigFromEnvRefuses(t *testing.T) {
	for _, name := range []string{
		"PROCESSOR_TLS_CERT", "PROCESSOR_TLS_KEY", "PROCESSOR_CLIENT_CA", "PROCESSOR_KEY", "PROCESSOR_KEYRINGS",
		"PROCESSOR_ROOTS", "PROCESSOR_PIN", "PROCESSOR_BUNDLE", "PROCESSOR_ROUTES", "PROCESSOR_BODY_LIMIT",
		"POD_NAME",
	} {
		for _, value := range []string{"", "  "} {
			e := env()
			e[name] = value
			if _, err := server.FromEnv(lookup(e)); err == nil || !strings.Contains(err.Error(), name) {
				t.Errorf("FromEnv with %s=%q = %v, want an error naming it", name, value, err)
			}
		}
	}
	for _, tc := range []struct{ name, value, want string }{
		{"PROCESSOR_KEYRINGS", "/a.json,,/b.json", "PROCESSOR_KEYRINGS"},
		{"PROCESSOR_ROOTS", "/a.json,", "PROCESSOR_ROOTS"},
		{"PROCESSOR_BODY_LIMIT", "0", "PROCESSOR_BODY_LIMIT"},
		{"PROCESSOR_BODY_LIMIT", "-1", "PROCESSOR_BODY_LIMIT"},
		{"PROCESSOR_BODY_LIMIT", "1MiB", "PROCESSOR_BODY_LIMIT"},
		{"PROCESSOR_BODY_LIMIT", "1073741825", "PROCESSOR_BODY_LIMIT"},
		{"PROCESSOR_ADMIN_LISTEN", ":9002", "PROCESSOR_ADMIN_LISTEN"},
	} {
		e := env()
		e[tc.name] = tc.value
		if _, err := server.FromEnv(lookup(e)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("FromEnv with %s=%q = %v, want an error naming %s", tc.name, tc.value, err, tc.want)
		}
	}
	e := env()
	e["PROCESSOR_BODY_LIMIT"] = "1073741824"
	if _, err := server.FromEnv(lookup(e)); err != nil {
		t.Errorf("FromEnv with a body limit of 1 GiB = %v", err)
	}
}
