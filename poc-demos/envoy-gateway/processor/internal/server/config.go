// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"unicode"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/edge"
)

// MaxBodyLimit is the largest body limit the processor takes: 1 GiB. Envoy holds a buffered body in memory,
// and so does the processor, so a limit near this is already far past what an edge should buffer.
const MaxBodyLimit = 1 << 30

// Config is the processor's configuration. [FromEnv] reads it from the environment, where the chart sets it.
type Config struct {
	// Listen is the gRPC port's address, PROCESSOR_LISTEN, by default :9002.
	Listen string
	// AdminListen is the address of the plain-HTTP port that serves /metrics, /readyz and /livez,
	// PROCESSOR_ADMIN_LISTEN, by default :9090. It is never the gRPC port.
	AdminListen string
	// TLSCert and TLSKey are the processor's server certificate and its key, PROCESSOR_TLS_CERT and
	// PROCESSOR_TLS_KEY, in PEM.
	TLSCert, TLSKey string
	// ClientCA is the authority whose certificate the edge's client certificate must chain to,
	// PROCESSOR_CLIENT_CA, in PEM.
	ClientCA string
	// Key is the edge's private key, PROCESSOR_KEY.
	Key string
	// Pin is the pinned policy key, PROCESSOR_PIN.
	Pin string
	// Keyrings and Roots are the keyring and root files, PROCESSOR_KEYRINGS and PROCESSOR_ROOTS, each a
	// comma-separated list, so that an old and a new one can overlap during a rollover.
	Keyrings, Roots []string
	// Bundle is the edge's proof bundle, PROCESSOR_BUNDLE.
	Bundle string
	// Routes is the routes file, PROCESSOR_ROUTES, which maps each HTTPRoute to its receiver.
	Routes string
	// BodyLimit is the most bytes of body the edge stamps, PROCESSOR_BODY_LIMIT, from 1 to [MaxBodyLimit].
	BodyLimit int
	// Inst is the instance the edge's stamps name: the pod's name, POD_NAME.
	Inst string
}

// FromEnv reads the processor's configuration with getenv, such as os.Getenv. Every setting but the two
// listen addresses is required, and refused unset or blank, naming it; a file list is refused with an
// empty entry, a body limit that is not a whole number of bytes from 1 to [MaxBodyLimit], and an admin
// address on the gRPC port. Reload is a restart: the configuration and every file it names are read once.
func FromEnv(getenv func(string) string) (Config, error) {
	r := reader{getenv: getenv}
	c := Config{
		Listen:      r.optional("PROCESSOR_LISTEN", ":9002"),
		AdminListen: r.optional("PROCESSOR_ADMIN_LISTEN", ":9090"),
		TLSCert:     r.required("PROCESSOR_TLS_CERT"),
		TLSKey:      r.required("PROCESSOR_TLS_KEY"),
		ClientCA:    r.required("PROCESSOR_CLIENT_CA"),
		Key:         r.required("PROCESSOR_KEY"),
		Keyrings:    r.list("PROCESSOR_KEYRINGS"),
		Roots:       r.list("PROCESSOR_ROOTS"),
		Pin:         r.required("PROCESSOR_PIN"),
		Bundle:      r.required("PROCESSOR_BUNDLE"),
		Routes:      r.required("PROCESSOR_ROUTES"),
		BodyLimit:   r.bodyLimit("PROCESSOR_BODY_LIMIT"),
		Inst:        r.required(edge.InstEnv),
	}
	if r.err == nil && samePort(c.Listen, c.AdminListen) {
		r.fail("PROCESSOR_ADMIN_LISTEN " + strconv.Quote(c.AdminListen) + " is on the gRPC port, PROCESSOR_LISTEN " +
			strconv.Quote(c.Listen))
	}
	if r.err != nil {
		return Config{}, r.err
	}
	return c, nil
}

// reader reads settings, keeping the first fault.
type reader struct {
	getenv func(string) string
	err    error
}

func (r *reader) fail(msg string) {
	if r.err == nil {
		r.err = errors.New("server: " + msg)
	}
}

func (r *reader) optional(name, def string) string {
	if v := strings.TrimFunc(r.getenv(name), unicode.IsSpace); v != "" {
		return v
	}
	return def
}

func (r *reader) required(name string) string {
	v := strings.TrimFunc(r.getenv(name), unicode.IsSpace)
	if v == "" {
		r.fail(name + " is unset or blank")
	}
	return v
}

func (r *reader) list(name string) []string {
	v := r.required(name)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	for i, p := range parts {
		parts[i] = strings.TrimFunc(p, unicode.IsSpace)
		if parts[i] == "" {
			r.fail(name + " has an empty entry")
			return nil
		}
	}
	return parts
}

func (r *reader) bodyLimit(name string) int {
	v := r.required(name)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > MaxBodyLimit {
		r.fail(name + " is not a whole number of bytes from 1 to " + strconv.Itoa(MaxBodyLimit))
		return 0
	}
	return n
}

// samePort reports whether the addresses a and b name the same port on hosts that could overlap: the same
// host, or either one every interface.
func samePort(a, b string) bool {
	ah, ap, errA := net.SplitHostPort(a)
	bh, bp, errB := net.SplitHostPort(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return ap == bp && (ah == bh || ah == "" || bh == "" || ah == "0.0.0.0" || bh == "0.0.0.0" || ah == "::" || bh == "::")
}
