// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package routes

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// Map maps each HTTPRoute the edge stamps for, by namespace and name, onto the receiver its requests are
// stamped for: the receiving service's policy name. It is the operator's configuration, read with [Load];
// the zero Map maps nothing. A Map never changes once built.
type Map struct {
	byRoute map[string]string // "<namespace>/<name>" to the receiver
}

// Load reads a routes file: one route a line, as <namespace>/<httproute>=<receiver>, with the space and tab
// around each part ignored, and blank lines and lines whose first other character is # skipped. The
// namespace must be a Kubernetes namespace's name (an RFC 1123 label) and the HTTPRoute's name an object
// name (an RFC 1123 subdomain), so that each line can name a route that exists; the receiver must be a
// route node. Load refuses a file that maps one route twice or maps none, and names the line of any other
// fault.
func Load(path string) (Map, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Map{}, fmt.Errorf("routes: can't read the routes file: %w", err)
	}
	byRoute := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.Trim(sc.Text(), " \t\r")
		if line == "" || line[0] == '#' {
			continue
		}
		key, rcv, err := parseLine(line)
		if err != nil {
			return Map{}, fmt.Errorf("routes: %s: line %d: %w", path, n, err)
		}
		if _, dup := byRoute[key]; dup {
			return Map{}, fmt.Errorf("routes: %s: line %d: the route %s is mapped twice", path, n, key)
		}
		byRoute[key] = rcv
	}
	if err := sc.Err(); err != nil {
		return Map{}, fmt.Errorf("routes: can't read the routes file: %w", err)
	}
	if len(byRoute) == 0 {
		return Map{}, fmt.Errorf("routes: %s maps no route", path)
	}
	return Map{byRoute: byRoute}, nil
}

// parseLine returns the route key and the receiver of one line that is not blank or a comment.
func parseLine(line string) (key, rcv string, err error) {
	route, rcv, ok := strings.Cut(line, "=")
	if !ok || strings.Contains(rcv, "=") {
		return "", "", errors.New("not <namespace>/<httproute>=<receiver>")
	}
	ns, name, ok := strings.Cut(strings.Trim(route, " \t"), "/")
	if !ok {
		return "", "", errors.New("the route is not <namespace>/<httproute>")
	}
	if !label(ns) {
		return "", "", errors.New("the namespace is not a Kubernetes namespace's name")
	}
	if !subdomain(name) {
		return "", "", errors.New("the HTTPRoute's name is not a Kubernetes object name")
	}
	rcv = strings.Trim(rcv, " \t")
	if err := policy.ValidNode(rcv); err != nil {
		return "", "", fmt.Errorf("the receiver is not a route node: %w", err)
	}
	return ns + "/" + name, rcv, nil
}

// label reports whether s is an RFC 1123 label, as Kubernetes names a namespace: 1 to 63 lower-case
// letters, digits and hyphens, beginning and ending with a letter or digit.
func label(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// subdomain reports whether s is an RFC 1123 subdomain, as Kubernetes names most objects: at most 253
// characters of labels joined by dots.
func subdomain(s string) bool {
	if len(s) > 253 {
		return false
	}
	for l := range strings.SplitSeq(s, ".") {
		if !label(l) {
			return false
		}
	}
	return true
}

// Receiver returns the receiver the HTTPRoute name in the namespace ns maps to, and whether it maps to
// one.
func (m Map) Receiver(ns, name string) (string, bool) {
	rcv, ok := m.byRoute[ns+"/"+name]
	return rcv, ok
}

// Receivers returns every receiver the map names, once each, in order.
func (m Map) Receivers() []string {
	var rcvs []string
	for _, r := range m.byRoute {
		rcvs = append(rcvs, r)
	}
	slices.Sort(rcvs)
	return slices.Compact(rcvs)
}
