// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"strings"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/text"
)

var (
	errNodeEmpty     = errors.New("paztport policy: a route node is empty")
	errNodeDots      = errors.New(`paztport policy: a route node is "." or ".."`)
	errNodeSeparator = errors.New(`paztport policy: a route node holds "/", "\" or "|"`)
	errNodeText      = errors.New("paztport policy: a route node is not valid UTF-8")
	errServiceHash   = errors.New(`paztport policy: a service name holds "#"`)
	errReceiver      = errors.New(`paztport policy: a receiver is not a service, or a service, "#" and an operation name`)
)

// ValidNode checks node by the rules for a route node: it is not empty, is neither "." nor "..", holds no
// '/', '\' or '|', and is valid UTF-8, so holds no lone surrogate. Node names become route segments and
// file names (proofs-<svc>.json), so one that could climb a directory, or run two nodes into one, must
// never reach a signed policy. The error names the rule, never the node.
func ValidNode(node string) error {
	switch {
	case node == "":
		return errNodeEmpty
	case node == "." || node == "..":
		return errNodeDots
	case strings.ContainsAny(node, `/\|`):
		return errNodeSeparator
	case !text.Valid(node):
		return errNodeText
	}
	return nil
}

// ValidService checks name by the rules for a service name: a valid route node ([ValidNode]) holding no '#',
// which separates a service from an operation in a stamp's rcv. A service name, and an operation name, that
// held one could not be told from the pair it would imitate. The error names the rule, never the name.
func ValidService(name string) error {
	if err := ValidNode(name); err != nil {
		return err
	}
	if strings.Contains(name, "#") {
		return errServiceHash
	}
	return nil
}

// ValidReceiver checks a stamp's rcv: a valid service name ([ValidService]), or a valid service name, '#' and
// an operation that is itself a valid service name. It refuses "payment#", "#pay" and "a#b#c". The error
// names the rule, never the receiver.
func ValidReceiver(rcv string) error {
	service, operation, found := strings.Cut(rcv, "#")
	if ValidService(service) != nil || (found && ValidService(operation) != nil) {
		return errReceiver
	}
	return nil
}

// JoinRoute returns the route through nodes: their names joined with "/". A policy's leaf, a verifier's
// route rebuilt from a chain and a caller's proof lookup all build the route here, so that they agree on
// its text.
func JoinRoute(nodes ...string) string {
	return strings.Join(nodes, "/")
}

// Service returns the service a route node names: the text before the first '#', or the whole node when it
// has none. A node is <service> or <service>#<operation>; policy bundles and keyrings are keyed by service.
func Service(node string) string {
	service, _, _ := strings.Cut(node, "#")
	return service
}

// AddressedTo reports whether a stamp's rcv addresses the service svc: the name itself, or the name, '#' and an
// operation name, which is a valid route node ([ValidNode]) holding no '#'. An empty or invalid operation, or a
// longer service name, is not addressed to it.
func AddressedTo(rcv, svc string) bool {
	if rcv == svc {
		return true
	}
	op, found := strings.CutPrefix(rcv, svc+"#")
	return found && ValidNode(op) == nil && !strings.Contains(op, "#")
}

// isRoute reports whether route is a route: at least two valid route nodes joined with "/".
func isRoute(route string) bool {
	nodes := strings.Split(route, "/")
	if len(nodes) < 2 {
		return false
	}
	for _, node := range nodes {
		if ValidNode(node) != nil {
			return false
		}
	}
	return true
}
