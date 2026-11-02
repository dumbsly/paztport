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

// JoinRoute returns the route through nodes: their names joined with "/". A policy's leaf, a verifier's
// route rebuilt from a chain and a caller's proof lookup all build the route here, so that they agree on
// its text.
func JoinRoute(nodes ...string) string {
	return strings.Join(nodes, "/")
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
