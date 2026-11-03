// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package policy holds what a policy owner signs and what services and verifiers hold of it: the signed
// keyring of every service's public key, the signed Merkle root of the allowed routes, the reply
// certificate that lets one service's key sign session replies, and the proofs that a route is a leaf of
// the tree.
//
// The policy key signs each kind of statement under its own domain prefix, so that no signature can be
// read as another kind:
//
//	keyring            "paztport-keyring\n"    || JCS({notAfter, policy, services})
//	root               "paztport-root\n"       || JCS({notAfter, root, rootId})
//	reply certificate  "paztport-reply-cert\n" || JCS({key, notAfter, policy, svc})
//
// The policy key is kept offline, so what it signed can't be withdrawn, only left to lapse. Each statement
// therefore carries notAfter, in milliseconds since the Unix epoch, after which the policy owner no longer
// vouches for it. Verifying a signature says nothing about time: whoever relies on a statement checks both,
// with Verifies and Current.
//
// The files (keyring.json, root.json, reply-cert.json and proofs-<svc>.json) are read strictly, by the
// spec's rules for files: at most 1 MiB, one JSON value under the protocol's grammar, its members in any
// order and spacing, and exactly the members the object has. A refusal names the rule and the member that
// broke it, and the file where there is one, and never quotes the input.
//
// A route is the services a request passed through, then its receiver, joined with "/", such as
// "gateway/orders/payment". The allowed routes are the leaves of a salted Merkle tree of fixed depth, whose
// root the policy key signs; a caller sends the proof for the route it completes, and a verifier checks it
// against a pinned root with the proof's rootId.
package policy
