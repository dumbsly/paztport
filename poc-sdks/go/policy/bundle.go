// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"errors"
	"fmt"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
)

// ProofBundle is one service's proof bundle, as proofs-<svc>.json holds it: the proofs of the routes the
// service is the caller on, the node before the last, by route. A caller looks up the route it is about to
// complete and sends that proof with the request.
type ProofBundle struct {
	// Service is the service the bundle is for.
	Service string
	// RootID labels the tree the proofs are for.
	RootID string
	// Proofs maps each route to its proof.
	Proofs map[string]Proof
}

var bundleMembers = []string{"proofs", "rootId", "service"}

// ParseProofBundleFile reads a proof bundle file: an object of exactly the strings service and rootId and
// proofs, an object each of whose names is a route of at least two route nodes and each of whose values is
// a proof, as ParseProof reads one.
func ParseProofBundleFile(b []byte) (ProofBundle, error) {
	return parseFile(b, "proof bundle", bundleFromValue)
}

// LoadProofBundleFile reads the proof bundle file at path, as ParseProofBundleFile reads bytes.
func LoadProofBundleFile(path string) (ProofBundle, error) {
	return loadFile(path, "proof bundle", bundleFromValue)
}

func bundleFromValue(v json.Value) (ProofBundle, error) {
	if err := json.Exactly(v, bundleMembers, nil); err != nil {
		return ProofBundle{}, err
	}
	service, err := json.String(v, "service")
	if err != nil {
		return ProofBundle{}, err
	}
	rootID, err := json.String(v, "rootId")
	if err != nil {
		return ProofBundle{}, err
	}
	field, _ := json.Field(v, "proofs")
	if field.Kind() != json.KindObject {
		return ProofBundle{}, errors.New(`the member "proofs" is not an object`)
	}
	members := field.Members()
	proofs := make(map[string]Proof, len(members))
	for _, m := range members {
		if !isRoute(m.Name) {
			return ProofBundle{}, errors.New(`the member "proofs" names a proof by something that is not a route`)
		}
		p, err := proofFromValue(m.Value)
		if err != nil {
			return ProofBundle{}, fmt.Errorf(`the member "proofs" holds a malformed proof: %w`, err)
		}
		proofs[m.Name] = p
	}
	return ProofBundle{Service: service, RootID: rootID, Proofs: proofs}, nil
}

// ProofFor returns the proof for route, and whether the bundle holds one.
func (b ProofBundle) ProofFor(route string) (Proof, bool) {
	p, ok := b.Proofs[route]
	return p, ok
}
