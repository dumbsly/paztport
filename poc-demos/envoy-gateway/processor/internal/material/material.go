// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package material

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/dumbsly/paztport/poc-sdks/go/keys"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"

	"github.com/dumbsly/paztport/poc-demos/envoy-gateway/processor/internal/routes"
)

// Service is the name the edge signs as, and the first node of every route it stamps.
const Service = "edge"

// The checks Load and Ready make, one error each. A refusal wraps one of them, so errors.Is tells which
// check failed, and names the file by its place in its list where there is more than one.
var (
	ErrKey            = errors.New("material: the edge's private key does not load")
	ErrPin            = errors.New("material: the pinned policy key does not load")
	ErrKeyring        = errors.New("material: a keyring does not load")
	ErrKeyringPin     = errors.New("material: a keyring does not verify under the pinned policy key")
	ErrKeyringExpired = errors.New("material: a keyring is past its notAfter")
	ErrRoot           = errors.New("material: a root does not load")
	ErrRootPin        = errors.New("material: a root does not verify under the pinned policy key")
	ErrRootExpired    = errors.New("material: a root is past its notAfter")
	ErrEdgeKey        = errors.New("material: no keyring holds the private key's public half as edge's key")
	ErrBundle         = errors.New("material: the proof bundle does not load")
	ErrBundleService  = errors.New("material: the proof bundle is not the edge's")
	ErrBundleRoot     = errors.New("material: the proof bundle's rootId is no loaded root's")
	ErrRoutes         = errors.New("material: the routes map no route")
	ErrNoProof        = errors.New("material: the proof bundle holds no proof for a mapped receiver's route")
	ErrProof          = errors.New("material: a mapped receiver's proof does not verify against its root")
	ErrExpired        = errors.New("material: the policy material has expired")
)

// Config names the edge's policy material and holds the routes it stamps for.
type Config struct {
	// KeyPath is the edge's private key file, edge.key.
	KeyPath string
	// PinPath is the pinned policy key, policy.pub.
	PinPath string
	// KeyringPaths are the keyring files, one or more, at least one of which must hold the edge's public
	// key: two during a rollover of the edge's key, the keyring for the old key and the one for the new.
	KeyringPaths []string
	// RootPaths are the signed root files, one or more.
	RootPaths []string
	// BundlePath is the edge's proof bundle, proofs-edge.json.
	BundlePath string
	// Routes maps each HTTPRoute to its receiver.
	Routes routes.Map
}

// Set is the edge's policy material, loaded and checked: its key, its proof bundle and the routes it
// stamps for, and how long the material vouches for its stamps. A Set never changes once loaded, so it is
// safe for concurrent use.
type Set struct {
	key      ed25519.PrivateKey
	bundle   policy.ProofBundle
	routes   routes.Map
	notAfter int64 // the last moment a receiver pinning this material accepts the edge's stamps
}

// Load loads the material cfg names and checks it at the time now gives, in milliseconds since the Unix
// epoch, so that the edge never starts on material that would not stamp what its routes promise:
//
//   - the private key loads ([ErrKey]), and so does the pin ([ErrPin]);
//   - there is at least one keyring, and each loads ([ErrKeyring]), verifies under the pin
//     ([ErrKeyringPin]) and is current ([ErrKeyringExpired]);
//   - there is at least one root, and each loads ([ErrRoot]), verifies under the pin ([ErrRootPin]) and
//     is current ([ErrRootExpired]);
//   - at least one keyring's edge key is the private key's public half ([ErrEdgeKey]);
//   - the proof bundle loads ([ErrBundle]), is the edge's ([ErrBundleService]) and names the rootId of a
//     loaded root ([ErrBundleRoot]);
//   - the routes map at least one route ([ErrRoutes]), and for each receiver they map to, the bundle
//     holds the proof of the route edge/<receiver> ([ErrNoProof]), which verifies against a loaded root
//     with the proof's rootId ([ErrProof]).
//
// The SDK's caller sends a call with no proof when its bundle holds none, so these checks are what makes
// a missing proof a fault at start rather than a refusal at every receiver.
func Load(cfg Config, now func() int64) (*Set, error) {
	at := now()
	key, err := keys.LoadPrivate(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrKey, err)
	}
	pin, err := keys.LoadPin(cfg.PinPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrPin, err)
	}
	if len(cfg.KeyringPaths) == 0 {
		return nil, fmt.Errorf("%w: no keyring file is named", ErrKeyring)
	}
	pub := key.Public().(ed25519.PublicKey)
	keyNotAfter := int64(math.MinInt64) // the latest notAfter of a keyring holding the key
	for i, path := range cfg.KeyringPaths {
		kf, err := policy.LoadKeyringFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: keyrings[%d]: %w", ErrKeyring, i, err)
		}
		if !kf.Verifies(pin) {
			return nil, fmt.Errorf("%w: keyrings[%d]", ErrKeyringPin, i)
		}
		if !kf.Current(at) {
			return nil, fmt.Errorf("%w: keyrings[%d]", ErrKeyringExpired, i)
		}
		kr, err := kf.Keyring()
		if err != nil {
			return nil, fmt.Errorf("%w: keyrings[%d]: %w", ErrKeyring, i, err)
		}
		if bytes.Equal(kr[Service], pub) {
			keyNotAfter = max(keyNotAfter, kf.NotAfter)
		}
	}
	if keyNotAfter == math.MinInt64 {
		return nil, ErrEdgeKey
	}

	if len(cfg.RootPaths) == 0 {
		return nil, fmt.Errorf("%w: no root file is named", ErrRoot)
	}
	roots := make([]policy.Root, len(cfg.RootPaths))
	for i, path := range cfg.RootPaths {
		r, err := policy.LoadRootFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: roots[%d]: %w", ErrRoot, i, err)
		}
		if !r.Verifies(pin) {
			return nil, fmt.Errorf("%w: roots[%d]", ErrRootPin, i)
		}
		if !r.Current(at) {
			return nil, fmt.Errorf("%w: roots[%d]", ErrRootExpired, i)
		}
		roots[i] = r
	}

	bundle, err := policy.LoadProofBundleFile(cfg.BundlePath)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBundle, err)
	}
	if bundle.Service != Service {
		return nil, ErrBundleService
	}
	if !hasRoot(roots, bundle.RootID) {
		return nil, ErrBundleRoot
	}

	receivers := cfg.Routes.Receivers()
	if len(receivers) == 0 {
		return nil, ErrRoutes
	}
	notAfter := min(keyNotAfter, latestRoot(roots, bundle.RootID))
	for _, rcv := range receivers {
		route := policy.JoinRoute(Service, rcv)
		p, ok := bundle.ProofFor(route)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrNoProof, route)
		}
		if !proves(p, route, roots) {
			return nil, fmt.Errorf("%w: %s", ErrProof, route)
		}
		notAfter = min(notAfter, latestRoot(roots, p.RootID))
	}
	return &Set{key: key, bundle: bundle, routes: cfg.Routes, notAfter: notAfter}, nil
}

// latestRoot returns the latest notAfter of the roots with the rootId id, or math.MinInt64 when none has
// it. Roots that share a rootId are renewals of one tree, so a proof stays good while any one is current.
func latestRoot(roots []policy.Root, id string) int64 {
	latest := int64(math.MinInt64)
	for _, r := range roots {
		if r.RootID == id {
			latest = max(latest, r.NotAfter)
		}
	}
	return latest
}

// hasRoot reports whether one of roots has the rootId id.
func hasRoot(roots []policy.Root, id string) bool {
	for _, r := range roots {
		if r.RootID == id {
			return true
		}
	}
	return false
}

// proves reports whether p proves route against one of roots with p's rootId.
func proves(p policy.Proof, route string, roots []policy.Root) bool {
	for _, r := range roots {
		if r.RootID != p.RootID {
			continue
		}
		if b, err := r.Bytes(); err == nil && p.Verify(route, b) {
			return true
		}
	}
	return false
}

// Ready returns nil while the material still vouches for the edge's stamps at now, in milliseconds since
// the Unix epoch, and [ErrExpired] once it does not: from then the edge must refuse rather than stamp,
// since a receiver pinning the same material would refuse what it stamped. A stamp needs a current
// keyring holding the edge's key and, for its proof, a current root of the proof's tree. So the material
// is ready until the earlier of the latest notAfter of the keyrings holding the key and, for the bundle's
// rootId and each mapped receiver's proof's, the latest notAfter of the roots with it. Each member keeps
// its own window, as the SDK's verify.Pinned keeps them: a keyring or root that expires first, such as
// the old one in a rollover, does not end it.
func (s *Set) Ready(now int64) error {
	if now > s.notAfter {
		return fmt.Errorf("%w: at %d, past %d", ErrExpired, now, s.notAfter)
	}
	return nil
}

// TimeLeft returns how long the material stays ready after now, in milliseconds since the Unix epoch:
// the moment [Set.Ready] gives up, less now. It is below zero once the material has
// expired. A notAfter is a protocol integer, at most 2^53 - 1, so for a clock near the present the
// difference fits; one too long for a Duration is held at the longest either way. The proof bundle has
// no window of its own.
func (s *Set) TimeLeft(now int64) time.Duration {
	const most = math.MaxInt64 / int64(time.Millisecond)
	switch ms := s.notAfter - now; {
	case ms > most:
		return math.MaxInt64
	case ms < -most:
		return math.MinInt64
	default:
		return time.Duration(ms) * time.Millisecond
	}
}

// Key returns the edge's private key. The caller must not change it.
func (s *Set) Key() ed25519.PrivateKey {
	return s.key
}

// Bundle returns the edge's proof bundle, every mapped receiver's proof checked.
func (s *Set) Bundle() policy.ProofBundle {
	return s.bundle
}

// Routes returns the routes the edge stamps for.
func (s *Set) Routes() routes.Map {
	return s.routes
}
