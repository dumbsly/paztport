// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"fmt"
	"math"

	"github.com/dumbsly/paztport/poc-sdks/go/policy"
)

// The spec's freshness and replay windows, in milliseconds.
const (
	// CallMaxAgeMs is how far the last stamp's time may be from now, either way, and how far the origin's
	// may be in the future.
	CallMaxAgeMs = 5000
	// RunMaxAgeMs is how long a run's origin stays usable. An agent run reuses one origin for many calls,
	// so the origin may be older than one call window. A verifier for a single request tree, such as an
	// HTTP mesh, may set its run window to the call window instead.
	RunMaxAgeMs = 1800000
	// NonceTTLMs is how long a nonce cache remembers a key. It is at least twice CallMaxAgeMs.
	NonceTTLMs = 15000
)

// NonceTTLFor returns how long a nonce cache must remember keys for a call window of callMaxAgeMs:
// NonceTTLMs, or twice the window if that is longer, and math.MaxInt64 when twice the window does not fit
// an int64. The verifier refuses a cache that forgets sooner, so a service that widens its window sizes
// its cache with this.
func NonceTTLFor(callMaxAgeMs int64) int64 {
	if callMaxAgeMs > math.MaxInt64/2 {
		return math.MaxInt64
	}
	return max(NonceTTLMs, 2*callMaxAgeMs)
}

// PinnedKeyring is a keyring a verifier pins: each service's public key, and the keyring's window.
type PinnedKeyring struct {
	// Keys is each service's public key, from a keyring that verified under the pinned policy key. A key
	// is looked up by its service's own name only.
	Keys policy.Keyring
	// NotAfter is the keyring's notAfter, in milliseconds since the Unix epoch: the keyring is current
	// while the time it is judged at is at most this. math.MaxInt64 is no window, for a keyring that counts
	// at every time, such as one whose window a session record judges itself; a keyring under any other
	// window outside [0, 2^53 - 1] is current at no time.
	NotAfter int64
}

// PinnedRoot is a root a verifier pins: the root of an allowed routes' tree, its rootId and its window.
type PinnedRoot struct {
	// Root is the bytes of the root, from a root that verified under the pinned policy key.
	Root []byte
	// RootID labels the tree. A proof is checked only against the roots with its rootId: roots that share
	// one are renewals of one tree.
	RootID string
	// NotAfter is the root's notAfter, in milliseconds since the Unix epoch, read as PinnedKeyring's is.
	NotAfter int64
}

// Config is everything a verifier pins: the policy material it checks chains against, the request's
// context it expects, and its clock, windows and nonce cache. Pinned fills in the policy material from
// signed material, checking it once, up front; a Config built wholly by hand is for material already
// judged.
//
// It pins one or more keyrings and one or more roots, each with its own window, so that a rollover can pin
// the old and the new together. For each request the verifier uses only those current at its clock. A
// Config built by hand with no keyring has no key for any stamp, so every chain is BAD_SIGNATURE, and one
// with no root proves no route, so every chain that gets that far is PATH_NOT_ALLOWED.
type Config struct {
	// Keyrings are the keyrings the verifier pins. Check 4 looks a stamp's key up in every one current at
	// the verifier's clock.
	Keyrings []PinnedKeyring
	// Roots are the roots the verifier pins. Check 11 proves the route against a current one whose RootID is
	// the proof's.
	Roots []PinnedRoot
	// PolicyNotAfter is the earlier of the latest keyring's notAfter and the latest root's, in milliseconds
	// since the Unix epoch: the last moment the policy owner vouches for some keyring and some root. A
	// verifier refuses every request once its clock passes it, and refuses every request under a window
	// outside [0, 2^53 - 1]. It is an input in its own right: the verifier does not work it out from the
	// members' windows.
	PolicyNotAfter int64
	// AllowedOrigins are the services that may sign an origin stamp.
	AllowedOrigins []string
	// Sess is the session id every stamp must carry; "" for a chain in no session.
	Sess string
	// Nonces is the replay cache.
	Nonces NonceCache
	// Now is the verifier's clock, in milliseconds since the Unix epoch.
	Now func() int64
	// CallMaxAgeMs bounds the last stamp's age either way, and how far ahead the origin's time may be.
	CallMaxAgeMs int64
	// RunMaxAgeMs bounds the origin's age.
	RunMaxAgeMs int64
}

// Pinned returns cfg with the keyrings kfs and the roots pinned: its Keyrings, Roots and PolicyNotAfter
// filled from them, once each is checked against pin, the pinned policy key as base64url
// SubjectPublicKeyInfo (the text of policy.pub). The caller sets the rest of cfg by name: AllowedOrigins,
// Sess, Nonces, Now, CallMaxAgeMs and RunMaxAgeMs. Each keyring must name pin and verify under it, each
// root must verify under it, and every one must be current at cfg.Now(). Pinned refuses them otherwise,
// naming the member by its place in its list, such as keyrings[1], so that no verifier is built on
// material the pin does not vouch for now. It refuses no keyring or no root, and a cfg with no clock or no
// nonce cache. Each member keeps its own window, in the order given, and PolicyNotAfter is the earlier of
// the latest keyring's notAfter and the latest root's.
func Pinned(kfs []policy.KeyringFile, roots []policy.Root, pin string, cfg Config) (Config, error) {
	if cfg.Now == nil {
		return Config{}, errors.New("paztport verify: Config.Now must be a clock")
	}
	if cfg.Nonces == nil {
		return Config{}, errors.New("paztport verify: Config.Nonces must be a nonce cache")
	}
	if len(kfs) == 0 {
		return Config{}, errors.New("paztport verify: no keyring to pin: pin at least one")
	}
	if len(roots) == 0 {
		return Config{}, errors.New("paztport verify: no root to pin: pin at least one")
	}
	at := cfg.Now()
	keyrings := make([]PinnedKeyring, len(kfs))
	latestKeyring := int64(math.MinInt64)
	for i, kf := range kfs {
		k, err := pinnedKeyring(kf, pin, at)
		if err != nil {
			return Config{}, fmt.Errorf("paztport verify: keyrings[%d] %w", i, err)
		}
		keyrings[i], latestKeyring = k, max(latestKeyring, k.NotAfter)
	}
	pinnedRoots := make([]PinnedRoot, len(roots))
	latestRoot := int64(math.MinInt64)
	for i, root := range roots {
		r, err := pinnedRoot(root, pin, at)
		if err != nil {
			return Config{}, fmt.Errorf("paztport verify: roots[%d] %w", i, err)
		}
		pinnedRoots[i], latestRoot = r, max(latestRoot, r.NotAfter)
	}
	cfg.Keyrings = keyrings
	cfg.Roots = pinnedRoots
	cfg.PolicyNotAfter = min(latestKeyring, latestRoot)
	return cfg, nil
}

// pinnedKeyring returns kf pinned, once it names pin and verifies under it and is current at at. Its
// error is worded to follow the member's name, as Pinned gives it.
func pinnedKeyring(kf policy.KeyringFile, pin string, at int64) (PinnedKeyring, error) {
	if !kf.Verifies(pin) {
		return PinnedKeyring{}, errors.New("does not verify under the pinned policy key")
	}
	if !kf.Current(at) {
		return PinnedKeyring{}, fmt.Errorf("expired: notAfter %d is before now %d", kf.NotAfter, at)
	}
	keys, err := kf.Keyring()
	if err != nil {
		return PinnedKeyring{}, fmt.Errorf("can't be used: %w", err)
	}
	return PinnedKeyring{Keys: keys, NotAfter: kf.NotAfter}, nil
}

// pinnedRoot returns root pinned, once it verifies under pin and is current at at. Its error is worded to
// follow the member's name, as Pinned gives it.
func pinnedRoot(root policy.Root, pin string, at int64) (PinnedRoot, error) {
	if !root.Verifies(pin) {
		return PinnedRoot{}, errors.New("does not verify under the pinned policy key")
	}
	if !root.Current(at) {
		return PinnedRoot{}, fmt.Errorf("expired: notAfter %d is before now %d", root.NotAfter, at)
	}
	b, err := root.Bytes()
	if err != nil {
		return PinnedRoot{}, fmt.Errorf("can't be used: %w", err)
	}
	return PinnedRoot{Root: b, RootID: root.RootID, NotAfter: root.NotAfter}, nil
}
