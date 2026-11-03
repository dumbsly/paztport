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

// Config is everything a verifier pins: the policy material it checks chains against, the request's
// context it expects, and its clock, windows and nonce cache. Pinned fills in the policy material from
// signed material, checking it once, up front; a Config built wholly by hand is for material already
// judged.
type Config struct {
	// Keyring is each service's public key, from a keyring that verified under the pinned policy key.
	Keyring policy.Keyring
	// Root is the bytes of the pinned root of the allowed routes' tree.
	Root []byte
	// RootID labels that tree; a proof for another tree proves nothing.
	RootID string
	// PolicyNotAfter is the earliest notAfter of the keyring and the root, in milliseconds since the Unix
	// epoch: the last moment the policy owner vouches for both. A verifier refuses every request once its
	// clock passes it, and refuses every request under a window outside [0, 2^53 - 1].
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

// Pinned returns cfg with the keyring kf and the root pinned: its Keyring, Root, RootID and
// PolicyNotAfter filled from them, once they are checked against pin, the pinned policy key as base64url
// SubjectPublicKeyInfo (the text of policy.pub). The caller sets the rest of cfg by name: AllowedOrigins,
// Sess, Nonces, Now, CallMaxAgeMs and RunMaxAgeMs. The keyring must name pin and verify under it, the root
// must verify under it, and both must be current at cfg.Now(). Pinned refuses them otherwise, naming the
// keyring or the root, so that no verifier is built on material the pin does not vouch for now, and
// refuses a cfg with no clock or no nonce cache. PolicyNotAfter is the earlier of their windows.
func Pinned(kf policy.KeyringFile, root policy.Root, pin string, cfg Config) (Config, error) {
	if cfg.Now == nil {
		return Config{}, errors.New("paztport verify: Config.Now must be a clock")
	}
	if cfg.Nonces == nil {
		return Config{}, errors.New("paztport verify: Config.Nonces must be a nonce cache")
	}
	if !kf.Verifies(pin) {
		return Config{}, errors.New("paztport verify: the keyring does not verify under the pinned policy key")
	}
	at := cfg.Now()
	if !kf.Current(at) {
		return Config{}, fmt.Errorf("paztport verify: the keyring expired: notAfter %d is before now %d", kf.NotAfter, at)
	}
	keyring, err := kf.Keyring()
	if err != nil {
		return Config{}, fmt.Errorf("paztport verify: the keyring can't be used: %w", err)
	}
	if !root.Verifies(pin) {
		return Config{}, errors.New("paztport verify: the root does not verify under the pinned policy key")
	}
	if !root.Current(at) {
		return Config{}, fmt.Errorf("paztport verify: the root expired: notAfter %d is before now %d", root.NotAfter, at)
	}
	rootBytes, err := root.Bytes()
	if err != nil {
		return Config{}, fmt.Errorf("paztport verify: the root can't be used: %w", err)
	}
	cfg.Keyring = keyring
	cfg.Root = rootBytes
	cfg.RootID = root.RootID
	cfg.PolicyNotAfter = min(kf.NotAfter, root.NotAfter)
	return cfg, nil
}
