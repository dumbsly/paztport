// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"crypto/ed25519"
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/dumbsly/paztport/poc-sdks/go/internal/exact"
	"github.com/dumbsly/paztport/poc-sdks/go/policy"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// SessionsConfig is a partner's configuration: its own policy material, which its handshake replies carry,
// the client policy keys it has pinned, and the limits and clock its sessions are kept by. Every member is
// required unless it says otherwise; [NewSessions] refuses a configuration that lacks one.
type SessionsConfig struct {
	// Root is the partner's own signed root, which every reply carries.
	Root policy.Root
	// Keyring is the partner's own signed keyring, which every reply carries. It must verify under
	// PolicyKey: a handshake judges it by its window alone.
	Keyring policy.KeyringFile
	// PolicyKey is the partner's own policy public key, as base64url SubjectPublicKeyInfo: the key its
	// clients pin.
	PolicyKey string
	// Entry is the partner's entry service, whose key signs the replies: the receiver every boundary stamp
	// must be addressed to.
	Entry string
	// EntryKey is the entry service's private key, which signs every reply in the entry-key form.
	EntryKey ed25519.PrivateKey
	// ReplyCert is the policy key's certificate for the entry service's key, which every reply carries.
	// A client accepts a reply only while it is current, so the partner is given a fresh one before it
	// expires.
	ReplyCert policy.ReplyCert
	// Pinned are the client policy keys whose sessions may be attested, each as base64url
	// SubjectPublicKeyInfo. At least one is required: with none, every session would be unsafe.
	Pinned []string
	// ClientOrigins are the services allowed to start a chain in a client's attested session. At least one
	// is required: with none, no call could verify.
	ClientOrigins []string
	// UnsafeDisabled are the operations switched off in an unsafe session, each "<METHOD> <route pattern>",
	// as an unsafe session's reply lists them and [UnsafeOperations] refuses them. It may be empty.
	UnsafeDisabled []string
	// MaxPerPeer is how many sessions one peer may hold at once; a handshake that would give it more
	// evicts its least recently used. It must be positive. The spec leaves its value to the partner.
	MaxPerPeer int
	// IdleMs is how long, in milliseconds, a session no call has used is kept. It must be positive. The
	// spec leaves its value to the partner.
	IdleMs int64
	// CallMaxAgeMs and RunMaxAgeMs are each attested session's verifier's windows: see verify.Config.
	CallMaxAgeMs, RunMaxAgeMs int64
	// Nonces is the replay cache every session's verifier shares.
	Nonces verify.NonceCache
	// Now is the partner's clock, in milliseconds since the Unix epoch: each handshake judges both sides'
	// material by it, the session verifiers check stamps against it, and it ages an idle session.
	Now func() int64
}

// Sessions is a partner's sessions: [ServeHandshake] opens them and [Sessions.Accept] decides each call
// in the one it names. Each session is kept by its id and bound to the peer that opened it: the client
// certificate's issuer and the service it names, both of which the transport authenticated. A call is
// in a session only when that same issuer and service name it; the service alone is not enough, since
// another CA the transport trusts could issue a certificate with the same name.
//
// A handshake adds a session and replaces none, so replicas that share a certificate each keep their own,
// and a client that opens a new session does not cut off calls still in flight in its earlier one. A
// peer holds at most MaxPerPeer sessions: one more evicts its least recently used, and only its own. A
// session no call has used for IdleMs expires. An evicted or expired id is simply unknown, as one from
// before a restart is.
//
// An attested session has a verifier of its own, pinned to the keyring and root the client presented in
// the handshake, with the session id as its sess, so a stamp made in one session never verifies in
// another; all of them share the one nonce cache. An unsafe session has none.
//
// Sessions is safe for concurrent use when its nonce cache and clock are: one mutex guards the sessions,
// so concurrent handshakes from one peer never leave it over its cap, and no request is verified while it
// is held.
type Sessions struct {
	cfg SessionsConfig
	// readRequest reads a handshake's body; it is session.ParseRequest, held here so that a test can
	// count which bodies reach it.
	readRequest func([]byte) (session.Request, error)

	mu     sync.Mutex
	byID   map[string]*sessionEntry
	byPeer map[peerKey][]*sessionEntry // each peer's sessions, least recently used first
}

// peerKey is the authenticated peer a session is bound to: the certificate's issuer, as RFC 2253 text,
// and the service its subject names.
type peerKey struct{ issuer, svc string }

// sessionEntry is one session kept. Only lastUsed changes, under the lock.
type sessionEntry struct {
	id       string
	peer     peerKey
	verifier *verify.Verifier // nil for an unsafe session
	lastUsed int64
}

// NewSessions returns a partner's sessions, none open yet, configured by its own copy of cfg. It refuses
// a configuration with no pinned client policy key, no client origin, a MaxPerPeer or IdleMs that is not
// positive, no nonce cache or no clock, or a Keyring that does not verify under PolicyKey.
func NewSessions(cfg SessionsConfig) (*Sessions, error) {
	switch {
	case len(cfg.Pinned) == 0:
		return nil, errors.New("paztport http: SessionsConfig.Pinned holds no client policy key")
	case len(cfg.ClientOrigins) == 0:
		return nil, errors.New("paztport http: SessionsConfig.ClientOrigins holds no client origin")
	case cfg.MaxPerPeer < 1:
		return nil, errors.New("paztport http: SessionsConfig.MaxPerPeer must be positive")
	case cfg.IdleMs < 1:
		return nil, errors.New("paztport http: SessionsConfig.IdleMs must be positive")
	case cfg.Nonces == nil:
		return nil, errors.New("paztport http: SessionsConfig.Nonces is nil")
	case cfg.Now == nil:
		return nil, errors.New("paztport http: SessionsConfig.Now is nil")
	case !cfg.Keyring.Verifies(cfg.PolicyKey):
		return nil, errors.New("paztport http: SessionsConfig.Keyring does not verify under SessionsConfig.PolicyKey")
	}
	cfg.Keyring.Services = maps.Clone(cfg.Keyring.Services)
	cfg.EntryKey = slices.Clone(cfg.EntryKey)
	cfg.Pinned = slices.Clone(cfg.Pinned)
	cfg.ClientOrigins = slices.Clone(cfg.ClientOrigins)
	cfg.UnsafeDisabled = slices.Clone(cfg.UnsafeDisabled)
	return &Sessions{
		cfg:         cfg,
		readRequest: session.ParseRequest,
		byID:        map[string]*sessionEntry{},
		byPeer:      map[peerKey][]*sessionEntry{},
	}, nil
}

// add keeps e, a session just opened: it refuses an id already in use, which would take a repeated server
// nonce, leaving every session as it was; otherwise it drops every expired session, adds e as its peer's
// most recently used, and evicts that peer's least recently used down to the cap.
func (s *Sessions) add(e *sessionEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[e.id]; ok {
		return false
	}
	now := s.cfg.Now()
	for _, old := range s.byID {
		if idleExpired(now, old.lastUsed, s.cfg.IdleMs) {
			s.remove(old)
		}
	}
	e.lastUsed = now
	s.byID[e.id] = e
	own := append(s.byPeer[e.peer], e)
	if over := len(own) - s.cfg.MaxPerPeer; over > 0 {
		for _, old := range own[:over] {
			delete(s.byID, old.id)
		}
		own = slices.Delete(own, 0, over)
	}
	s.byPeer[e.peer] = own
	return true
}

// find returns the live session id that the peer issuer, svc opened, and true, marking it used now. It
// returns false for a peer with no issuer or no service, an unknown id, another peer's, and an expired
// one, which it drops.
func (s *Sessions) find(issuer, svc, id string) (*sessionEntry, bool) {
	if issuer == "" || svc == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok || e.peer != (peerKey{issuer: issuer, svc: svc}) {
		return nil, false
	}
	now := s.cfg.Now()
	if idleExpired(now, e.lastUsed, s.cfg.IdleMs) {
		s.remove(e)
		return nil, false
	}
	e.lastUsed = now
	own := s.byPeer[e.peer]
	i := slices.Index(own, e)
	s.byPeer[e.peer] = append(slices.Delete(own, i, i+1), e)
	return e, true
}

// remove forgets e, and its peer when it was the peer's last; under the lock.
func (s *Sessions) remove(e *sessionEntry) {
	delete(s.byID, e.id)
	own := slices.DeleteFunc(s.byPeer[e.peer], func(o *sessionEntry) bool { return o == e })
	if len(own) == 0 {
		delete(s.byPeer, e.peer)
		return
	}
	s.byPeer[e.peer] = own
}

// idleExpired reports whether a session last used at lastUsed has expired at now: now - lastUsed >= idle,
// computed exactly, for a positive idle.
func idleExpired(now, lastUsed, idle int64) bool {
	return !exact.AtMost(now, lastUsed, idle-1)
}
