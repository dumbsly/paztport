// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"github.com/dumbsly/paztport/poc-sdks/go/internal/json"
	"github.com/dumbsly/paztport/poc-sdks/go/session"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// The handshake endpoint's error codes.
const (
	// invalidParams answers a body that is not a request's wire bytes, or is over the wire limit.
	invalidParams = "INVALID_PARAMS"
	// noSession answers a request that opens no session, or comes from no peer that could hold one.
	noSession = "NO_SESSION"
)

// ServeHandshake is a partner's answer to one POST to wire.SessionPath: body is the request's body, whole,
// and peer the client certificate the transport authenticated, or nil without one. The adapter sends the
// Answer as it stands.
//
// The session is bound to peer, never to a name the body gives, so no client can open one as another. In
// order:
//
//   - with no peer, or one whose certificate names no service or has no issuer, the answer is
//     400 {"error":"NO_SESSION"}, and the body is not read;
//   - a body over the wire limit, 262 144 bytes, is 400 {"error":"INVALID_PARAMS"}, and is not read
//     either, so an adapter need read at most one byte past the limit;
//   - a body that is not exactly a request's wire bytes, as session.ParseRequest reads them, is
//     400 {"error":"INVALID_PARAMS"};
//   - a request that opens no session (see session.OpensSession) is 400 {"error":"NO_SESSION"};
//   - otherwise a session is opened for peer and the answer is 200, its body the signed reply's wire
//     bytes.
//
// The session is attested only when session.Status says so and a verifier can be pinned to the keyring
// and root the client presented; otherwise it is unsafe, and the reply lists the operations
// SessionsConfig.UnsafeDisabled switches off. The reply is in the entry-key form, signed by the entry
// service's key. A handshake that opens no session changes no session.
func ServeHandshake(body []byte, peer *PeerCert, s *Sessions) Answer {
	if peer == nil || peer.Peer.Svc == "" || peer.Issuer == "" {
		return HandshakeError(noSession)
	}
	if len(body) > json.WireBytes {
		return HandshakeError(invalidParams)
	}
	req, err := session.ParseRequest(body)
	if err != nil {
		return HandshakeError(invalidParams)
	}
	if !session.OpensSession(req) {
		return HandshakeError(noSession)
	}
	reply, ok := s.open(req, peerKey{issuer: peer.Issuer, svc: peer.Peer.Svc})
	if !ok {
		return HandshakeError(noSession)
	}
	return Answer{Status: 200, Body: reply}
}

// open opens the session req asks for, for peer, and returns the signed reply's wire bytes. It returns
// false, with every session left as it was, when the request has no session id, the reply cannot be
// signed, or the id is already in use.
func (s *Sessions) open(req session.Request, peer peerKey) ([]byte, bool) {
	cfg := &s.cfg
	nonce := session.NewNonce()
	id, ok := session.ID(req, &cfg.Root, nonce)
	if !ok {
		return nil, false
	}
	e := &sessionEntry{id: id, peer: peer}
	status := session.Status(req, &cfg.Root, cfg.Keyring, cfg.PolicyKey, cfg.Pinned, cfg.Now())
	if status == session.StatusAttested {
		// The client's keyring whole, its window included, so that its signature is checked over that window.
		vc, err := verify.Pinned(req.KeyringFile(), *req.ClientRoot, req.ClientPolicyKey, verify.Config{
			AllowedOrigins: cfg.ClientOrigins,
			Sess:           id,
			Nonces:         cfg.Nonces,
			Now:            cfg.Now,
			CallMaxAgeMs:   cfg.CallMaxAgeMs,
			RunMaxAgeMs:    cfg.RunMaxAgeMs,
		})
		if err == nil {
			e.verifier = verify.New(vc)
		} else {
			// Material no verifier can be built on opens an unsafe session: the client must still be told.
			status = session.StatusUnsafe
		}
	}
	disabled := []string{}
	if status == session.StatusUnsafe {
		disabled = cfg.UnsafeDisabled
	}
	r, err := session.SignReply(session.Reply{
		ServerRoot:            &cfg.Root,
		ServerPolicyKey:       cfg.PolicyKey,
		ServerKeyring:         cfg.Keyring.Services,
		ServerKeyringSig:      &cfg.Keyring.Sig,
		ServerKeyringNotAfter: &cfg.Keyring.NotAfter,
		ServerReplyCert:       &cfg.ReplyCert,
		Nonce:                 nonce,
		Sess:                  id,
		Status:                status,
		Disabled:              disabled,
	}, cfg.EntryKey)
	if err != nil {
		return nil, false
	}
	b, err := r.Wire()
	if err != nil || !s.add(e) {
		return nil, false
	}
	return b, true
}
