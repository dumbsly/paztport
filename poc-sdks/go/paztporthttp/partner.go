// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

package paztporthttp

import (
	"context"

	"github.com/dumbsly/paztport/poc-sdks/go/influence"
	"github.com/dumbsly/paztport/poc-sdks/go/paztporthttp/wire"
	"github.com/dumbsly/paztport/poc-sdks/go/reason"
	"github.com/dumbsly/paztport/poc-sdks/go/stamp"
	"github.com/dumbsly/paztport/poc-sdks/go/verify"
)

// PartnerAccepted is what [Sessions.Accept] decided about another organisation's call: a refusal to send
// in place of the handler's answer, or a call served in an unsafe session, where nothing the request
// carries is believed, or in an attested one, where it verified in that session.
//
// A trusted record may be written from a call only when [PartnerAccepted.TrustedRecord] says so: when it
// is attested and neither its influence nor what the handler has read since holds untrusted content.
type PartnerAccepted struct {
	// Refusal is the answer to send in place of the handler's, or nil when the call is served.
	Refusal *Answer
	// Attested reports whether the call is served in an attested session, having verified there. It is
	// false in an unsafe session and for a refusal.
	Attested bool
	// Chain is the chain that verified in the session, for the handler's own calls to stamp onto, or nil
	// unless Attested.
	Chain stamp.Chain
	// Influence is the verified influence, owners included, the handler starts from when Attested, and
	// otherwise none, whatever headers came.
	Influence []influence.Entry
	// Result is the session verifier's result on the call, or nil when no verification ran: in an unsafe
	// session, or when the session is unknown. The embedder may build an event from it; the caller is
	// never told it.
	Result *verify.Result
}

// Accept decides the call req in the session its X-Path-Session header names, which the transport
// authenticated as sent by peer, the client certificate, or nil without one.
//
//   - A header that names no live session opened by peer, the same issuer and service, is refused
//     403 {"reason":"SESSION_UNKNOWN"}: another peer's id, the same service's under another issuer, an
//     evicted or expired one, one from before a restart, or a call with no certificate, or one with no
//     issuer or naming no service. It is never taken as unsafe, or a caller refused in an attested session
//     could step down to an unsafe one by naming a wrong id. A session found is used: its idle period
//     starts again.
//   - With no header, the caller never opened a session, and the call is served as in an unsafe one. In
//     an unsafe session nothing is verified and nothing the call carries is believed: it is served with
//     no chain and no influence, and not Attested.
//   - In an attested session the live order runs once, with the session's own verifier, the entry
//     service as receiver, the request's own binding, the tokens of its headers, the nonce key
//     <rid>|<last svc>|<last rcv>|req and peer's service and address as the peer. A result that is not OK
//     is refused 403 {"reason":"<code>"}: a partner has no audit mode, so influence that does not read is
//     refused 403 {"reason":"INFLUENCE_MISMATCH"} too. On OK the call is Attested, with the chain and the
//     influence its boundary stamp committed to.
//
// Accept does not refuse the operations switched off for unsafe sessions, since only the framework knows
// which handler a request reaches. An adapter refuses one served and not Attested whose method and route
// pattern UnsafeOperations(SessionsConfig.UnsafeDisabled).Refuses, with [UnsafeRefusal], before its
// handler runs: so a call with no session header, too.
//
// Accept never panics on any request, and a call that does not verify is answered, never an error. ctx
// reaches only the nonce cache. The error is the cache's, when it could not answer, and comes with the
// zero PartnerAccepted, so the adapter fails the call.
func (s *Sessions) Accept(ctx context.Context, req InboundRequest, peer *PeerCert) (PartnerAccepted, error) {
	id, named := wire.HeaderValue(req.Session)
	if !named {
		return PartnerAccepted{}, nil
	}
	var p PeerCert
	if peer != nil {
		p = *peer
	}
	e, ok := s.find(p.Issuer, p.Peer.Svc, id)
	if !ok {
		return partnerRefused(Refusal(403, reason.SessionUnknown), nil), nil
	}
	if e.verifier == nil {
		return PartnerAccepted{}, nil
	}
	in, chain := requestInput(req, s.cfg.Entry, &p.Peer)
	res, err := e.verifier.Verify(ctx, in)
	if err != nil {
		return PartnerAccepted{}, err
	}
	if !res.OK() {
		return partnerRefused(Refusal(403, res.Reason), &res), nil
	}
	es, read := readInfluence(req.Influence)
	if !read || chain == nil {
		// Not reached after OK, which has read both; refused rather than served with less than was
		// committed to.
		return partnerRefused(Refusal(403, reason.InfluenceMismatch), &res), nil
	}
	return PartnerAccepted{Attested: true, Chain: chain, Influence: es, Result: &res}, nil
}

// partnerRefused returns the refusal answer, with the verifier's result res, or nil when none ran.
func partnerRefused(answer Answer, res *verify.Result) PartnerAccepted {
	return PartnerAccepted{Refusal: &answer, Result: res}
}
