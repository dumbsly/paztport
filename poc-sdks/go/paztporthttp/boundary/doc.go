// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package boundary is the egress: an organisation's last internal hop before another organisation, the
// partner, which must not see the sender's internal chain. In its place a call carries one boundary stamp,
// signed by the egress over the request it sends, in a session opened with the partner, and the request's
// influence blinded, one entry per class and owner.
//
// The egress follows the spec's steps without a transport: it sends nothing, logs nothing and uses no
// HTTP library. Egress.Begin takes the request the egress's own receiver accepted (a
// paztporthttp.Accepted), the request's influence so far, and the call's path and body, and returns an
// Exchange and the first Step: a POST for the embedder to send. The embedder sends each Step as it is,
// its path, body and headers, and passes the partner's answer to Exchange.Answer, or a handshake's
// absence of one to Exchange.NoAnswer, which return the next step, until the exchange ends;
// Exchange.Result then gives its Outcome: the partner's answer, whether the call went out attested, and
// the request's influence with that answer joined.
//
// In order, as the spec's egress does:
//
//  1. Only a request whose chain passed the live order at this hop is sent on: anything else, an origin's,
//     one at a hop that is off or has no verifier, one that failed in audit mode, and work outside any
//     request, is refused with ErrNotVerified before anything is signed or sent, the handshake included.
//  2. A call is made in the session open with the partner, which every call shares. When none is, the
//     exchange opens one first: the full handshake presents the egress's own root, policy key and keyring
//     with a fresh nonce, and its reply is checked against the partner's pinned policy key, with the
//     partner's entry service from the configuration. A reply that is genuine opens an attested or an
//     unsafe session, as it says. Anything else, a reply this side cannot use or an HTTP error (a 404
//     included), may mean the partner opened a session this side cannot stamp in, so the replacement
//     follows: the same request with no root and a fresh nonce, whose session is unsafe whatever its reply
//     says. When the replacement is not answered 200, no session is opened and the call is not sent.
//  3. In an attested session, the call's influence is blinded by influence.Reduce under the boundary key,
//     and the boundary stamp (stamp.Stamper.Boundary) commits to the entries sent and binds the request
//     sent; the call carries the stamp, the proof for the route <egress>/<partner> and the entries. Before
//     sending it, the embedder keeps the originals and the entries sent, which its Step carries, so that
//     any entry sent can later be opened; it does not send the call if it cannot keep them.
//  4. In an unsafe session nothing is signed and no influence is sent: the call carries the session id
//     alone.
//  5. The partner does not attest what it answers, so its answer joins the request's influence as one
//     local-untrusted entry. A 403 whose body is the refusal SESSION_UNKNOWN drops the session the call was
//     made in, and the next call opens a new one; the refused call is not retried. An attested session is
//     dropped, too, once the egress's own root or keyring has passed its notAfter, since the partner
//     would refuse every call in it; the next call's handshake then opens an unsafe session.
//
// One setting is not set by the spec: Config.IdleMs, how long the egress keeps a session no call has used,
// which the spec says should be below the partner's own idle period, so that the partner never forgets a
// session the egress still uses. It has no default here; the embedder sets it.
package boundary
