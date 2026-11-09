// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package paztporthttp carries v3 over HTTP at a service: it decides each request it receives, attests
// the answers it gives, stamps the calls it makes and checks their answers. It sends nothing, logs
// nothing, publishes no events and uses no HTTP library: it takes a request or a response as the strings
// and bytes an adapter already has, from a net/http handler, a gateway's external processor or a test
// alike, and hands back answers, headers and verdicts. The headers and bindings themselves are package
// wire's.
//
// An adapter builds an [InboundRequest], with [NewInboundRequest] or by hand, and passes it to
// [Receiver.Accept] with the peer its transport authenticated and the operator's [Mode]. The [Accepted]
// it gets back holds a refusal to send in place of the handler's answer, or the chain and influence the
// handler starts from; once the handler's answer is complete, [Accepted.Attest] gives its X-Path-Response
// header when it is attested. [Accepted.TrustedRecord] says whether the handler may write a record later
// decisions take as fact.
//
// The receiver follows the spec. Under [ModeEnforce] or [ModeAudit] it runs the live order once on each
// request, with itself as receiver, the request's own binding, the tokens of its headers, the nonce key
// <rid>|<last svc>|<last rcv>|req and the peer; enforce refuses a request whose result is not OK with
// 403 {"reason":"<code>"}, and audit serves it, unverified. Influence that does not read is never
// dropped: in every mode, at every service but an origin, a request carrying it is refused with
// 400 {"reason":"INFLUENCE_MISMATCH"} wherever verification has not refused it first. An origin starts
// each request tree afresh, so it carries neither the chain nor the influence a request brings, never
// takes the chain as verified and never attests; under a mode it still verifies, and enforce refuses.
//
// A response stamp is shaped like a request stamp, so attesting a chain nobody checked would let anyone
// mint stamps under the service's key. So a service attests only an answer to a chain that passed the
// live order here: under a mode, the mode's verification decides; with [ModeNone], the chain is verified
// once for attestation alone, and a failure only withholds the attestation. A hop that is [ModeOff], an
// origin and a service with no verifier or no stamp key never attest, and their callers count their
// answers untrusted.
//
// The peer a receiver passes is the one the transport authenticated. Under mutual TLS,
// [PeerFromCertificate] reads it from the client's certificate, as DER: the service is the subject's one
// common name, as [ServiceOf] reads it, and the instance the address the connection came from. Its
// issuer, as RFC 2253 text, is what a partner keeps sessions by, with the service.
//
// A service's calls go through a [Caller]. [Caller.Stamp] stamps a call to the receiver's policy name,
// after the chain the service received and committing to its influence so far, and returns the headers to
// send in order, which the adapter sets after removing every header of the call that wire.IsPaztport
// names; a gateway's external processor, an origin, calls it with neither. Which policy name a
// destination has is the deployment's to configure, never the request's: [Receivers] maps a host to it, and
// a host holding a byte outside ASCII has none, so a call to it is not stamped. [Caller.Check] checks the
// response against the chain sent and returns the influence it adds: an entry for each label of a response
// that verifies, and one local-untrusted entry for any other, so a response is never dropped.
//
// A partner, the entry point of another organisation's calls, keeps [Sessions], made with [NewSessions]
// from its own material and the client policy keys it has pinned. Its adapter answers each POST to
// wire.SessionPath with [Sessions.ServeHandshake], which opens a session bound to the peer the transport
// authenticated, by the certificate's issuer and service, and replies with the session's id and status,
// signed by the entry service's key. It decides each call with [Sessions.Accept] in place of
// [Receiver.Accept]: a call in an attested session is verified by that session's own verifier, pinned to
// the material the client presented, and one in an unsafe session is served believing nothing it carries.
// The adapter then refuses an unsafe session's switched-off endpoints with [UnsafeEndpoints].
//
// Two of a partner's settings are not set by the spec, which leaves them to each partner: how many
// sessions one peer may hold at once, SessionsConfig.MaxPerPeer, and how long a session no call uses is
// kept, SessionsConfig.IdleMs. Neither has a default here; the embedder sets both.
//
// Header values are read as package wire reads them: only HTTP's optional whitespace around a value is
// trimmed, a value of nothing else is absent, and of a repeated header the first value counts. A
// refusal's body is exactly {"reason":"<code>"} and carries no suspect: who is suspected is in the
// verifier's Result, for the operator's logs and events, never for the caller. The adapter sends an
// [Answer]'s Body exactly as its bytes, with the header Content-Type: wire.ContentType and no parameters
// when it is not empty; an empty body, as [Unavailable]'s, carries no Content-Type.
package paztporthttp
