// Copyright 2026 The Paztport Authors
// SPDX-License-Identifier: Apache-2.0

// Package paztporthttp carries version 4 over HTTP at a service: it decides each request it receives, attests
// the answers it gives, stamps the calls it makes and checks their answers. It sends nothing, logs
// nothing, publishes no events and uses no HTTP library: it takes a request or a response as the strings
// and bytes an adapter already has, from a net/http handler, a gateway's external processor or a test
// alike, and hands back answers, headers and verdicts. The headers and bindings themselves are package
// wire's.
//
// An adapter builds an [InboundRequest], with [NewInboundRequest] or by hand, and passes it to
// [Receiver.Accept] with the peer its transport authenticated and the operator's [Mode]. The [Accepted]
// it gets back holds a refusal to send in place of the handler's answer, or the chain and blocks the handler's
// calls carry on and the items the request hands the extensions the service acts on; once the handler's answer
// is complete, [Accepted.Attest] gives its X-Path-Response header when it is attested, its block carrying the
// handler's labels where the service acts on influence.
// [Accepted.PublicWrite] decides a guarded public write the handler makes, and [Accepted.TrustedRecord] whether it
// may write a record later decisions take as fact.
//
// The receiver follows the spec. A service states its extension settings once, the extensions it acts on and
// the names it carries: its verifier's, or [Receiver.Extensions] where it has none. Under [ModeEnforce] or
// [ModeAudit] it runs the live order once on each request, with itself as receiver, the request's own binding,
// the tokens of its headers, X-Path-Extensions among them, the nonce key, the JCS text of
// [rid, last svc, last rcv, "req"], and the peer (the key value of a keyed operation joins the nonce key, see
// [Receiver.Operations]); enforce refuses a request whose result is not OK with 403 {"reason":"<code>"}, and
// audit serves it, unverified. A verified request hands the service the verifier's hand-over. Every other request
// a service is about to serve, in audit mode after a failure, with no verifier, under no mode or with Paztport
// off, has its blocks matched to its stamps first, by check 9a, and is refused with
// 400 {"reason":"EXTENSION_MISMATCH"} where they do not match: a hop may not drop or alter a block it carries.
// Blocks that match are handed on as not verified. A service whose settings act on influence then refuses a
// request handed an item that does not read with 400 {"reason":"INFLUENCE_MISMATCH"}, in every mode. An origin
// starts each request tree afresh, so it carries neither the chain nor the blocks a request brings, never takes
// the chain as verified and never attests; under a mode it still verifies, and enforce refuses.
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
// A service's calls go through a [Caller]. [Caller.Stamp] stamps a call to the receiver's policy name, after
// the chain the service received, sending the blocks it received unchanged and then its own, which names
// influence with what the service added for the request where its settings act on influence and requires what
// [Caller.Requires] holds for the receiver, and returns the headers to send in order, X-Path-Extensions on every
// call, which the adapter sets after removing every header of the call that wire.IsPaztport names; a gateway's
// external processor, an origin, calls it with no inbound chain. Which policy name a destination has is the
// deployment's to configure, never the request's: [Receivers] maps a host to it, and a host holding a byte
// outside ASCII has none, so a call to it is not stamped. [Caller.Check] checks the response against the chain
// and blocks sent and returns the influence it adds, the entries of its labels where it verified and otherwise one
// local-untrusted entry, so a response is never dropped, and whether it was refused at check 9c, a call the
// embedder fails.
//
// A partner, the entry point of another organisation's calls, keeps [Sessions], made with [NewSessions]
// from its own material, its extension settings and the client policy keys it has pinned. Its adapter answers
// each POST to wire.SessionPath with [Sessions.ServeHandshake], which opens a session bound to the peer the
// transport authenticated, by the certificate's issuer and service, and replies with the session's id and
// status and the extensions the partner acts on, signed by the entry service's key. It decides each call with
// [Sessions.Accept] in place of [Receiver.Accept]: a call in an attested session is verified by that session's
// own verifier, pinned to the material the client presented, and hands the partner the boundary block's items;
// one in an unsafe session is served believing nothing it carries, its blocks unread.
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
