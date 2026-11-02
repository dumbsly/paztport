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
// header when it is attested. [TrustedRecord] says whether the handler may write a record later decisions
// take as fact.
//
// The receiver follows the spec. Under [ModeEnforce] or [ModeAudit] it runs the live order once on each
// request, with itself as receiver, the request's own binding, the tokens of its headers, the nonce key
// <rid>|<last svc>|req and the peer; enforce refuses a request whose result is not OK with
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
// common name, read by the spec's walk of the certificate's own encoding, never through an X.509 parser,
// and the instance the address the connection came from. Its issuer, as RFC 2253 text, is what a
// partner keeps sessions by, with the service.
//
// A service's calls go through a [Caller]. [Caller.Stamp] stamps a call to the receiver's policy name,
// after the chain the service received and committing to its influence so far, and returns the headers
// to send in order; a gateway's external processor, an origin, calls it with neither. Which policy name
// a destination has is the deployment's to configure, never the request's: [Receivers] maps a host to it.
// [Caller.Check] checks the response against the chain sent and returns the influence it adds: an entry
// for each label of a response that verifies, and one local-untrusted entry for any other, so a response
// is never dropped.
//
// Header values are read as package wire reads them: only HTTP's optional whitespace around a value is
// trimmed, a value of nothing else is absent, and of a repeated header the first value counts. A
// refusal's body is exactly {"reason":"<code>"} and carries no suspect: who is suspected is in the
// verifier's Result, for the operator's logs and events, never for the caller.
package paztporthttp
