# Where this could go

This file collects where Paztport could go beyond this proof of concept. It
builds on [How it works](../README.md#how-it-works) in the README and uses its
terms.

These are design directions, except where a bullet says what is built.

- **Post-quantum.** Keep the Merkle tree and swap Ed25519 stamps for hash-based
  signatures. SLH-DSA (FIPS 205) is stateless, but at ~8–50 KB per signature, one
  stamp as `X-Path-Chain` encodes it, with any parameter set, is larger than
  Tomcat's default 8 KB header limit, and two stamps with the smallest are larger
  than Node's default 16 KiB; those limits can be raised. XMSS and LMS are smaller
  but stateful, and reusing a key is catastrophic. Signing isn't behind a swap
  interface yet. Making it swappable would take a `StampSigner` / `StampVerifier`
  interface, an algorithm tag in `keyring.json` and alongside each `sig`, and, for
  XMSS or LMS, a signer with persisted key state. The interface is cheap; managing
  stateful keys and living with the header sizes is the real work.
- **AI agents and MCP.** For an agent, a path is a sequence of steps
  (`user → orchestrator → subagent → tool`, or
  `read_inbox → summarize → send_email`), and the agent *runtime*, not the model,
  holds the keys and stamps each step. A sensitive MCP server can require a chain
  proving a call began in a user session and went only through approved agents,
  without the client revealing its agent architecture. The MCP chain, the session
  handshake, influence tracking and response attestation are built in the
  TypeScript SDK and [the agents demo](../poc-demos/agents-mcp/README.md), against a
  mock MCP server. Still open: running it in a production agent runtime.
- **Origin intent, further.** The extension `intent` is built: the origin states
  facts about a request in its own block, and a receiver whose handler requires a
  fact refuses a request that lacks it or differs from it
  ([intent](../poc-sdks/spec/intent.md),
  [limits](limits.md#limits-of-the-concept)). What remains is open. Every hop after
  the origin reads every fact; sealing, with the construction of SD-JWT (RFC 9901),
  could keep each fact from the hops not on the way to a receiver that requires it:
  the origin would sign one salted digest per fact, and a value and its salt would
  travel only on that way. The item is closed, so that would be a format change for
  every implementation that acts on `intent`. A value worked out mid-request, such
  as a total a pricing service computes, has no signer but the hop that sends it;
  signed by the service that derived it, it could be required under that service's
  key. The origin's signature could cross the boundary, so that a partner could
  compare its request with the facts itself instead of relying on the egress. The
  user's own client could sign the facts, making them the user's statement rather
  than the entry point's, and letting a receiver apply per-user limits a
  compromised hop could not evade. A hop that withholds the call that would compare
  is caught by nothing yet; a detector over the logged chains could flag it
  ("Detecting misuse on allowed routes", below). And `intent` has no MCP form.
- **Influence carried forward.** Each call could carry the influence its signer
  received as well as the influence it sends, each part committed by the stamp that
  sent it, so a receiver could check that no entry was dropped along the chain. A
  hop could still add content it read off the chain without a label: what shaped its
  own output stays its to declare.
- **Detecting misuse on allowed routes.** Misuse that stays on allowed routes
  refuses nothing, so it sends no event. The chains receivers verify are signed
  evidence of each request's id, route and signers; logged, they are what a detector
  needs, for example to flag a service making more calls than the requests that
  reached it explain.
- **Sidecar meshes.** The peer check reads the sender from mutual TLS ended in the
  service's own process ([limits](limits.md#using-it-soundly)). Behind Istio's or
  Linkerd's per-pod proxy, an SDK could take the peer from the client identity the
  proxy forwards (Envoy's `x-forwarded-client-cert` under Istio, `l5d-client-id`
  under Linkerd), only on connections from the pod's own loopback address, and map
  it to a service name. That
  trusts the proxy to be the only way in, which the deployment would have to enforce
  and the SDK could not check, so it would be a mode a deployment turns on by name.
- **Retries.** Over HTTP a service calls an operation once per request tree, so an
  application's retry of a call that was delivered is refused `REPLAY` by the
  replica that saw it, yet served by any other replica, where the application's
  idempotency handles it ([limits](limits.md#what-adopting-it-costs)). An attempt
  number in the signed stamp, part of the nonce key but not of the delivery key and
  capped by the verifier, would let a caller retry up to that cap on any replica,
  while the application still saw one delivery. A compromised caller could then
  make that many calls per request rather than one. A retried hop that calls onward
  would reuse its onward calls' nonce keys, so either the attempt travels down the
  chain or the receiver's idempotency answers the retry before any onward call.
  Unlike the retry under interrupted work below, which the origin mints, this one is
  the caller's own.
- **Revocation before expiry.** A version number in the signed keyring and root
  would let a partner refuse an issue older than the newest it has seen, but only
  once it has seen it ([limits](limits.md#using-it-soundly)). To end the window, the
  policy key could sign, once, a long-lived delegation to an online key that signs
  short-lived statements naming the newest issue, in the manner of OCSP stapling,
  which each side shows in the handshake. The policy key stays offline; the online
  key can say which issue is current, but cannot write a keyring or a route. Stolen,
  it could keep naming an old issue current until the delegation expires.
- **Async boundaries.** Treat a queue like another organisation: attest and
  summarise at enqueue, carry a compact signed commitment plus the broker's message
  ID, and let the message ID replace the timestamp as the anti-replay key. Fan-in
  (joins) is the open frontier and likely needs its own commitment structure.
- **Scale.** A forest of sub-roots partitioned by destination keeps every proof at
  `log(subtree)` no matter how large the global path space gets. It also shrinks the
  blast radius of a policy change to one domain.
- **Interrupted work and race conditions.** A quarantined node can't be trusted to
  hand off its own work. The trusted party is the origin, which can mint a
  retry (the same `rid` and an `attempt` counter, which would need a new field in
  the signed bytes and the nonce key) that a replayer can't forge. The same
  verifiable `rid` could own leases on declared intent keys, giving path-scoped
  concurrency control at the attested boundary.
- **Cross-organisation trust.** Publish signed roots, never trees. An egress
  gateway verifies the internal chain and emits one boundary attestation. The
  boundary attestation is implemented in the Java demo (see
  [the storyline](../poc-demos/java-mesh/README.md#the-support-assistant-storyline)).
  What is still a direction is the rest: an append-only log of roots (in the style
  of Certificate Transparency) lets partners detect an unexpected new root without
  seeing the policy behind it.
