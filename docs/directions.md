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
