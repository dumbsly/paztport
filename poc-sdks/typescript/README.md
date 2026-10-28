# TypeScript SDK

An npm workspace of four packages. Node 22.19 or newer runs the `.ts` sources
directly, with no build step. Nothing is published: the agents demo
([poc-demos/agents-mcp](../../poc-demos/agents-mcp/README.md)) links the packages
with `file:` paths, and they resolve their own dependencies from this workspace,
so install it first.

```bash
npm install
npm run check   # tsc, for the type-level guards that vitest does not check
npm test
```

One test reads a keyring written by the Java keygen, from `PAZTPORT_JAVA_KEYRING`
or else the Java demo's `out/keys/keyring.json`. With neither it skips; `./run test`
writes one and names it, so there it always runs.

## @paztport/core

The protocol, with no transport: base64url, Ed25519 and SHA-256 helpers,
canonical JSON, v1, v2 and v3 stamps and chains, the salted Merkle tree, signed roots
and keyrings, reply certificates, policy building, reason codes, the replay cache, prompt
binding, influence and the owner-aware influence rule, sessions, local tool rules and the
verdict for a local tool call, local steps, the live v1 verifier and the live v3 chain
verifier (`verifyChainV3`).
Offline verification of a recorded run (`verifyChainOffline`) is here too, and shares its
checks with the live verifier; the agents demo's `npm run verify` uses it.

It implements protocol v3, as the [spec](../spec/README.md) defines it:

- **v3 only, live.** The live chain verifier takes v3 stamps only; a v2 chain is `CHAIN_MISSING`. v2 is
  accepted only offline (`verifyChainOffline`, `recheckResponse`), as legacy, and a chain that mixes the two
  never verifies.
- **The receiver.** Every v3 stamp names the hop it was handed to, and the verifier checks each `rcv` against
  the next stamp and the last against `receiver`. A live call or chain stamped for a different receiver is
  `BINDING_MISMATCH`, not a route failure, so a forwarded chain no longer names its last signer.
- **The peer.** `peer` (`{ svc, inst }`) is the sender a transport authenticated. Given one, the verifier
  checks it is the last signer (`PEER_MISMATCH`, after every other check) and names it as the suspect in every
  result. No transport here supplies one yet: the MCP wrappers (`verifyCall`, `verifyMcpResponse`,
  `McpServerSession.checkCall`) pass no peer, because stdio has no TLS, so for MCP over stdio the live order
  ends at check 11, and the peer check is core's (`verifyChainV3`).
- **Signed keyrings.** A keyring is signed by its policy key (`signKeyring`, `verifyKeyring`), and the session
  request carries the signature as `clientKeyringSig`. A request without it is legacy offline and unsafe live.
  One whose signature is present but malformed (not a string) or wrong is unsafe live, and offline is a v3
  request whose signature fails, not a legacy one.
- **Legacy is reported.** The offline results say whether a chain was legacy, and the agents demo's `verify`
  marks each such item ([eval README](../../poc-demos/agents-mcp/eval/README.md)).

## @paztport/http

The v1 HTTP request binding (`bindHttp`): SHA-256 over method, path and body. The
Java SDK computes the same bytes for a request with no query. This SDK does not
speak v3 over HTTP, which only the Java SDK does, and does not replay
`spec/vectors/http-v3.json`.

## @paztport/mcp

MCP transport on top of core: the `tools/call` binding, the `_meta` keys
(`paztport/chain`, `paztport/proof`, `paztport/influence` and the rest), the client
side (the session request and its reply, stamping a tool call, reading a tool
result's attestation) and the server side (`McpServerSession`, checking a call,
and the decision on a public write). A call names `mcp:<serverId>.<tool>` as its
receiver, and a response chain ends at the client that made the call. A server
opens an attested session only for a client policy key in its `pinnedClientKeys`.
`McpServerSession` holds no policy private key: it answers handshakes in the
[entry-key form](../spec/sessions-and-influence.md#the-reply), signed by its entry
service's key (`hops[0]`), with the `ServerPolicy`'s `keyringSig` and `replyCert`.
Whoever loads the policy checks that the certificate verifies, names the entry and
its key, and is unexpired.

## policy-tool

`@paztport/policy-tool`: two command-line tools. `paztport-keygen` writes a
keypair per service, a policy keypair and a keyring signed by the policy key;
`paztport-policy` turns a `paths.yaml` into a signed root and one proof bundle per
service, and with `--reply-cert-svc <name> --keyring <keyring.json> [--reply-cert-days 7]` also writes
`reply-cert.json`, a [reply certificate](../spec/wire.md#the-reply-certificate) for that service's key. It
refuses, writing nothing, a keyring that is not signed by its policy key or has no key for the service.
