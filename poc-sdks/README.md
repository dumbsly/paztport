# Paztport SDKs

The SDKs hold the Paztport pieces: stamps, chains, request binding, proofs,
policy, verification, influence and sessions. The demos in
[poc-demos](../poc-demos/README.md) only wire them together.

- [java](java/README.md): `paztport-core`, the `paztport-http` and
  `paztport-spring` extensions, and the `keygen` and `policy-tool` jobs.
- [typescript](typescript/README.md): `@paztport/core`, the `@paztport/mcp`
  extension, and the policy command-line tools.
- [spec](spec/README.md): the written protocol spec and the shared conformance vectors: v3,
  which both SDKs replay (the Java SDK all of it but the MCP profile), and v3 over HTTP, which only the Java SDK
  speaks.
- `scripts/`: the name and link checks that `./run test` runs, the tests for `./run`, and
  `third-party.sh`, which regenerates `THIRD-PARTY.txt` from both Java trees.

## On the wire

The full format is in the [protocol spec](spec/README.md): every byte layout, binding, check and code. This is
a summary of v3, the current version.

A v3 stamp is a JSON object, and a chain is an array of them, origin first:

```json
{ "v": 3, "svc": "...", "inst": "...", "rid": "...", "ts": 0, "sess": "...", "rcv": "...",
  "bind": "<b64url>", "infl": "<b64url>", "prev": "<b64url>", "sig": "<b64url>" }
```

- `sig` signs the UTF-8 bytes `3|svc|inst|rid|ts|sess|rcv|bind|infl|prev`, with `ts` in decimal. No field may
  hold `|`.
- `rcv` names the hop the stamp was handed to: the next stamp's `svc`, and for the last stamp the chain's
  receiver (`mcp:<server>.<tool>` for an MCP call). A chain forwarded to anyone else fails `BINDING_MISMATCH`.
- `sess` is the session the handshake opened, `infl` commits to the influence the call was made under, and
  `bind` binds what the hop sent.
- `prev` is the previous stamp's `sig`, or the empty string at the origin.

Over MCP (the TypeScript SDK), the chain, the route proof, the influence and the call id travel in the
`tools/call` request's `_meta`, and a result carries the server's response chain and content labels. Over HTTP
(the Java SDK), the chain, the proof and the influence travel in the `X-Path-Chain`, `X-Path-Proof` and
`X-Path-Influence` headers, and a response carries one more stamp on the request chain, back to the caller, in
`X-Path-Response` ([wire.md](spec/wire.md#http-v3)). A verifier accepts v3 stamps only.

Binary values are base64url without padding.

The signed root (`root.json`) that verifiers pin is `{ "rootId", "root", "sig", "notAfter" }`, where `sig` is the
policy key's Ed25519 signature over the root, its `rootId` and `notAfter`, the time after which the policy owner no
longer vouches for it ([wire.md](spec/wire.md#the-signed-root)). A keyring (`keyring.json`) is signed by the same
key, with its own `notAfter`, by both SDKs' tools.
