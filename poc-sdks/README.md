# Paztport SDKs

The SDKs hold the Paztport pieces: stamps, chains, request binding, proofs,
policy, verification, influence and sessions. The demos in
[poc-demos](../poc-demos/README.md) only wire them together.

- [java](java/README.md): `paztport-core`, the `paztport-http` and
  `paztport-spring` extensions, and the `keygen` and `policy-tool` jobs.
- [typescript](typescript/README.md): `@paztport/core`, the `@paztport/http` and
  `@paztport/mcp` extensions, and the policy command-line tools.
- [spec](spec/README.md): the written protocol spec and the shared conformance vectors: v1, which
  both SDKs replay, and v2 and v3, which the TypeScript SDK checks.
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

Over MCP, the chain, the route proof, the influence and the call id travel in the `tools/call` request's
`_meta`, and a result carries the server's response chain and content labels. A live verifier accepts v3 only;
v2 records are accepted only offline, marked legacy.

v1, which the Java SDK speaks, travels in the `X-Path-Chain` and `X-Path-Proof` headers, and its stamps sign
`svc|inst|rid|ts|bind|prev`, with no receiver ([wire.md](spec/wire.md#v1-the-http-mesh-format)). Binary values
are base64url without padding, in every version.

The signed root (`root.json`) that verifiers pin is `{ "rootId", "root", "sig" }`, where `sig` is the policy key's
Ed25519 signature over `rootId|root`. A keyring (`keyring.json`) written by the TypeScript tools is signed by the
same key; the Java keygen's keyrings aren't signed yet.
