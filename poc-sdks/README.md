# Paztport SDKs

The SDKs hold the Paztport pieces: stamps, chains, request binding, proofs,
policy, verification, influence and sessions. The demos in
[poc-demos](../poc-demos/README.md) only wire them together.

- [java](java/README.md): `paztport-core`, the `paztport-http` and
  `paztport-spring` extensions, the `keygen` and `policy-tool` command-line tools, and the
  `bench` micro-benchmarks.
- [typescript](typescript/README.md): `@paztport/core`, the `@paztport/mcp`
  extension, and the policy command-line tools.
- [go](go/README.md): one module, `github.com/dumbsly/paztport/poc-sdks/go`: the
  protocol's packages, and `paztporthttp` with its `wire` and `boundary` packages.
- [spec](spec/README.md): the written protocol spec and the shared conformance vectors. The TypeScript SDK
  replays `v4.json`. Java replays `v4.json` in `paztport-core`, but for what belongs to the MCP profile, and
  `http-v4.json` in `paztport-http`. The Go SDK replays `v4.json`, but for its MCP profile sections and the
  MCP-only parts of `influence`, and `http-v4.json` in full. All three replay `events.json`, `json.json` and
  `ed25519.json`. Java and Go replay `intent.json`.
- `scripts/`: the checks that `./run test` runs (links, imports, the review path's line counts
  and jars), the tests for `./run`, and `third-party.sh`, which regenerates `THIRD-PARTY.txt`
  from both Java trees.

## On the wire

The full format is in the [protocol spec](spec/README.md): every byte layout, binding, check and code. This is
a summary of version 4, which the TypeScript SDK, Java's `paztport-core` and `paztport-http`, and the Go SDK speak.

A stamp is a JSON object, and a chain is an array of them, origin first:

```json
{ "v": 4, "svc": "...", "inst": "...", "rid": "...", "ts": 0, "sess": "...", "rcv": "...",
  "bind": "<b64url>", "ext": "<b64url>", "prev": "<b64url>", "sig": "<b64url>" }
```

- `sig` signs the UTF-8 bytes of `paztport-stamp` and a newline, then the JCS bytes of the stamp's other ten
  members, `v` included ([wire.md](spec/wire.md#fields-and-signed-bytes)). JCS escapes every string, so no field
  needs a rule against a delimiter.
- `rcv` names the hop the stamp was handed to: the next stamp's `svc`, and for the last stamp the chain's
  receiver (`mcp:<server>.<tool>` for an MCP call). Over HTTP, an `rcv` may also be `<service>#<operation>`. A
  chain forwarded to anyone else fails `BINDING_MISMATCH`.
- `sess` is the session the handshake opened, `ext` commits to the stamp's block (`""` for the empty block), and
  `bind` binds what the hop sent.
- `prev` is the previous stamp's `sig`, or the empty string at the origin.

A block holds the claims a hop attaches, `{ "items": { "<extension>": [ ... ] }, "requires": [ ... ] }`: its
items under each extension's name, which the core carries without reading, and the extensions it requires the next
hop to act on ([wire.md](spec/wire.md#blocks)). Influence is the extension `influence`, whose entries are items
in each hop's block ([influence.md](spec/influence.md)).

Every Paztport object travels as its JCS bytes, or as their base64url, its token, and each SDK reads it from
those bytes with its own strict reader, never through a transport's JSON parser ([wire.md](spec/wire.md#json)).
Over MCP (the TypeScript SDK), the chain, the route proof and the blocks, one per stamp, travel as tokens in the
`tools/call` request's `_meta`, beside the call id, and a result carries the token of the server's attestation:
its response chain, one block per stamp of it, its proof and the result hash. Over HTTP (the Java and Go SDKs), the
chain, the proof and the blocks travel as tokens in the `X-Path-Chain`, `X-Path-Proof` and `X-Path-Extensions`
headers, a call in a session opened by the handshake over HTTP names it in `X-Path-Session`, and a response
carries one more stamp on the request chain, back to the caller, with its own block, in `X-Path-Response`
([wire.md](spec/wire.md#http)). Version 3 carried influence in `X-Path-Influence` in place of the
blocks. A version 4 verifier accepts only stamps whose `v` is 4.
Binary values are base64url without padding.

The signed root (`root.json`) that verifiers pin is `{ "notAfter", "root", "rootId", "sig" }`, where `sig` is the
policy key's Ed25519 signature over the root, its `rootId` and `notAfter`, the time after which the policy owner no
longer vouches for it ([wire.md](spec/wire.md#the-signed-root)). The Java and TypeScript tools
also sign a keyring (`keyring.json`) with the same key and its own `notAfter`.
