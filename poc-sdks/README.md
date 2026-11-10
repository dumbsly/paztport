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
- [spec](spec/README.md): the written protocol spec and the shared conformance vectors: `v3.json`, which every SDK
  replays (the Java and Go SDKs all of it but the MCP profile), `http-v3.json`, which the Java and Go SDKs
  replay, and `events.json` and `json.json`, which all three replay.
- `scripts/`: the name, link and jar checks that `./run test` runs, the tests for `./run`,
  and `third-party.sh`, which regenerates `THIRD-PARTY.txt` from both Java trees.

## On the wire

The full format is in the [protocol spec](spec/README.md): every byte layout, binding, check and code. This is
a summary.

A stamp is a JSON object, and a chain is an array of them, origin first:

```json
{ "v": 3, "svc": "...", "inst": "...", "rid": "...", "ts": 0, "sess": "...", "rcv": "...",
  "bind": "<b64url>", "infl": "<b64url>", "prev": "<b64url>", "sig": "<b64url>" }
```

- `sig` signs the UTF-8 bytes `3|svc|inst|rid|ts|sess|rcv|bind|infl|prev`, with `ts` in decimal. No field may
  hold `|`.
- `rcv` names the hop the stamp was handed to: the next stamp's `svc`, and for the last stamp the chain's
  receiver (`mcp:<server>.<tool>` for an MCP call). Over HTTP, an `rcv` may also be `<service>#<operation>`. A
  chain forwarded to anyone else fails `BINDING_MISMATCH`.
- `sess` is the session the handshake opened, `infl` commits to the influence the call was made under, and
  `bind` binds what the hop sent.
- `prev` is the previous stamp's `sig`, or the empty string at the origin.

Every Paztport object travels as its JCS bytes, or as their base64url, its token, and each SDK reads it from
those bytes with its own strict reader, never through a transport's JSON parser ([wire.md](spec/wire.md#json)).
Over MCP (the TypeScript SDK), the chain, the route proof and the influence travel as tokens in the `tools/call`
request's `_meta`, beside the call id, and a result carries the token of the server's attestation: its response
chain and content labels. Over HTTP (the Java and Go SDKs), the chain, the proof and the influence travel as
tokens in the `X-Path-Chain`, `X-Path-Proof` and `X-Path-Influence` headers, a call in a session opened by the
handshake over HTTP names it in `X-Path-Session`, and a response carries one more stamp on the request chain, back
to the caller, in `X-Path-Response` ([wire.md](spec/wire.md#http-v3)). A verifier
accepts only stamps whose `v` is 3. Binary values are base64url without padding.

The signed root (`root.json`) that verifiers pin is `{ "notAfter", "root", "rootId", "sig" }`, where `sig` is the
policy key's Ed25519 signature over the root, its `rootId` and `notAfter`, the time after which the policy owner no
longer vouches for it ([wire.md](spec/wire.md#the-signed-root)). The Java and TypeScript tools
also sign a keyring (`keyring.json`) with the same key and its own `notAfter`.
