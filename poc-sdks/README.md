# Paztport SDKs

The SDKs hold the Paztport pieces: stamps, chains, request binding, proofs,
policy, verification, influence and sessions. The demos in
[poc-demos](../poc-demos/README.md) only wire them together.

- [java](java/README.md): `paztport-core`, the `paztport-http` and
  `paztport-spring` extensions, and the `keygen` and `policy-tool` jobs.
- [typescript](typescript/README.md): `@paztport/core`, the `@paztport/http` and
  `@paztport/mcp` extensions, and the policy command-line tools.
- [spec](spec/README.md): the shared conformance vectors that both SDKs test against.
- `scripts/`: the name and link checks that `./run test` runs, and the tests for `./run`.

## On the wire

This is the v1 format. The Java SDK (`paztport-core`, with `paztport-http` for the
request binding) is its reference implementation. Binary values are **base64url
without padding**, and both headers are base64url-encoded JSON.

`X-Path-Chain` is a JSON array of stamps, origin first:

```json
[{ "svc": "...", "inst": "...", "rid": "...", "ts": 0,
   "bind": "<b64url>", "prev": "<b64url>", "sig": "<b64url>" }]
```

- `sig` signs the UTF-8 bytes `svc|inst|rid|ts|bind|prev`, joined with `|`, with
  `ts` in decimal.
- `prev` is the previous stamp's `sig` as base64url, or the empty string at the
  origin.
- `bind` is `b64url(SHA-256(METHOD \n PATH \n BODY))` of the request this hop sent.

`X-Path-Proof` proves membership for the full route, **including the receiving
service**:

```json
{ "leafSalt": "<b64url>", "siblings": ["<b64url>", ...], "dirs": "LRL...", "rootId": "..." }
```

`dirs[i]` is `L` when the working hash is the left input at level `i`, and `R`
otherwise.

The signed root (`root.json`) that verifiers pin:

```json
{ "rootId": "...", "root": "<b64url>", "sig": "<b64url>" }
```

`sig` is the policy key's Ed25519 signature over `rootId|root`.
