# Spec

The written protocol spec is coming in a later project. Until then, the
on-the-wire format is in [poc-sdks](../README.md#on-the-wire), and the SDK code is
the reference.

`vectors/` holds the shared, language-neutral conformance vectors that both SDKs
test against, so the two implementations are held to one set of recorded answers:

- `v1.json`: keys, stamps, chains, request bindings, Merkle proofs and verify
  cases for the v1 format. The Java SDK (`paztport-http`) and the TypeScript SDK
  (`@paztport/http`) both replay it.
- `v2.json`: pinned bytes for the v2 bindings, session ids, influence commitments
  and signing bytes. The TypeScript SDK (`@paztport/core`, `@paztport/mcp`)
  checks it.

Change a vector only with a protocol change.
