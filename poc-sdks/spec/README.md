# Paztport protocol spec

This is the written Paztport protocol, for anyone implementing it in a new language. It gives every value
exactly: the byte layouts, field orders, prefixes, constants, the order of the checks and the code each check
fails with. Where it explains a rule, it says why in a clause.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

| File | What it holds |
|---|---|
| [wire.md](wire.md) | Encodings, keys and files, stamps (v1, v2, v3) and their signed bytes, chains and receivers, every binding, how a chain is carried, the Merkle tree, routes, the signed root, the signed keyring, the reply certificate, proof bundles and who holds what. |
| [verification.md](verification.md) | The live order of checks, freshness and nonce keys, the receiver and peer checks, attribution, the MCP wrappers, HTTP requests and responses, offline verification, the legacy rule, v1, the reason codes, and guidance for a responder. |
| [sessions-and-influence.md](sessions-and-influence.md) | The session handshake, the session id, status and unsafe sessions, the server's decision, influence entries and their commitment, content labels, the owner-aware rule, and the boundary attestation between organisations. |
| [vectors/](vectors) | The conformance vectors. |

## Versions

| Version | Status | What it is |
|---|---|---|
| v1 | Kept for `v1.json` | The first HTTP mesh format: stamps in the `X-Path-Chain` header and the proof in `X-Path-Proof`. No session, receiver or influence. Both SDKs replay `v1.json`; neither demo sends v1. |
| v2 | Legacy | Stamps with a session and an influence commitment, but no receiver. Implementations MUST NOT produce it. It is accepted only offline, for records made before v3, and marked legacy. |
| v3 | Current | v2 plus `rcv`: every stamp names the hop it was handed to. Live verifiers accept only v3. It travels over MCP (the TypeScript SDK) and over HTTP (the Java SDK). |

What v3 changed, deliberately:

- **The receiver check.** A live call or chain stamped for a different receiver is `BINDING_MISMATCH`, found
  with the links, not a route failure later. So a chain forwarded unchanged no longer blames its last signer.
- **v3 only, live.** A live verifier rejects a v2 chain (`CHAIN_MISSING`). An offline verifier accepts an
  all-v2 chain as legacy, and a mixed one never.
- **The signed keyring.** A keyring is signed by its policy key, and the session request carries that
  signature as `clientKeyringSig`. A request without the field is legacy offline and unsafe live. One whose
  signature is present but malformed (not a string) or wrong is unsafe live, and offline is a v3 request whose
  signature fails, not a legacy one. A server attests a session only for a client
  policy key it has pinned.
- **The transport peer.** A verifier given an authenticated peer checks it is the last signer
  (`PEER_MISMATCH`), and names it in every result.
- **Owners.** An influence entry and a content label may carry an `owner`, and one owner-aware rule decides
  public writes.
- **Legacy is reported.** An item verified from v2 stamps, or from a session request with no keyring signature,
  is marked legacy in a verifier's report.

## Conformance

`vectors/` holds language-neutral vectors, so every implementation is held to one set of recorded answers.

| File | Covers | Replayed by |
|---|---|---|
| `v1.json` | v1 keys, stamps and their signed bytes, chain headers, HTTP request bindings, Merkle leaves, nodes and proofs, the signed root, and the v1 verify cases. | Java (`paztport-http`) and TypeScript (`@paztport/http`) |
| `v2.json` | The session id, the prompt, result, `tools/call` and response bindings, the influence commitment, and the v2 signed bytes. | TypeScript (`@paztport/core`, `@paztport/mcp`), and Java (`paztport-core`) for all but the result and `tools/call` bindings, which only MCP uses |
| `v3.json` | v3 signed bytes and signatures, influence with owners and its commitment, the owner-aware rule's truth table, the signed keyring, reply certificates (the signed bytes and signature, a tampered `notAfter`, one signed by and one naming another policy key, an ignored extra field and the largest `notAfter`), live verify cases (each kind of receiver, a v2 chain live, malformed `rcv` fields, the check order, the peer and attribution, replay, an altered owner) and offline cases (a legacy v2 call, with and without a stray `rcv`, a v3 call, a mixed chain, a broken receiver, the recorded time, age, prompt and replay checks). | Java (`paztport-core`) and TypeScript (`@paztport/mcp`) |
| `http-v3.json` | v3 over HTTP: the HTTP result hash, the request binding with and without a query, and response checks (a good response, one sent to the wrong receiver, altered labels, an altered status and a replay), and blinded boundary influence (the salts, the sent entries, and an opening that opens and one with an extra original that does not). It reuses `v3.json`'s keys and mesh policy by name, and adds a `payment` key derived by `v3.json`'s rule. | Java (`paztport-http`) only. The TypeScript SDK does not speak v3 over HTTP and does not replay it. |

| Version | Java SDK | TypeScript SDK |
|---|---|---|
| v1 | yes, for `v1.json` | yes, for `v1.json` |
| v2 (offline, legacy) | yes | yes |
| v3: stamps, the live and offline verifiers, influence and sessions | yes | yes |
| v3 over MCP | no | yes |
| v3 over HTTP | yes | no |

A new implementation MUST pass `v3.json`. It MUST pass `v2.json` if it reads records made before v3,
`http-v3.json` if it speaks v3 over HTTP, and `v1.json` if it speaks the v1 HTTP format.

Known divergences, with no vector: a lone surrogate in a binding's plain strings ([wire.md](wire.md#bindings)).
The Java SDK's prompt and response bindings refuse one, as the spec requires, and its HTTP request binding
encodes it as `?`. The TypeScript SDK's bindings (prompt, response, `tools/call`, local tool and HTTP) encode it
as U+FFFD, so its prompt and response bindings break the rule.

`v3.json` is self-contained: every case carries its inputs, and keys and policies are named and defined in the
file. Its `about` field says how its keys, salts and padding are derived, so the file can be rebuilt byte for
byte; a verify case runs the live verifier `uses` times against one nonce cache, and the last result is the one
expected. An offline case runs the offline verifier once, with no peer, clock or nonce TTL: `recordedTs.last` is
the recorded time of the last stamp, and `seen` is the set of nonce keys already spent in the record set.

Cases may be added at any time. A recorded answer changes only with a protocol change.
