# Wire format

This file defines the bytes: encodings, keys, stamps, chains, bindings, the Merkle tree, the signed root,
the signed keyring and the proof bundles. [verification.md](verification.md) says how a receiver checks
them, and [sessions-and-influence.md](sessions-and-influence.md) covers the handshake and influence.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [Encodings](#encodings) · [Keys and files](#keys-and-files) · [Stamps](#stamps) ·
[Chains](#chains) · [Bindings](#bindings) · [Carrying a chain](#carrying-a-chain) ·
[The Merkle tree](#the-merkle-tree) · [Routes](#routes) · [The signed root](#the-signed-root) ·
[The signed keyring](#the-signed-keyring) · [Proof bundles, and who holds what](#proof-bundles-and-who-holds-what)

## Encodings

| What | Rule |
|---|---|
| Text | Every string that is hashed or signed is encoded as UTF-8. A string that holds a lone surrogate has no UTF-8 form, so it MUST be rejected wherever this spec says so, and MUST NOT be signed. |
| Binary values | **base64url without padding** (RFC 4648 §5). Encoders MUST NOT emit `=`. Decoders MUST reject any character outside `A–Z a–z 0–9 - _`, and a length that is 1 more than a multiple of 4. They MAY accept up to two trailing `=`, as both SDKs do. |
| Canonical encoding | Where this spec compares encoded values, it compares the text, so a value with two encodings matches only one of them. A v2 or v3 stamp's `sig` MUST decode and re-encode to the identical text, or the chain does not parse (see [Stamp field rules](#stamp-field-rules)). |
| Canonical JSON | **JCS**, RFC 8785: object keys sorted by their UTF-16 code units, no whitespace, numbers in the ECMAScript shortest form, strings escaped as `JSON.stringify` does. JCS MUST fail on a lone surrogate, a non-finite number, or anything that is not plain JSON. Arrays keep their order. |
| Hash | SHA-256. `H(x)` below is SHA-256 of the bytes `x`. |
| Signatures | Ed25519 (RFC 8032), pure, with no pre-hash and no context. A signature is 64 bytes. Verifiers SHOULD apply RFC 8032 §5.1.7 in full, including the check that S is below the group order. |
| Integers | `ts` is an integer number of milliseconds since the Unix epoch. In signed bytes it is written in decimal, with no leading zeros, no `+` and no exponent. |

`b64url(x)` is the base64url text of `x`, and `utf8(s)` the UTF-8 bytes of `s`. `‖` is byte concatenation,
and `\n` is the single byte `0x0A`.

## Keys and files

| Key | Encoding |
|---|---|
| Public key | The X.509 SubjectPublicKeyInfo DER of the Ed25519 key (44 bytes, starting `302a300506032b6570032100`), as base64url. |
| Private key | The PKCS#8 DER of the Ed25519 key (48 bytes: `302e020100300506032b657004220420` ‖ the 32-byte seed), as base64url. |

The policy tools write these files, except the pins of the other side of a session, which whoever onboards that
side writes (in the agents demo, its setup script). Each holds one value, and readers trim surrounding whitespace.

| File | Holds | Secret |
|---|---|---|
| `<svc>.key` | The service's private key | yes |
| `policy.key` | The policy private key, which signs the root and the keyring | yes |
| `keyring.json` | [The signed keyring](#the-signed-keyring) | no |
| `root.json` | [The signed root](#the-signed-root) | no |
| `proofs-<svc>.json` | [A proof bundle](#proof-bundles-and-who-holds-what) | no, but it reveals its own routes |
| `policy.pub` | The policy public key that a mesh's own services pin, written by the Java keygen | no |
| `<side>-policy.pub` | A pinned policy public key (`server-policy.pub`, `client-policy.pub`) | no |

## Stamps

A stamp is a JSON object. Field order in the JSON is not significant; encoders SHOULD write the fields in the
order shown.

### v3 (current)

```json
{ "v": 3, "svc": "...", "inst": "...", "rid": "...", "ts": 0, "sess": "...", "rcv": "...",
  "bind": "...", "infl": "...", "prev": "...", "sig": "<b64url>" }
```

| Field | Type | Meaning |
|---|---|---|
| `v` | the number `3` | Version. |
| `svc` | string | The signing service. The verifier looks its key up by this name, and rebuilds the route from it. |
| `inst` | string | The signer's instance, as the signer reports it. Signed, but only the signer vouches for it. |
| `rid` | string | The request id, minted at the origin and carried unchanged by every stamp. |
| `ts` | integer | When this stamp was signed, in ms since the Unix epoch. |
| `sess` | string | The session id ([sessions-and-influence.md](sessions-and-influence.md#the-session-id)), or `""` for a chain with no session: one that never leaves one process, such as a local step, or one inside a single HTTP mesh. |
| `rcv` | string | The receiver this stamp was signed for: the next stamp's `svc`, or for the last stamp, the receiver of the chain. See [Receivers](#receivers). |
| `bind` | string | The binding of what this hop sent. See [Bindings](#bindings). |
| `infl` | string | The influence commitment: `""` for no influence, otherwise `b64url(H(utf8(JCS(normalise(entries)))))`, with `normalise` as defined in [sessions-and-influence.md](sessions-and-influence.md#normalisation-and-commitment). |
| `prev` | string | The previous stamp's `sig`, exactly as written, or `""` at the origin. |
| `sig` | string | `b64url` of the Ed25519 signature, by `svc`'s key, over the signed bytes. |

The signed bytes are:

```
utf8( "3|" svc "|" inst "|" rid "|" ts "|" sess "|" rcv "|" bind "|" infl "|" prev )
```

That is the ten values `3, svc, inst, rid, ts, sess, rcv, bind, infl, prev`, joined with `|` (`0x7C`), with `ts`
in decimal. `v3.json` pins two layouts in `signingBytesV3`. For example, the stamp
`{ v: 3, svc: "pi", inst: "pi-é", rid: "rid-1", ts: 1767225600000, sess: "", rcv: "local:read", bind: "bind-2", infl: "", prev: "prev-2" }`
signs the bytes of `3|pi|pi-é|rid-1|1767225600000||local:read|bind-2||prev-2`, with `é` as `c3 a9`.

### Stamp field rules

These hold for v2 and v3 stamps. A signer MUST NOT sign a stamp that breaks them, and a verifier MUST reject
one that does, with the code in brackets.

- The chain is a non-empty JSON array of objects (`CHAIN_MISSING`).
- `v` is exactly the stamp's version number, `2` or `3` (`CHAIN_MISSING`).
- `ts` is a JSON number that is an integer with an absolute value of at most 2^53 − 1 (`CHAIN_MISSING`), so
  every implementation reads and prints it the same way. It is checked by value: `1.0` and `1e3` are the
  integers 1 and 1000.
- Every string field (`svc`, `inst`, `rid`, `sess`, `rcv` in v3, `bind`, `infl`, `prev`, `sig`) is a JSON
  string (`CHAIN_MISSING`) with no lone surrogate (`CHAIN_MISSING`).
- `sig` decodes as base64url and re-encodes to the identical text (`CHAIN_MISSING`).
- No signed field holds `|` (`BAD_SIGNATURE`). The fields are joined with `|`, so a field holding it would let
  two different stamps share signed bytes.
- A v3 stamp without `rcv` does not parse (`CHAIN_MISSING`). A v2 stamp's `rcv`, if it has one, is not signed,
  so it is ignored.
- Every stamp in a chain has the same version. A chain that mixes v2 and v3 does not parse (`CHAIN_MISSING`),
  so a v3 stamp can never lend its receiver check to a v2 chain.

Unknown fields are ignored; they are not signed.

### v2 (legacy)

```json
{ "v": 2, "svc": "...", "inst": "...", "rid": "...", "ts": 0, "sess": "...",
  "bind": "...", "infl": "...", "prev": "...", "sig": "<b64url>" }
```

The fields mean what they mean in v3. There is no `rcv`, so a v2 stamp does not say who it was meant for. The
signed bytes are:

```
utf8( "2|" svc "|" inst "|" rid "|" ts "|" sess "|" bind "|" infl "|" prev )
```

Implementations MUST NOT produce v2 stamps. A verifier MAY accept a v2 chain read back from a record, and only
offline, as legacy ([verification.md](verification.md#the-legacy-rule)). `v2.json` pins the layout in
`signingBytesV2`.

### v1 (the HTTP mesh format)

```json
{ "svc": "...", "inst": "...", "rid": "...", "ts": 0, "bind": "...", "prev": "...", "sig": "<b64url>" }
```

v1 has no `v`, `sess`, `rcv` or `infl`. Its `ts` is the origin's time, carried unchanged. The signed bytes are:

```
utf8( svc "|" inst "|" rid "|" ts "|" bind "|" prev )
```

v1 has no delimiter rule, so its fields are not checked for `|`. v1 is kept for `v1.json` only: both SDKs replay
it, and neither demo sends it. A v1 stamp has no `v`, so a live v3 verifier reads a v1 chain as `CHAIN_MISSING`.

## Chains

A chain is an array of stamps, **origin first**.

- **Origin.** The first stamp has `prev = ""`. Its `svc` MUST be one of the verifier's allowed origins: only an
  entry point holds an origin key, so an inner service can't start a chain.
- **Links.** Stamp *i* (for *i* ≥ 1) has `prev` equal to stamp *i − 1*'s `sig`. Because each signature covers
  `prev`, removing, reordering or inserting a stamp breaks a signature or a link.
- **Shared values.** Every stamp carries the origin's `rid`. In v2 and v3 every stamp carries the session's
  `sess`.
- **Receivers (v3).** Stamp *i*'s `rcv` MUST equal stamp *i + 1*'s `svc`, and the last stamp's `rcv` MUST equal
  the chain's receiver. So each stamp names the hop it was handed to, and a chain forwarded unchanged to anyone
  else fails.
- **The last stamp** is the one whose `bind` and `infl` the receiver checks: it describes what was actually
  sent.

### Receivers

| Chain | Stamps, origin first | Each `rcv` |
|---|---|---|
| HTTP hops (mesh) | `gateway`, `orders` | `orders`, then `payment`: each hop names the next service, and the last names the receiving service. |
| HTTP response | `gateway`, `orders`, then `payment`'s response stamp | The request's, then `orders`: the response stamp names the caller, the request's last `svc`. |
| Run origin (agents) | `session` | `pi`: the client hop the run's origin hands to. The origin is minted once per run and server session, and reused for every call in it. |
| MCP tool call | `session`, `pi` | `pi`, then `mcp:<server>.<tool>`, where `<server>` is the server id and `<tool>` the tool name. |
| MCP response | `mcp-entry`, `github-tools` | `github-tools`, then the calling client's `svc` (`pi`): the response chain ends at whoever made the call. |
| Local step | `session`, `pi` (with `sess = ""`) | `pi`, then `local:<tool>`. |
| Boundary stamp | the egress service | The partner's entry service ([sessions-and-influence.md](sessions-and-influence.md#between-organisations)). |

The names in the second column are the agents demo's and the vectors'; the shape of each row is the rule.

An MCP server id MUST NOT contain `/`, `|` or `.`, and a tool name MUST NOT contain `/` or `|`. `/` would add a
route segment, `|` is the stamp delimiter, and a `.` in the server id would make `mcp:a.b.c` ambiguous. A
verifier MUST reject a call that breaks this (`CHAIN_MISSING`).

## Bindings

A stamp's `bind` ties it to what its hop sent, so a chain copied onto a different payload fails. Every binding
is `b64url(H(bytes))`, over these bytes:

| Binding | Used for | Bytes |
|---|---|---|
| HTTP | An HTTP hop's request | `utf8(METHOD) ‖ \n ‖ utf8(PATH) ‖ \n ‖ BODY`, the body as raw bytes. There is no prefix. `PATH` is the request target as sent: the raw path, plus `?` and the raw query when the query is non-empty, with nothing decoded, so `/pay?` binds as `/pay`. With no query the bytes are v1's. |
| HTTP result | An HTTP response's `resultHash` | `utf8("http-response\n" ‖ status ‖ "\n") ‖ BODY`, with `status` the response's status code in decimal and the body as raw bytes, so a response can't pass under another status. |
| Prompt | A run's origin stamp | `utf8("prompt\n" ‖ text)` |
| `tools/call` | An MCP call's stamp | `utf8("tools/call\n" ‖ tool ‖ "\n" ‖ callId ‖ "\n" ‖ JCS(arguments))`. Absent or `null` arguments hash as `{}`. |
| Result | An MCP result's `resultHash` | `utf8("result\n" ‖ JCS(result))`, with the result's top-level `_meta` key removed first. |
| Response | The last stamp of a response chain | `utf8(resultHash ‖ "\n" ‖ toolCallId ‖ "\n" ‖ JCS(labels))`. There is no prefix: it starts with the result hash. |
| Local tool | A local step's stamp | `utf8("tool\n" ‖ toolName ‖ "\n" ‖ JCS({ "input": input, "resolved": decision }))`. An absent or `null` input, or decision, hashes as `{}`. |

Rules:

- `tool`, `callId`, `toolCallId` and `toolName` MUST NOT contain `\n`, so the parts can't run into each other.
  A verifier that cannot compute the binding for a call MUST reject it (`BINDING_MISMATCH`).
- A string with a lone surrogate has no UTF-8 form. A part hashed as JCS fails on one ([Encodings](#encodings)).
  The prompt and response bindings MUST refuse one in their other strings (the text, `resultHash` and
  `toolCallId`), never compute a binding over it. The other bindings' plain strings (the HTTP method and path,
  the `tools/call` tool and call id, the local tool's name) have no such rule yet, and the SDKs replace a lone
  surrogate there. The TypeScript SDK also replaces it in the prompt and response bindings, against the rule.
  See [Conformance](README.md#conformance).
- `labels` in the response binding is the attestation's label array in its own order, each label written as
  `{ cls, cid }` or `{ cls, cid, owner }` (other fields are dropped before hashing).
- In a response chain the first stamp, by the server's entry service, binds the call it took (the `tools/call`
  binding), and the last binds the response.
- The local tool `decision` is the gate's signed decision on the call:
  `{ "callId": ..., "resolved": { "paths": [{ "need", "at" }], "programs": [{ "name", "via" }], "parse": "ok" | "error", "readOnly": bool }, "verdict": ..., "routeAllowed": bool, "rulesHash": string | null }`.
  So the call id, what the gate resolved, its verdict, whether the route is listed and which rules decided
  are all covered by the stamp.

`v1.json` pins the HTTP binding in `bindings`. `v2.json` pins the prompt, `tools/call`, result and response
bindings. `v3.json` pins a local-tool binding through the `local step ok` case. `http-v3.json` pins the HTTP
binding with and without a query in `requestBinding`, and the HTTP result hash in `resultHash`.

## Carrying a chain

### MCP (v3)

A tool call carries Paztport in the `tools/call` request's `params._meta`:

| `_meta` key | Value |
|---|---|
| `paztport/chain` | The chain, as a JSON array of stamps: the run's origin, then the calling hop's stamp. |
| `paztport/proof` | The proof for the call's route, a [proof object](#proof-object). |
| `paztport/influence` | The influence entries the call was made under, as a JSON array ([sessions-and-influence.md](sessions-and-influence.md#entries)). The last stamp's `infl` commits to them. |
| `paztport/callId` | The call id, a string, which the `tools/call` binding covers. |

A result carries the server's attestation in `result._meta["paztport/attestation"]`:

```json
{ "chain": [ /* the response chain, v3 */ ], "proof": { /* proof for the server's route */ },
  "labels": [{ "cls": "private", "cid": "<b64url>", "owner": "..." }], "resultHash": "<b64url>" }
```

`resultHash` is the result binding of the result it rides on. A refusal carries `result._meta["paztport/verdict"]`
instead: `{ "reason": "<code>" }`, or `{ "reason": "<code>", "audit": true }` when an audit-mode server ran the
call anyway. A verdict is not signed ([verification.md](verification.md#the-mcp-server-and-client)). The
handshake is the JSON-RPC method `paztport/session` ([sessions-and-influence.md](sessions-and-influence.md#the-handshake)).

### HTTP (v3)

A request carries Paztport in three headers, each the base64url of UTF-8 JSON, and names its session in a fourth, which is plain text:

| Header | Value |
|---|---|
| `X-Path-Chain` | The chain, as a JSON array of v3 stamps, origin first. The last stamp's `rcv` is the receiving service, and its `bind` the [HTTP binding](#bindings) of the request sent. |
| `X-Path-Proof` | The [proof object](#proof-object) for the full route, receiving service included. |
| `X-Path-Influence` | The influence entries the request was made under, as a JSON array ([sessions-and-influence.md](sessions-and-influence.md#entries)). An absent header means `[]`. The last stamp's `infl` commits to them. |
| `X-Path-Session` | The [session id](sessions-and-influence.md#the-session-id), as plain text, on a call made in a session opened by [the handshake over HTTP](sessions-and-influence.md#over-http). Inside a mesh, which has no handshake, it is absent. An absent header means no session; one that is not the peer's current session is refused `SESSION_UNKNOWN`. |

A response carries the answering service's attestation in one header, also the base64url of UTF-8 JSON:

| Header | Value |
|---|---|
| `X-Path-Response` | The JSON object `{ "stamp": <v3 stamp>, "labels": [ ... ] }`, the labels written as in an MCP attestation. |

The response stamp is one more stamp on the request chain the answering service received, so it needs no proof
of its own: the caller already holds the proof for the request's route. Because it is shaped like a request stamp,
a service attests only a chain that verified there, and an origin never attests
([verification.md](verification.md#http-requests-and-responses) has the rule).

| Field | Value |
|---|---|
| `v` | `3`. |
| `svc` | The answering service. |
| `inst` | The answering service's instance, as it reports it. |
| `rcv` | The caller: the request's last `svc`. |
| `rid`, `sess` | The request's. |
| `ts` | When the answering service signed it. |
| `bind` | The response binding of `resultHash` (the [HTTP result](#bindings) binding of the status and body sent), with the request's `rid` as the call id, over `labels`. |
| `infl` | `""`: a response's labels are in its binding instead. |
| `prev` | The request's last `sig`. |
| `sig` | The answering service's signature over the v3 signed bytes, as for any stamp. |

[verification.md](verification.md#http-requests-and-responses) says how each side checks these. Only the Java
SDK speaks v3 over HTTP, and `http-v3.json` pins it.

## The Merkle tree

The allowed routes are the leaves of a salted Merkle tree. A verifier pins only the signed root.

| Part | Rule |
|---|---|
| Leaf | `H(0x00 ‖ salt ‖ utf8(route))` |
| Node | `H(0x01 ‖ left ‖ right)` |
| Salt | 16 random bytes per leaf, from a cryptographic random source, fresh on every build. |
| Depth | Fixed: 8 by default, so 256 leaf slots. Each route takes a random slot, so a proof's `dirs` reveals nothing about policy order. |
| Padding | Every unused slot holds 32 random bytes, which look like any other leaf hash. |

Why: the `0x00` and `0x01` prefixes stop a 64-byte node from passing as a leaf (the second-preimage attack). A
real route space is small, so an unsalted leaf could be confirmed by hashing a few guesses: the salt is a
secret, not extra effort. A fixed depth means a proof's length says nothing about how many routes exist, and random slots mean its `dirs` say nothing about where in the policy a route sits.
A builder MUST NOT build a tree with an unsalted leaf, MUST NOT reuse salts across builds, and MUST choose slots
from a cryptographic random source, never in policy order.

### Proof object

```json
{ "leafSalt": "<b64url, 16 bytes>", "siblings": ["<b64url, 32 bytes>", ...], "dirs": "LRL...", "rootId": "..." }
```

`siblings` runs from the leaf's level up to the level below the root. `dirs[i]` is `L` when the working hash is
the left input at level *i*, and `R` when it is the right. A verifier checks a proof for `route` against the
pinned `root` and `rootId` like this, and any failure is "not proven":

1. The proof is an object whose `leafSalt`, `dirs` and `rootId` are strings and whose `siblings` is an array
   of strings; `dirs` matches `^[LR]*$` and has as many characters as `siblings` has entries.
2. `rootId` equals the pinned root's `rootId`.
3. `leafSalt` decodes to exactly 16 bytes, and each sibling to exactly 32.
4. Starting from `w = H(0x00 ‖ salt ‖ utf8(route))`, for each level *i*: `w = H(0x01 ‖ w ‖ sibling[i])` when
   `dirs[i]` is `L`, else `w = H(0x01 ‖ sibling[i] ‖ w)`.
5. `w` equals the pinned root's bytes.

The verifier need not check the depth: the root commits to the tree's shape, and the domain prefixes stop a
shorter or longer path from reaching it.

### rootId

`rootId = "v" ‖ 12 lowercase hex digits of 6 random bytes`, from a cryptographic random source, fresh on every
build. It is a label, compared for equality and never derived from the routes: a label derived from the routes
would let anyone who guessed a policy confirm the guess. §"The signed root" is unchanged. The `rootId`s pinned in
`v3.json` come from the vectors' own fixed construction (described in its `about`), for example `v128498df6662`
for the client policy in `policies.client`; a real build does not produce them.

## Routes

A route is the list of services a request passed through, then its receiver, joined with `/`:

```
route = svc₁ "/" svc₂ "/" … "/" receiver
```

The verifier always rebuilds the route from the stamps' authenticated `svc` fields, never from a claimed field.

- A route has at least two nodes, because its proof is held by its caller (the node before the last).
- A route node MUST be non-empty, MUST NOT be `.` or `..`, and MUST NOT contain `/`, `\`, `|` or a lone
  surrogate. Node names become route segments and file names (`proofs-<svc>.json`).
- A call's route ends at its receiver: `gateway/orders/payment`, or `session/pi/mcp:github.create_pull_request`.
- An MCP response's route is the server's own hops, `mcp-entry/github-tools`. Its receiver, the calling client,
  is not on it: the server's policy can't list every client.
- An HTTP response's route is the request's own, `gateway/orders/payment`, proven by the proof the caller sent.
  Its receiver, the caller, is already on it.
- A local step's route is `session/pi/local:<tool>`.
- A client's local folder rules are pinned as one more route, `session/pi/rules:<rulesHash>`, where
  `rulesHash = b64url(H(utf8("local-rules\n" ‖ JCS(rules))))` and `rules` is the parsed rule set
  `{ "v": 1, "folders": [...], "programs": [...] }` (its format is in the
  [pi-extension README](../../poc-demos/agents-mcp/pi-extension/README.md#local-tool-gating)). A client MUST NOT
  apply rules that the signed root does not cover.

## The signed root

`root.json`, the value verifiers pin:

```json
{ "rootId": "...", "root": "<b64url, 32 bytes>", "sig": "<b64url>" }
```

`sig` is the policy key's Ed25519 signature over `utf8(rootId ‖ "|" ‖ root)`, with `root` as its base64url text.
A widened policy can't be swapped in without the policy private key. A verifier MUST check the signature
against the pinned policy key before using the root.

## The signed keyring

`keyring.json` names the policy key and every service's public key, and is signed by the policy key:

```json
{ "services": { "<svc>": "<public key>", ... }, "policy": "<policy public key>", "sig": "<b64url>" }
```

`sig` is the policy key's Ed25519 signature over:

```
utf8( "paztport-keyring\n" ‖ JCS({ "policy": policy, "services": services }) )
```

A keyring verifies under a pinned policy key only when its `policy` equals that key and `sig` verifies under it.
The prefix keeps a keyring signature from being read as any other message the policy key signs. Without the
signature, a session's keyring would be the client's own claim, and anyone who could open a session could name
their own keys. `v3.json` pins the signed bytes and the signature in `keyring`, with a tampered keyring that
fails.

Both SDKs' keygens write signed keyrings.

## Proof bundles, and who holds what

`proofs-<svc>.json` holds the proofs a service attaches to the requests it sends:

```json
{ "service": "<svc>", "rootId": "...", "proofs": { "<route>": { /* proof object */ }, ... } }
```

A route's proof is held by its caller, the node before the last, since that is the hop that sends the request
the proof travels with.

| Party | Holds | Never holds |
|---|---|---|
| Policy owner | The policy private key, offline. It signs the root and the keyring. | |
| Each service | Its own private key, and its own proof bundle. | Other services' keys, other routes' salts. |
| Each verifier | The pinned policy public key, the signed root and the signed keyring. | The tree, the route list or any salt but those in the proofs it is shown. |
| The other side of a session | The peer side's policy key, pinned in advance, and the root and keyring it sends in the handshake. | Its map. |

In the agents demo the client's policy private key is deleted once it has signed the client root and keyring;
the server's stays, because it signs session replies.
