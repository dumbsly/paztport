# Wire format

This file defines the bytes: encodings, how JSON is read and written, keys, stamps, chains, bindings, the Merkle
tree, the signed root, the signed keyring, the reply certificate, events and the proof bundles.
[verification.md](verification.md) says how a receiver checks them, and
[sessions-and-influence.md](sessions-and-influence.md) covers the handshake and influence.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [Encodings](#encodings) · [JSON](#json) · [Keys and files](#keys-and-files) · [Stamps](#stamps) ·
[Chains](#chains) · [Bindings](#bindings) · [Carrying a chain](#carrying-a-chain) ·
[The Merkle tree](#the-merkle-tree) · [Routes](#routes) · [The signed root](#the-signed-root) ·
[The signed keyring](#the-signed-keyring) · [The reply certificate](#the-reply-certificate) ·
[Events](#events) · [Proof bundles, and who holds what](#proof-bundles-and-who-holds-what)

## Encodings

| What | Rule |
|---|---|
| Text | Every string that is hashed or signed is encoded as UTF-8. A string that holds a lone surrogate has no UTF-8 form, so it MUST be rejected wherever this spec says so, and MUST NOT be signed. |
| Binary values | **base64url without padding** (RFC 4648 §5). Encoders MUST NOT emit `=`. Decoders MUST reject any character outside `A–Z a–z 0–9 - _`, and a length that is 1 more than a multiple of 4. They MAY accept up to two trailing `=`, as both SDKs do. |
| Canonical encoding | Where this spec compares encoded values, it compares the text, so a value with two encodings matches only one of them. A stamp's `sig` MUST decode and re-encode to the identical text, or the chain does not parse (see [Stamp field rules](#stamp-field-rules)). |
| Canonical JSON | **JCS**, RFC 8785: object keys sorted by their UTF-16 code units, no whitespace, numbers in the ECMAScript shortest form, strings escaped as RFC 8785 §3.2.2.2 says ([Canonical bytes](#canonical-bytes)). JCS MUST fail on a lone surrogate, a non-finite number, or anything that is not plain JSON. Arrays keep their order. |
| Hash | SHA-256. `H(x)` below is SHA-256 of the bytes `x`. |
| Signatures | Ed25519 (RFC 8032), pure, with no pre-hash and no context. A signature is 64 bytes. Verifiers SHOULD apply RFC 8032 §5.1.7 in full, including the check that S is below the group order. |
| Integers | `ts` is an integer number of milliseconds since the Unix epoch. In signed bytes it is written in decimal, with no leading zeros, no `+` and no exponent. |

`b64url(x)` is the base64url text of `x`, and `utf8(s)` the UTF-8 bytes of `s`. `‖` is byte concatenation,
and `\n` is the single byte `0x0A`.

**Domain prefixes.** Each kind of signed message opens with its own prefix, so that no signature can be read as
another kind: roots `"paztport-root\n"`, keyrings `"paztport-keyring\n"`, reply certificates
`"paztport-reply-cert\n"`, session replies `"paztport-session-reply\n"`, responder events `"paztport-event\n"`,
and stamps `3|`.

## JSON

Paztport's own objects are JSON: stamps and chains, proofs, influence entries, content labels, the attestation,
keyrings, roots, reply certificates, session requests and replies, verdicts and refusals, events and their
envelopes, proof bundles and local rules. This section says how they are read and written, so that every
implementation accepts and refuses the same bytes. An object's **wire bytes** are the bytes it travels as, and a
**file** is one of the files under [Keys and files](#keys-and-files) or a client's local `rules.json`. Content
Paztport only hashes, such as a tool's arguments, is not one of its objects ([Hashed content](#hashed-content)).

### Reading

A reader reads an object from bytes in four steps, and refuses it at the first step that fails:

1. **Size.** The bytes are within their [limit](#limits), checked before anything is parsed.
2. **Parse.** The bytes are one JSON value under [the grammar](#the-grammar), nested no deeper than the depth
   limit.
3. **Canonical bytes.** Wire bytes are exactly the [canonical bytes](#canonical-bytes) of the value parsed. A
   file skips this step.
4. **Schema.** The value is the object its section defines: every member it requires is present and of its type,
   every integer is in the range the section gives, and there is no other member. A member whose value is a map by
   definition, such as a keyring's `services`, holds data, not schema: its names are checked by the rules its
   section gives, and its values by type.

Steps 1 to 3 are the same for every object, and step 4 is each object's own section. The parse takes a JSON value
of any type; the schema says which type each object is.

### The grammar

The bytes are JSON text (RFC 8259) within I-JSON (RFC 7493). Anything RFC 8259's grammar does not produce is
refused, such as a trailing comma, a comment, a single-quoted string, `NaN`, an escape it does not define (`\x`,
or `\u` with fewer than four hex digits) or a second value after the first. A reader also refuses:

- **Any encoding but strict UTF-8** (RFC 3629): an overlong form, a surrogate code point, a code point above
  U+10FFFF, a byte that starts no sequence, or a sequence cut short. A byte order mark is refused, and so is text
  in UTF-16 or UTF-32 (RFC 8259 §8.1).
- **A repeated member name** (RFC 7493 §2.3). Names are compared after unescaping, so `{"a":1,"\u0061":2}`
  repeats `a`.
- **A lone surrogate**, raw or escaped (RFC 7493 §2.1): `"\ud800"`, `"\udc00"` and `"\ud800x"` are refused. An
  escaped high surrogate followed by an escaped low one is one character: `"\ud83d\ude00"` is U+1F600.
- **A noncharacter**, raw or escaped (RFC 7493 §2.1): U+FDD0 to U+FDEF, and every code point whose last four hex
  digits are FFFE or FFFF, from U+FFFE and U+FFFF to U+10FFFE and U+10FFFF. So `"\uffff"` and `"\udbff\udfff"`
  are refused.
- **Any number that is not a protocol integer.** A **protocol integer** is `0`, or a digit 1–9 followed by digits,
  with at most 16 digits and a value of at most 2^53 − 1 (9007199254740991). So `-0`, `-1`, `01`, `+1`, `1.0`,
  `1e3` and `9007199254740992` are refused. A reader decides this from the number's text and refuses any other
  number before it builds a value, so no number is rounded, and a long one is refused at its seventeenth digit.

### Canonical bytes

An object's canonical bytes are its JCS text (RFC 8785), in UTF-8. Its wire bytes MUST be exactly those, so one
signed object has one token: whitespace, member order, an escape or an integer's spelling can't give the same object
a second form.

- There is no whitespace between tokens.
- Member names are sorted by their UTF-16 code units, compared as unsigned integers (RFC 8785 §3.2.3). U+1F600 is
  the code units D83D DE00, so it sorts before U+FB33, though its code point is greater.
- Strings are escaped exactly as RFC 8785 §3.2.2.2 says: `\"`, `\\`, `\b`, `\f`, `\n`, `\r` and `\t` for the
  characters they name, every other code point below U+0020 as `\u00xx` with lowercase hex digits, and every other
  code point as itself. So `\/`, `\u0041`, `\u00e9`, `\u001F`, `\u0008` and `\ud83d\ude00` are never canonical.
- An integer is its digits, as a protocol integer already is.
- Array elements keep their order.

### Limits

| Limit | Value |
|---|---|
| Wire bytes | At most 262 144 bytes (256 KiB), checked before parsing. |
| A base64url token | Its text is checked first, at most 349 526 characters (the unpadded length of 262 144 bytes), then its decoded length against the wire limit, so a reader never decodes more than the limit allows. |
| Depth | At most 32. An array or object is one level, and each array or object inside it is one more: `[]` is one level, and `[[]]` two. |
| Files | At most 1 048 576 bytes (1 MiB), with the same depth limit. |

A value at a limit is read, and one past it is refused.

### Files

A file is read by steps 1, 2 and 4 of [Reading](#reading), with the file limit: its members may come in any order,
with any JSON whitespace, and an escape RFC 8259 defines, such as `\/` or `\u0041`, reads as its character. A file
is written in one form, so that every implementation writes the same bytes:

- members in JCS order, and strings escaped as JCS escapes them;
- two-space indentation, one member or element per line, and `": "` between a name and its value;
- an empty object written `{}`, and an empty array `[]`;
- a newline at the end.

A keyring file, for example:

```json
{
  "notAfter": 1798761600000,
  "policy": "<policy public key>",
  "services": {
    "pi": "<public key>",
    "session": "<public key>"
  },
  "sig": "<b64url>"
}
```

### Writing

A writer writes canonical bytes, or a file in the form above, and MUST refuse to write anything a reader refuses: a
string holding a lone surrogate or a noncharacter, a number that is not a protocol integer, or a value nested
deeper than 32 levels or larger than its limit. It refuses the whole object, and never writes U+FFFD, `?` or an
escape in place of what it refuses.

### Hashed content

Content Paztport only hashes, such as a tool's arguments and result or a local tool's input, is not Paztport's to
define, and the [bindings](#bindings) that hash it as JCS belong to [the MCP profile](README.md#the-mcp-profile). Its
JCS is RFC 8785's in full: each number is read as the nearest IEEE 754 binary64 value and written in ECMAScript's
shortest form (RFC 8785 §3.2.2.3), so `-0` is written `0` and `1E30` is written `1e+30`. It refuses a lone
surrogate, which has no UTF-8 form, and a number that is not finite. It allows noncharacters, which belong to the
content. A binding over hashed content binds the value read, not its text: `9007199254740993` and
`9007199254740992` read as the same binary64 value and share one binding, though a tool that reads integers
exactly sees two.

`json.json` pins all of it: `wire` reads bytes as a base64url token, `file` reads them as a file, `fileFormat` holds
one file of each kind as it is written, and `jcs` (the MCP profile) holds hashed content as JCS writes it. Its
`about` says how to replay each section.

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
| `policy.key` | The policy private key, which signs the root, the keyring and reply certificates | yes |
| `keyring.json` | [The signed keyring](#the-signed-keyring), valid until its `notAfter` | no |
| `reply-cert.json` | [A reply certificate](#the-reply-certificate) for one service's key, written only when a policy tool is asked for one | no |
| `root.json` | [The signed root](#the-signed-root), valid until its `notAfter` | no |
| `proofs-<svc>.json` | [A proof bundle](#proof-bundles-and-who-holds-what) | no, but it reveals its own routes |
| `policy.pub` | The policy public key that a mesh's own services pin, written by the Java keygen | no |
| `boundary.key` | An egress's [boundary key](sessions-and-influence.md#blinded-influence): 32 bytes as base64url. The Java keygen writes it only when it does not exist, since a new key makes the entries sent under the old one unopenable, and refuses an existing one that is not 32 bytes. It belongs to one egress service and its replicas, and MUST NOT be shared with another service | yes |
| `<side>-policy.pub` | A pinned policy public key (`server-policy.pub`, `client-policy.pub`) | no |

**Expiry.** The policy key stays offline, so a root or keyring it once signed can't be withdrawn, only left to
lapse. Each therefore carries `notAfter`, the time after which the policy owner no longer vouches for it, and its
signature covers that value. `notAfter` follows the reply certificate's rule: an integer number of milliseconds
since the Unix epoch, in [0, 2^53 − 1], checked by value and written as plain decimal digits. A reader MUST
refuse, as malformed, a keyring or root whose own `notAfter` is missing or is not such an integer. A root or
keyring is valid at time `t` when `t <= notAfter`; verifying its signature says nothing about time, so whoever
relies on it MUST check both.

## Stamps

A stamp is a JSON object. Field order in the JSON is not significant; encoders SHOULD write the fields in the
order shown.

### Fields and signed bytes

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

These hold for every stamp. A signer MUST NOT sign a stamp that breaks them, and a verifier MUST reject one
that does, with the code in brackets.

- The chain is a non-empty JSON array of objects (`CHAIN_MISSING`).
- `v` is exactly `3` (`CHAIN_MISSING`).
- `ts` is a JSON number that is an integer with an absolute value of at most 2^53 − 1 (`CHAIN_MISSING`), so
  every implementation reads and prints it the same way. It is checked by value: `1.0` and `1e3` are the
  integers 1 and 1000.
- Every string field (`svc`, `inst`, `rid`, `sess`, `rcv`, `bind`, `infl`, `prev`, `sig`) is a JSON
  string (`CHAIN_MISSING`) with no lone surrogate (`CHAIN_MISSING`).
- `sig` decodes as base64url and re-encodes to the identical text (`CHAIN_MISSING`).
- No signed field holds `|` (`BAD_SIGNATURE`). The fields are joined with `|`, so a field holding it would let
  two different stamps share signed bytes.
- A stamp without `rcv` does not parse (`CHAIN_MISSING`).

Unknown fields are ignored; they are not signed.

## Chains

A chain is an array of stamps, **origin first**.

- **Origin.** The first stamp has `prev = ""`. Its `svc` MUST be one of the verifier's allowed origins: only an
  entry point holds an origin key, so an inner service can't start a chain.
- **Links.** Stamp *i* (for *i* ≥ 1) has `prev` equal to stamp *i − 1*'s `sig`. Because each signature covers
  `prev`, removing, reordering or inserting a stamp breaks a signature or a link.
- **Shared values.** Every stamp carries the origin's `rid`. Every stamp carries the session's `sess`.
- **Receivers.** Stamp *i*'s `rcv` MUST equal stamp *i + 1*'s `svc`, and the last stamp's `rcv` MUST equal
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
| MCP tool call ([MCP profile](README.md#the-mcp-profile)) | `session`, `pi` | `pi`, then `mcp:<server>.<tool>`, where `<server>` is the server id and `<tool>` the tool name. |
| MCP response ([MCP profile](README.md#the-mcp-profile)) | `mcp-entry`, `github-tools` | `github-tools`, then the calling client's `svc` (`pi`): the response chain ends at whoever made the call. |
| Local step ([MCP profile](README.md#the-mcp-profile)) | `session`, `pi` (with `sess = ""`) | `pi`, then `local:<tool>`. |
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
| HTTP | An HTTP hop's request | `utf8(METHOD) ‖ \n ‖ utf8(PATH) ‖ \n ‖ BODY`, the body as raw bytes. There is no prefix. `PATH` is the request target as sent: the raw path, plus `?` and the raw query when the query is non-empty, with nothing decoded, so `/pay?` binds as `/pay`. With no query the bytes are `METHOD \n PATH \n BODY` alone. |
| HTTP result | An HTTP response's `resultHash` | `utf8("http-response\n" ‖ status ‖ "\n") ‖ BODY`, with `status` the response's status code in decimal and the body as raw bytes, so a response can't pass under another status. |
| Prompt | A run's origin stamp | `utf8("prompt\n" ‖ text)` |
| `tools/call` ([MCP profile](README.md#the-mcp-profile)) | An MCP call's stamp | `utf8("tools/call\n" ‖ tool ‖ "\n" ‖ callId ‖ "\n" ‖ JCS(arguments))`. Absent or `null` arguments hash as `{}`. |
| Result ([MCP profile](README.md#the-mcp-profile)) | An MCP result's `resultHash` | `utf8("result\n" ‖ JCS(result))`, with the result's top-level `_meta` key removed first. |
| Response | The last stamp of a response chain | `utf8(resultHash ‖ "\n" ‖ toolCallId ‖ "\n" ‖ JCS(labels))`. There is no prefix: it starts with the result hash. |
| Local tool ([MCP profile](README.md#the-mcp-profile)) | A local step's stamp | `utf8("tool\n" ‖ toolName ‖ "\n" ‖ JCS({ "input": input, "resolved": decision }))`. An absent or `null` input, or decision, hashes as `{}`. |

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
- In an MCP response chain (the MCP profile) the first stamp, by the server's entry service, binds the call it
  took (the `tools/call` binding), and the last binds the response.
- The local tool `decision` (the MCP profile) is the gate's signed decision on the call:
  `{ "callId": ..., "resolved": { "paths": [{ "need", "at" }], "programs": [{ "name", "via" }], "parse": "ok" | "error", "readOnly": bool }, "verdict": ..., "routeAllowed": bool, "rulesHash": string | null }`.
  So the call id, what the gate resolved, its verdict, whether the route is listed and which rules decided
  are all covered by the stamp.

`v3.json` pins the prompt, `tools/call`, result and response bindings in `bindPrompt`, `bindMcpCall`, `bindResult`
and `bindResponse`, and a local-tool binding through the `local step ok` case. `http-v3.json` pins the HTTP
binding with and without a query in `requestBinding`, and the HTTP result hash in `resultHash`.

## Carrying a chain

### MCP (v3)

This section belongs to [the MCP profile](README.md#the-mcp-profile).

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
handshake is the JSON-RPC method `paztport/session`
([sessions-and-influence.md](sessions-and-influence.md#the-handshake)).

### HTTP (v3)

A request carries Paztport in three headers, each the base64url of UTF-8 JSON, and names its session in a
fourth, which is plain text:

| Header | Value |
|---|---|
| `X-Path-Chain` | The chain, as a JSON array of v3 stamps, origin first. The last stamp's `rcv` is the receiving service, and its `bind` the [HTTP binding](#bindings) of the request sent. |
| `X-Path-Proof` | The [proof object](#proof-object) for the full route, receiving service included. |
| `X-Path-Influence` | The influence entries the request was made under, as a JSON array ([sessions-and-influence.md](sessions-and-influence.md#entries)). An absent header means `[]`. The last stamp's `infl` commits to them. |
| `X-Path-Session` | The [session id](sessions-and-influence.md#the-session-id), as plain text, on a call made in a session opened by [the handshake over HTTP](sessions-and-influence.md#over-http). Inside a mesh, which has no handshake, it is absent. An absent header means no session; one that names no live session opened by the peer is refused `SESSION_UNKNOWN`. |

A refusal carries no Paztport header. Its body is `{"reason":"<code>"}` and nothing else, so it never names the
suspect to the caller ([verification.md](verification.md#modes-and-refusals)).

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
would let anyone who guessed a policy confirm the guess. It labels the tree, not the signature, so a
[renewed root](#the-signed-root) keeps it. The `rootId`s pinned in
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
- A call's route ends at its receiver: `gateway/orders/payment`, or
  (the MCP profile) `session/pi/mcp:github.create_pull_request`.
- An MCP response's route (the MCP profile) is the server's own hops, `mcp-entry/github-tools`. Its receiver, the
  calling client, is not on it: the server's policy can't list every client.
- An HTTP response's route is the request's own, `gateway/orders/payment`, proven by the proof the caller sent.
  Its receiver, the caller, is already on it.
- A local step's route is `session/pi/local:<tool>`. Local steps belong to
  [the MCP profile](README.md#the-mcp-profile).
- A client's local folder rules (the MCP profile again) are pinned as one more route,
  `session/pi/rules:<rulesHash>`, where `rulesHash = b64url(H(utf8("local-rules\n" ‖ JCS(rules))))` and `rules` is
  the parsed rule set `{ "v": 1, "folders": [...], "programs": [...] }` (its format is in the
  [pi-extension README](../../poc-demos/agents-mcp/pi-extension/README.md#local-tool-gating)). A client MUST NOT
  apply rules that the signed root does not cover.

## The signed root

`root.json`, the value verifiers pin:

```json
{ "rootId": "...", "root": "<b64url, 32 bytes>", "sig": "<b64url>", "notAfter": <integer> }
```

`sig` is the policy key's Ed25519 signature over:

```
utf8( "paztport-root\n" ‖ JCS({ "notAfter": notAfter, "root": root, "rootId": rootId }) )
```

with `root` as its base64url text. When it is valid is set out under [Expiry](#keys-and-files). A widened policy
can't be swapped in without the policy private key. A verifier MUST check the signature against the pinned policy
key before using the root. Any other field is ignored and not signed.

The policy owner MUST sign a root only over a tree whose routes it currently allows; `notAfter` is when it stops
vouching for them. Renewing a root signs the same `root` text under the same `rootId` again, with a new
`notAfter` (the policy tools use the run's time plus the lifetime, which may be earlier than the old one), so
proof bundles stay valid and holders can pick up the renewed root one at a time. A renewed root keeps its
`rootId`, and two validly signed roots for one tree differ only in `notAfter`. Narrowing a policy is not
renewing: it needs a new tree, a new `rootId` and new proof bundles.

`v3.json` pins the signed bytes and signatures in `root`, all for the client policy under the `client-policy`
pin: a signed root, at its `notAfter` and 1 ms after, the largest `notAfter` and a renewed root, which verify; a
tampered `notAfter`, a `notAfter` added to a signature made over `utf8(rootId ‖ "|" ‖ root)`, a `notAfter` that is
not an integer, a root signed by another policy key and a keyring signature offered as a root signature, which
fail; a root with no `notAfter` and one of 2^53, which a reader refuses, the first though its signature is the
policy key's over `utf8(rootId ‖ "|" ‖ root)`; and one written `1798761600000.0`, which a reader reads by value,
as the integer its signature is over.

## The signed keyring

`keyring.json` names the policy key and every service's public key, and is signed by the policy key:

```json
{ "services": { "<svc>": "<public key>", ... }, "policy": "<policy public key>", "sig": "<b64url>", "notAfter": <integer> }
```

`sig` is the policy key's Ed25519 signature over:

```
utf8( "paztport-keyring\n" ‖ JCS({ "notAfter": notAfter, "policy": policy, "services": services }) )
```

When it is valid is set out under [Expiry](#keys-and-files).

A keyring verifies under a pinned policy key only when its `policy` equals that key and `sig` verifies under it.
The prefix keeps a keyring signature from being read as any other message the policy key signs. Without the
signature, a session's keyring would be the client's own claim, and anyone who could open a session could name
their own keys. The policy owner MUST sign a keyring only after checking that each listed key is that service's
current key; `notAfter` is when it stops vouching for them. A retired key needs a new keyring, not a renewed one.

`v3.json` pins the signed bytes and signatures in `keyring`: a signed keyring, at its `notAfter` and 1 ms after,
and the largest `notAfter`, which verify; a tampered service key, a tampered `notAfter`, a `notAfter` added to a
signature made over `utf8("paztport-keyring\n" ‖ JCS({ "policy": policy, "services": services }))`, a `notAfter`
that is not an integer and a root signature offered as a keyring signature, which fail; a keyring with no
`notAfter` and one of 2^53, which a reader refuses, the first though its signature is the policy key's over those
same bytes; and one written `1798761600000.0`, which a reader reads by value.

Both SDKs' keygens write signed keyrings, by default valid for seven days, and both policy tools sign roots, by
default valid for seven days. The policy tools also re-sign the keyring on every rebuild and renew.

## The reply certificate

`reply-cert.json` is the policy key's statement that `key` is service `svc`'s key until `notAfter`. It lets that
key sign what the policy key would otherwise have to sign online, a
[session reply](sessions-and-influence.md#the-reply), while the policy key stays offline:

```json
{ "policy": "<policy public key>", "svc": "<service>", "key": "<that service's public key>", "notAfter": <integer>, "sig": "<b64url>" }
```

`sig` is the policy key's Ed25519 signature over:

```
utf8( "paztport-reply-cert\n" ‖ JCS({ "key": key, "notAfter": notAfter, "policy": policy, "svc": svc }) )
```

`notAfter` is an integer number of milliseconds since the Unix epoch, in [0, 2^53 − 1], and is written as plain
decimal digits in the signed bytes. A writer MUST write it in the file as plain decimal digits too. A reader
MUST refuse a certificate that is not a JSON object, whose `policy`, `svc`, `key` or `sig` is missing or not a
string, or whose `notAfter` is missing, not a JSON number, not an integer, negative, or greater than 2^53 − 1.
`notAfter` is checked by value, as a stamp's `ts` is: `1.0` and `1e3` are the integers 1 and 1000. The
signature covers the plain digits of that value. Any other field is ignored and not signed.

A certificate verifies under a pinned policy key only when its `policy` equals that key and `sig` verifies
under it. It is valid at time `t`, in milliseconds since the Unix epoch, when `t <= notAfter`. Verifying it says
nothing about time, so whoever relies on a certificate MUST check both. The prefix keeps a certificate signature
from being read as any other message the policy key signs.

It expires because the policy key is offline, so nothing it signed can be withdrawn, only left to lapse. A
keyring lapses too, at its `notAfter`, but it vouches for every service's key at once, for as long as the policy
owner renews it. A certificate vouches for one key's session replies alone, and is short-lived, so retiring that
key means not issuing it another certificate: once its last certificate has expired, no session reply it signs
is accepted, even while a keyring that lists it is still valid. The certificate's lifetime is that key's
revocation delay, so deployments SHOULD keep it short, days rather than months. Both policy tools default to 7
days.

The policy owner MUST issue a certificate only after checking that `key` is `svc`'s key in its current keyring,
signed by the same policy key, since that is what the certificate vouches for. Both policy tools check it
against the keyring they are given, and refuse, writing nothing, a keyring that does not verify under the
policy key or has no key for the service; that the keyring given is the current one is the policy owner's to
ensure.
The Java policy tool issues a certificate when `PAZTPORT_REPLY_CERT_SVC` names the service, valid for
`PAZTPORT_REPLY_CERT_DAYS` days. The TypeScript one takes
`--reply-cert-svc <name> [--reply-cert-days 7]`, beside the `--keyring <keyring.json>` it always takes. Both
print only the file, the service and `notAfter`.

`v3.json` pins the signed bytes and signatures in `replyCert`: a certificate for `mcp-entry` under the
`server-policy` pin, and, against the same pin, one with a tampered `notAfter`, one signed by `client-policy`,
and one that names `client-policy`, all of which fail, one with an extra field, which is ignored, and one with
the largest `notAfter`.

## Events

A verifying service MAY send its responder an event for each request whose live verification does not give
`OK`, in audit mode as well as enforce mode, with the result's reason and suspect. The responder may act on it,
for example by isolating the named instance ([verification.md](verification.md#guidance-for-a-responder)). Anyone
who can reach the responder can send it a body, so an event counts only when a service the responder allows has
signed it. [verification.md](verification.md#receiving-an-event) says how the responder checks one.

### The envelope

```json
{ "signer": "<service>", "payload": "<b64url>", "sig": "<b64url>" }
```

| Field | Type | Meaning |
|---|---|---|
| `signer` | string | The service that signed the event. The responder looks its key up by this name. |
| `payload` | string | `b64url(utf8(event))`: [the event](#the-event), as the JSON text the signer wrote. |
| `sig` | string | `b64url` of the Ed25519 signature, by `signer`'s key, over the signed bytes. |

The signed bytes are:

```
utf8( "paztport-event\n" ‖ payload )
```

with `payload` the base64url text exactly as sent. The signature covers that text, not a JSON form of the event,
so the responder verifies the bytes it was given and never canonicalises JSON. The event's JSON therefore need not
be JCS: a signer SHOULD write the fields in the order shown below, with no whitespace, and a responder MUST read
the event from the payload it verified, never from a form written again. `signer` is not signed, but a name other
than the signer's own looks up another key, and the signature fails. The body is exactly one JSON object, with
nothing but JSON whitespace (RFC 8259 `ws`) before or after it and no byte order mark, and it has exactly these
three members, each a string. The prefix keeps an event signature from being read as a stamp, or as anything else
the same key signs ([Encodings](#encodings)).

`events.json` pins the signed bytes and signatures in `envelope`: an attributed refusal, an audit event that
names no one, and one with non-ASCII text.

### The event

```json
{ "reason": "...", "suspectSvc": "...", "suspectInst": "...", "rid": "...", "audit": false, "ts": 0, "eventId": "..." }
```

| Field | Type | Meaning |
|---|---|---|
| `reason` | string | The [reason code](verification.md#reason-codes) the signer's verifier gave the request. |
| `suspectSvc`, `suspectInst` | string | The suspect that result names ([attribution](verification.md#receivers-the-peer-and-attribution)), or `""` for none. |
| `rid` | string | The `rid` of the refused chain's origin stamp, as received, or `""` when no chain parsed. It is the sender's text, not verified, so it is for matching the event with the signer's own logs only. |
| `audit` | boolean | `true` when the signer runs in audit mode, so it reported the failure but did not refuse the request. |
| `ts` | integer | When the event was signed, in ms since the Unix epoch. |
| `eventId` | string | This event's id. It MUST NOT be `""`; any other string is an id, one of only spaces included. A signer MUST NOT reuse one. It SHOULD be a random UUID (RFC 9562, version 4): one responder remembers the ids of every signer together, so a guessable id would let one signer spend another's. |

The payload is the UTF-8 encoding (RFC 3629) of exactly one JSON object, with nothing but JSON whitespace before
or after it and no byte order mark. The
object has exactly these seven members, and each is of the type shown, so no member is `null`: nothing is
converted from another type or filled in when absent, so that every implementation reads the same event from the
same bytes. `ts` is a JSON number that is an integer with an absolute value of at most 2^53 − 1, checked by value
as a stamp's `ts` is ([Stamp field rules](#stamp-field-rules)): `1767225600000.0` is the integer 1767225600000,
and `1767225600000.5` is not an integer.

**Attributable events.** A responder MUST NOT act against a suspect on an event that is not attributable. An
event is attributable when all of these hold:

- `audit` is `false`. An audit-mode verifier is measuring its rules, not refusing.
- `suspectSvc` and `suspectInst` are both non-empty. A result that names no one does so by design: the name would
  be unsigned, or the genuine stamp would belong to another request, so acting on it would let a forged chain
  point at anyone.
- `reason` is one of the codes that report what the sender did: `CHAIN_MISSING`, `BAD_ORIGIN`, `BAD_SIGNATURE`,
  `BROKEN_LINK`, `EXPIRED`, `RID_MISMATCH`, `BINDING_MISMATCH`, `REPLAY`, `PATH_NOT_ALLOWED`, `SESSION_UNKNOWN`,
  `CLIENT_PATH_NOT_ALLOWED`, `INFLUENCE_MISMATCH` and `PEER_MISMATCH`.

No other reason is attributable. `POLICY_EXPIRED` is the verifier's own policy running out, which every honest
caller meets. `INFLUENCE_DENIED` and `UNSAFE_SESSION` refuse a sound chain because of what shaped it: an honest
component misled by poisoned input gets them. The client-local and offline-only codes are never a live verdict
on a request, and `OK` refuses nothing.

### Carrying an event

Over HTTP a service sends an event as a `POST` to its responder's `/events` path, with the envelope as a UTF-8 JSON
body and `Content-Type: application/json`. An event MUST NOT change the verdict it reports: a responder that is
down, slow or refuses the event leaves the refusal as it was. A sender that waits for the responder before
answering the refusal SHOULD bound that wait, so that a slow responder cannot hold refusals up (the Java SDK
waits at most `paztport.event-timeout-ms`; see the [Java SDK README](../java/README.md#paztport-spring)). The
responder answers `200` when it accepts an event and `403` when it refuses one, with the same body for every
refusal, so the answer tells a sender nothing about the allowed signers, the keyring or the window.

## Proof bundles, and who holds what

`proofs-<svc>.json` holds the proofs a service attaches to the requests it sends:

```json
{ "service": "<svc>", "rootId": "...", "proofs": { "<route>": { /* proof object */ }, ... } }
```

A route's proof is held by its caller, the node before the last, since that is the hop that sends the request
the proof travels with.

| Party | Holds | Never holds |
|---|---|---|
| Policy owner | The policy private key, offline. It signs the root, the keyring and reply certificates. | |
| Each service | Its own private key, and its own proof bundle. An entry service that answers session handshakes in the [entry-key form](sessions-and-influence.md#the-reply) also holds a current reply certificate for its key, and signs the replies with that key. | Other services' keys, other routes' salts. |
| Each verifier | The pinned policy public key, the signed root and the signed keyring. | The tree, the route list or any salt but those in the proofs it is shown. |
| The other side of a session | The peer side's policy key, pinned in advance, and the root and keyring it sends in the handshake. A client also knows the server's entry service by name, from its own configuration, to check an entry-key reply. | Its map. |

A server that answers in the entry-key form needs its policy private key only offline, to sign its root, keyring
and reply certificates; one that answers in the policy-key form keeps it online to sign each reply. In the agents
demo neither side keeps its policy private key: the client's is deleted once it has signed the client root and
keyring, and the server's once it has signed the server root, keyring and a 30-day reply certificate for
`mcp-entry`'s key, since the demo's MCP server answers in the entry-key form.

The policy owner renews its root and keyring on a schedule, well before their `notAfter`, offline, where the
policy private key is kept. Renewing keeps the tree, so the proof bundles stay valid, and each holder can pick up
the renewed root and keyring on its own, one at a time. A rebuild is different: it changes the routes, so it is a
new tree with a new `rootId` and new proof bundles, and every holder of the root or of proofs must reload them
together, since a proof from one tree does not prove against the other's root. Both policy tools renew
(`--renew`, or `PAZTPORT_RENEW=true` for the Java one) and rebuild (the default), re-signing the keyring either
way; they check that the keyring and, renewing, the root were signed by the policy key before, and refuse,
writing nothing, otherwise. That the keyring's keys are still the services' current keys, and that the tree's
routes are still allowed, is the policy owner's to ensure.
