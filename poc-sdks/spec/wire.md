# Wire format

This file defines the bytes: encodings, how JSON is read and written, keys, stamps, chains, bindings, the Merkle
tree, the signed root, the signed keyring, the reply certificate, events, the proof bundles and operations.
[verification.md](verification.md) says how a receiver checks them, and
[sessions-and-influence.md](sessions-and-influence.md) covers the handshake and influence.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [Encodings](#encodings) · [JSON](#json) · [Keys and files](#keys-and-files) · [Stamps](#stamps) ·
[Chains](#chains) · [Bindings](#bindings) · [Carrying a chain](#carrying-a-chain) ·
[The Merkle tree](#the-merkle-tree) · [Routes](#routes) · [Operations](#operations) ·
[The signed root](#the-signed-root) · [The signed keyring](#the-signed-keyring) · [The reply certificate](#the-reply-certificate) ·
[Events](#events) · [Proof bundles, and who holds what](#proof-bundles-and-who-holds-what)

## Encodings

| What | Rule |
|---|---|
| Text | Every string that is hashed or signed is encoded as UTF-8. A string that holds a lone surrogate has no UTF-8 form, so it MUST be rejected wherever this spec says so, and MUST NOT be signed. |
| Binary values | **base64url without padding** (RFC 4648 §5). Encoders MUST NOT emit `=`. Decoders MUST accept only the canonical encoding of RFC 4648 §3.5, and so MUST reject `=`, any character outside `A–Z a–z 0–9 - _` (whitespace included), a length that is 1 more than a multiple of 4, and non-zero unused bits in the last character. `json.json`'s `base64url` section pins each case. |
| Canonical encoding | Where this spec compares encoded values, it compares the text, so a value with two encodings matches only one of them. This covers every base64url value that is decoded (a token, a `sig`, a `nonce`, a key, a salt, a root, a Merkle sibling, an event payload), not only `sig`; a value that is only compared as text, such as an influence entry's `h` and `cid` or a stamp's `bind` and `infl`, is not decoded and not checked. A stamp whose `sig` is not canonical does not parse (see [Stamp field rules](#stamp-field-rules)). |
| Canonical JSON | **JCS**, RFC 8785: object keys sorted by their UTF-16 code units, no whitespace, numbers in the ECMAScript shortest form, strings escaped as RFC 8785 §3.2.2.2 says ([Canonical bytes](#canonical-bytes)). JCS MUST fail on a lone surrogate, a non-finite number, or anything that is not plain JSON. Arrays keep their order. |
| Hash | SHA-256. `H(x)` below is SHA-256 of the bytes `x`. |
| Signatures | Ed25519 (RFC 8032), pure, with no pre-hash and no context. A signature is 64 bytes. Verifiers SHOULD apply RFC 8032 §5.1.7 in full, including the check that S is below the group order. |
| Integers | `ts` is a number of milliseconds since the Unix epoch, a [protocol integer](#the-grammar): an integer in [0, 2^53 − 1], decided from its text. In signed bytes it is written in decimal, with no leading zeros, no `+` and no exponent. |

`b64url(x)` is the base64url text of `x`, and `utf8(s)` the UTF-8 bytes of `s`. `‖` is byte concatenation,
and `\n` is the single byte `0x0A`.

**Domain prefixes.** Each kind of signed message opens with its own prefix, so that no signature can be read as
another kind: roots `"paztport-root\n"`, keyrings `"paztport-keyring\n"`, reply certificates
`"paztport-reply-cert\n"`, session replies `"paztport-session-reply\n"`, responder events `"paztport-event\n"`,
and stamps `3|`.

## JSON

Paztport's own objects are JSON: stamps and chains, proofs, influence entries, content labels, the attestation,
keyrings, roots, reply certificates, session requests and replies, verdicts and refusals, events and their
envelopes, proof bundles, local rules, a local tool's decision and a boundary opening. This section says how they
are read and written, so that every implementation accepts and refuses the same bytes. An object's **wire bytes**
are the bytes it travels as, and a **file** is one of the files under [Keys and files](#keys-and-files) or a
client's local `rules.json`. Content Paztport only hashes, such as a tool's arguments, is not one of its objects
([Hashed content](#hashed-content)).

Every Paztport object is read and written by these rules, and none passes through a transport's JSON parser: a
transport carries an object's wire bytes, or their token, and the object is read from those. Where this spec lists
an object's members, in a table, an example or a sentence, it says which members the object has, not their order:
its bytes hold them in JCS order ([Canonical bytes](#canonical-bytes)).

`json.json` pins all of it: `wire` reads bytes as a base64url token, `file` reads them as a file, `fileFormat` holds
one file of each kind as it is written, and `jcs` (the MCP profile) holds hashed content as JCS writes it. Two more
sections pin neighbours of JSON: `base64url` the [binary values](#encodings) a token is decoded from, and `bindings`
the [bindings](#bindings) that refuse a lone surrogate. Its `about` says how to replay each section.

### Carrying an object

An object travels as its wire bytes, or as its **token**, the base64url of its wire bytes:

- **HTTP headers.** A chain, a proof, influence entries and a response's attestation each travel as a token, one
  header each ([HTTP (v3)](#http-v3)).
- **HTTP bodies.** A session request, its reply and a handshake error `{"error"}`
  ([sessions-and-influence.md](sessions-and-influence.md#over-http)), a refusal `{"reason"}`, an event's envelope
  ([Events](#events)) and, in the PSP demo, a boundary opening travel as their wire bytes, the whole body.
- **MCP** ([the MCP profile](README.md#the-mcp-profile)). Each value under `_meta` but `paztport/callId` is a
  token ([MCP (v3)](#mcp-v3)), and so are the `request` of `paztport/session`'s params and the `reply` of its
  result ([sessions-and-influence.md](sessions-and-influence.md#the-handshake)). The JSON-RPC message around them is
  MCP's own, read by its JSON parser.

A record keeps each object as its token, as it was sent or received
([Recorded handshakes](sessions-and-influence.md#recorded-handshakes)).

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

Each object's reader gives one answer for an object it refuses, whichever step refuses it. An object inside
another, such as a stamp in a chain or a root in a session request, is read as part of its parent, and refused with
the parent's answer.

| Object | Read by | Refusal |
|---|---|---|
| An event's envelope | The responder ([Receiving an event](verification.md#receiving-an-event)) | `MALFORMED_ENVELOPE` |
| An event | The responder, from the envelope's `payload` ([Receiving an event](verification.md#receiving-an-event)) | `MALFORMED_EVENT`; an event whose only fault is an absent or `null` `eventId` is `NO_EVENT_ID` |
| A chain | A verifier, live or offline ([check 1](verification.md#the-live-order)), from an HTTP header or MCP `_meta` | `CHAIN_MISSING` |
| A proof | A verifier, live or offline ([check 11](verification.md#the-live-order)) | None: no proof, so the route is not proven (`PATH_NOT_ALLOWED`) |
| An influence list | A verifier, live or offline ([check 9](verification.md#the-live-order)) | `INFLUENCE_MISMATCH` |
| A response attestation | A client, from an HTTP header or MCP `_meta` ([HTTP](verification.md#http-requests-and-responses), [MCP](verification.md#the-mcp-server-and-client)) | `CHAIN_MISSING` |
| A verdict (MCP profile) | A client, from MCP `_meta` ([the verdict rule](verification.md#the-mcp-server-and-client)) | `UNKNOWN`, a refusal |
| A recorded verdict (MCP profile) | A verifier of a recorded response | No refusal: the result is judged as a response |
| A local-tool decision (MCP profile) | A verifier of a recorded local step ([step 1](verification.md#offline-verification)) | `BINDING_MISMATCH` |
| A session request | A server, over MCP or HTTP ([sessions-and-influence.md](sessions-and-influence.md#the-request)) | Invalid params: JSON-RPC `-32602`; over HTTP `400 {"error":"INVALID_PARAMS"}` |
| `paztport/session` params (MCP profile) | A server ([the handshake](sessions-and-influence.md#the-handshake)) | Invalid params: JSON-RPC `-32602` |
| A session reply | A client, live ([its check](sessions-and-influence.md#the-clients-check-of-the-reply)); a verifier of a [recorded handshake](sessions-and-influence.md#recorded-handshakes) | `MALFORMED_REPLY`; not attested |
| A `paztport/session` result (MCP profile) | A client ([the handshake](sessions-and-influence.md#the-handshake)) | `MALFORMED_REPLY` |
| A refusal `{"reason"}` | An egress reading its partner's `403` to a call ([sessions-and-influence.md](sessions-and-influence.md#over-http)) | None: the refusal gives no reason |
| A handshake error `{"error"}` | No one: a client takes any answer but a `200` as a failed handshake ([sessions-and-influence.md](sessions-and-influence.md#over-http)) | None |
| A boundary opening | A checker ([Opening an entry](sessions-and-influence.md#blinded-influence)) | Does not open; the PSP demo's check answers `400 {"reason":"MALFORMED_OPENING"}` for bytes that do not read or are not one JSON object |
| A keyring, root, reply certificate, proof bundle or local rules, as a [file](#files) | A service or client at startup, a policy tool | Malformed, and each reader names the file: a service or client does not start, and a policy tool writes nothing and exits as for any malformed input |

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
| A base64url token | Its text is checked first, at most 349 526 characters (the unpadded length of 262 144 bytes), then its decoded length against the wire limit, so a reader never decodes more than the limit allows. Text that does not decode is refused at the parse step. |
| Depth | At most 32. An array or object is one level, and each array or object inside it is one more: `[]` is one level, and `[[]]` two. |
| Files | At most 1 048 576 bytes (1 MiB), with the same depth limit. |

A value at a limit is read, and one past it is refused.

### Files

A file is read by steps 1, 2 and 4 of [Reading](#reading), with the file limit: its members may come in any order,
with any JSON whitespace, and an escape RFC 8259 defines, such as `\/` or `\u0041`, reads as its character. A file
is written in one form, so that every implementation writes the same bytes:

- members in JCS order, and strings escaped as JCS escapes them;
- one member or element per line, indented two spaces per level of nesting, and `": "` between a name and its value;
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

Every implementation writes each object as its JCS bytes and each file in the file format above. A writer MUST
refuse to write anything a reader refuses: a string holding a lone surrogate or a noncharacter, a number that is not
a protocol integer, or a value nested deeper than 32 levels or larger than its limit. It refuses the whole object,
and never writes U+FFFD, `?` or an escape in place of what it refuses.

### Hashed content

Content Paztport only hashes, such as a tool's arguments and result or a local tool's input, is not Paztport's to
define, and the [bindings](#bindings) that hash it as JCS belong to [the MCP profile](README.md#the-mcp-profile). It
travels in the transport's own JSON, read by the transport's parser, and is hashed as the value that parser read. Its
JCS is RFC 8785's in full: each number is read as the nearest IEEE 754 binary64 value and written in ECMAScript's
shortest form (RFC 8785 §3.2.2.3), so `-0` is written `0` and `1E30` is written `1e+30`. It refuses what the
[Encodings](#encodings) table's Canonical JSON row says JCS fails on, and allows noncharacters, which belong to the
content. A binding over hashed content binds the value read, not its text: `9007199254740993` and
`9007199254740992` read as the same binary64 value and share one binding, though a tool that reads integers
exactly sees two.

## Keys and files

| Key | Encoding |
|---|---|
| Public key | The X.509 SubjectPublicKeyInfo DER of the Ed25519 key (44 bytes, starting `302a300506032b6570032100`), as base64url. |
| Private key | The PKCS#8 DER of the Ed25519 key (48 bytes: `302e020100300506032b657004220420` ‖ the 32-byte seed), as base64url. |

The policy tools write these files, except the pins of the other side of a session, which whoever onboards that
side writes (in the agents demo, its setup script). A key file holds one value, and readers trim surrounding
whitespace: the space, horizontal tab, line feed and carriage return of JSON (RFC 8259), and no other character. A key
surrounded by any other character, a no-break space or a byte order mark included, is not that key and is refused. Each
JSON file (`keyring.json`, `reply-cert.json`, `root.json`, `proofs-<svc>.json` and `ops-<svc>.json`) is written in the [file format](#files),
and read as [Files](#files) says: strictly, in any member order and spacing.

| File | Holds | Secret |
|---|---|---|
| `<svc>.key` | The service's private key | yes |
| `policy.key` | The policy private key, which signs the root, the keyring and reply certificates | yes |
| `keyring.json` | [The signed keyring](#the-signed-keyring), valid until its `notAfter` | no |
| `reply-cert.json` | [A reply certificate](#the-reply-certificate) for one service's key, written only when a policy tool is asked for one | no |
| `root.json` | [The signed root](#the-signed-root), valid until its `notAfter` | no |
| `proofs-<svc>.json` | [A proof bundle](#proof-bundles-and-who-holds-what) | no, but it reveals its own routes |
| `ops-<svc>.json` | [An operation table](#operations), copied by the policy tool from beside `paths.yaml` | no |
| `policy.pub` | The policy public key that a mesh's own services pin, written by the Java keygen | no |
| `boundary.key` | An egress's [boundary key](sessions-and-influence.md#blinded-influence): 32 bytes as base64url. The Java keygen writes it only when it does not exist, since a new key makes the entries sent under the old one unopenable, and refuses an existing one that is not 32 bytes. It belongs to one egress service and its replicas, and MUST NOT be shared with another service | yes |
| `<side>-policy.pub` | A pinned policy public key (`server-policy.pub`, `client-policy.pub`) | no |

**Expiry.** The policy key stays offline, so a root or keyring it once signed can't be withdrawn, only left to
lapse. Each therefore carries `notAfter`, the time after which the policy owner no longer vouches for it, and its
signature covers that value. `notAfter` follows the reply certificate's rule: an integer number of milliseconds
since the Unix epoch, a [protocol integer](#the-grammar) by its text, so `1798761600000.0` is refused though its
value is an integer. A reader MUST refuse, as malformed, a keyring or root whose own `notAfter` is missing or is
not such an integer. A root or keyring is valid at time `t` when `t <= notAfter`; verifying its signature says
nothing about time, so whoever relies on it MUST check both.

## Stamps

A stamp is a JSON object. It travels inside its chain's JCS bytes ([Chains](#chains)), so its members are in JCS
order, whatever order they are shown in here.

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
| `rid` | string | The request id, minted at the origin and carried unchanged by every stamp. An origin MUST NOT reuse a `rid`: the [HTTP nonce key](verification.md#freshness-and-replay) names a request tree by it, so two trees with one `rid` would spend each other's keys. It SHOULD carry at least 122 random bits from a cryptographic random source, as a random UUID (RFC 9562, version 4) does, so that an origin's replicas need no coordination. |
| `ts` | integer | When this stamp was signed, in ms since the Unix epoch: a protocol integer. |
| `sess` | string | The session id ([sessions-and-influence.md](sessions-and-influence.md#the-session-id)), or `""` for a chain with no session: one that never leaves one process, such as a local step, or one inside a single HTTP mesh. |
| `rcv` | string | The receiver this stamp was signed for: the next stamp's `svc`, or for the last stamp, the receiver of the chain. Over HTTP it may also name the [operation](#operations) the stamp invokes there. See [Receivers](#receivers). |
| `bind` | string | The binding of what this hop sent. See [Bindings](#bindings). |
| `infl` | string | The influence commitment: `""` for no influence, otherwise `b64url(H(utf8(JCS(normalise(entries)))))`, with `normalise` as defined in [sessions-and-influence.md](sessions-and-influence.md#normalisation-and-commitment). |
| `prev` | string | The previous stamp's `sig`, exactly as written, or `""` at the origin. |
| `sig` | string | `b64url` of the Ed25519 signature, by `svc`'s key, over the signed bytes. |

The signed bytes are:

```
utf8( "3|" svc "|" inst "|" rid "|" ts "|" sess "|" rcv "|" bind "|" infl "|" prev )
```

That is the ten values `3, svc, inst, rid, ts, sess, rcv, bind, infl, prev`, joined with `|` (`0x7C`), with `ts`
in decimal. `v3.json` pins two layouts in `signingBytes`. For example, the stamp
`{ v: 3, svc: "pi", inst: "pi-é", rid: "rid-1", ts: 1767225600000, sess: "", rcv: "local:read", bind: "bind-2", infl: "", prev: "prev-2" }`
signs the bytes of `3|pi|pi-é|rid-1|1767225600000||local:read|bind-2||prev-2`, with `é` as `c3 a9`.

### Stamp field rules

These hold for every stamp. A signer MUST NOT sign a stamp that breaks them, and a verifier MUST reject one
that does, with the code in brackets.

- The chain is a non-empty JSON array of objects (`CHAIN_MISSING`).
- `v` is exactly `3` (`CHAIN_MISSING`).
- `ts` is a [protocol integer](#the-grammar) in [0, 2^53 − 1], by text (`CHAIN_MISSING`), so every
  implementation reads and prints it the same way: `1.0`, `1e3` and `-1` are not protocol integers.
- Every string field (`svc`, `inst`, `rid`, `sess`, `rcv`, `bind`, `infl`, `prev`, `sig`) is a JSON
  string (`CHAIN_MISSING`). None holds a lone surrogate or a noncharacter, since [the grammar](#the-grammar)
  refuses both (`CHAIN_MISSING`).
- `sig` is canonical base64url, as [Encodings](#encodings) requires of every decoded value (`CHAIN_MISSING`).
- No signed field holds `|` (`BAD_SIGNATURE`). The fields are joined with `|`, so a field holding it would let
  two different stamps share signed bytes.
- A stamp without `rcv` does not read (`CHAIN_MISSING`).

A stamp with any other member does not read (`CHAIN_MISSING`).

## Chains

A chain is an array of stamps, **origin first**. It travels as its JCS bytes and is read as
[wire bytes](#reading): a non-empty array whose every element is a stamp with exactly the members in
[Fields and signed bytes](#fields-and-signed-bytes), each of its type ([Stamp field rules](#stamp-field-rules)).

- **Origin.** The first stamp has `prev = ""`. Its `svc` MUST be one of the verifier's allowed origins: only an
  entry point holds an origin key, so an inner service can't start a chain.
- **Links.** Stamp *i* (for *i* ≥ 1) has `prev` equal to stamp *i − 1*'s `sig`. Because each signature covers
  `prev`, removing, reordering or inserting a stamp breaks a signature or a link.
- **Shared values.** Every stamp carries the origin's `rid`. Every stamp carries the session's `sess`.
- **Receivers.** Stamp *i*'s `rcv` MUST be stamp *i + 1*'s `svc`, or that `svc`, then `#`, then a non-empty
  [operation](#operations) name, and the last stamp's `rcv` MUST equal the chain's receiver exactly. So each stamp
  names the hop it was handed to, and a chain forwarded unchanged to anyone else fails.
- **The last stamp** is the one whose `bind` and `infl` the receiver checks: it describes what was actually
  sent.

### Receivers

| Chain | Stamps, origin first | Each `rcv` |
|---|---|---|
| HTTP hops (mesh) | `gateway`, `orders` | `orders`, then `payment`: each hop names the next service, and the last names the receiving service. |
| HTTP hops naming operations | `gateway`, `orders` | `orders#createOrder`, then `payment#charge`: each hop names the next service and the [operation](#operations) it invokes there, and the last names the receiving service and its operation. |
| HTTP response | `gateway`, `orders`, then `payment`'s response stamp | The request's, then `orders`: the response stamp names the caller, the request's last `svc`, with no operation. |
| Run origin (agents) | `session` | `pi`: the client hop the run's origin hands to. The origin is minted once per run and server session, and reused for every call in it. |
| MCP tool call ([MCP profile](README.md#the-mcp-profile)) | `session`, `pi` | `pi`, then `mcp:<server>.<tool>`, where `<server>` is the server id and `<tool>` the tool name. |
| MCP response ([MCP profile](README.md#the-mcp-profile)) | `mcp-entry`, `github-tools` | `github-tools`, then the calling client's `svc` (`pi`): the response chain ends at whoever made the call. |
| Local step ([MCP profile](README.md#the-mcp-profile)) | `session`, `pi` (with `sess = ""`) | `pi`, then `local:<tool>`. |
| Boundary stamp | the egress service | The partner's entry service ([sessions-and-influence.md](sessions-and-influence.md#between-organisations)). |

The names in the second column are the agents demo's and the vectors'; the shape of each row is the rule.

An MCP server id MUST NOT contain `/`, `|` or `.`, and a tool name MUST NOT contain `/` or `|`. `/` would add a
route segment, `|` is the stamp delimiter, and a `.` in the server id would make `mcp:a.b.c` ambiguous. A
verifier MUST reject a call that breaks this (`CHAIN_MISSING`).

A service name MUST NOT contain `#`, so that an `rcv` that names an operation reads one way: the service before its
first `#`, the operation after it. A policy owner MUST NOT sign a keyring that names such a service.

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
  Every binding MUST refuse one in every string it hashes, such as the prompt text, `resultHash`, the HTTP method
  and path, the `tools/call` tool and call id, and the local tool's name, and never compute a binding over it. A
  verifier that cannot compute a binding answers as the rule above says. A binding over hashed content binds the
  value read, not its text ([Hashed content](#hashed-content)).
- `labels` in the response binding is the attestation's label array in its own order, each label written as
  `{ cid, cls }` or `{ cid, cls, owner }`, the members a label has ([Carrying a chain](#carrying-a-chain)).
- In an MCP response chain (the MCP profile) the first stamp, by the server's entry service, binds the call it
  took (the `tools/call` binding), and the last binds the response.
- The local tool `decision` (the MCP profile) is the gate's signed decision on the call:
  `{ "callId": ..., "resolved": { "parse": "ok" | "error", "paths": [{ "at", "need" }], "programs": [{ "name", "via" }], "readOnly": bool }, "routeAllowed": bool, "rulesHash": string | null, "verdict": ... }`.
  So the call id, what the gate resolved, its verdict, whether the route is listed and which rules decided
  are all covered by the stamp. A recorded step carries the decision as a token, read as [wire bytes](#reading),
  with exactly these members, and `callId` the step's own; `verdict` is one of the local verdicts, `need` one of
  `read`, `write` and `exec`, and `via` one of `list`, `folder`, `never`, `missing` and `uncheckable`.

`v3.json` pins the prompt, `tools/call`, result and response bindings in `bindPrompt`, `bindMcpCall`, `bindResult`
and `bindResponse`, and a local-tool binding through the `local step ok` case. `http-v3.json` pins the HTTP
binding with and without a query in `requestBinding`, and the HTTP result hash in `resultHash`. `json.json` pins the
refusals in `bindings`: each binding, given a lone surrogate in one string it hashes.

## Carrying a chain

### MCP (v3)

This section belongs to [the MCP profile](README.md#the-mcp-profile).

A tool call carries Paztport in the `tools/call` request's `params._meta`. Every value but `paztport/callId`'s is a
token, the base64url of the object's JCS bytes, read as [wire bytes](#reading), as an HTTP header is:

| `_meta` key | Value |
|---|---|
| `paztport/chain` | The chain's token: a JSON array of stamps, the run's origin, then the calling hop's stamp. |
| `paztport/proof` | The token of the proof for the call's route, a [proof object](#proof-object). |
| `paztport/influence` | The token of the influence entries the call was made under, a JSON array ([sessions-and-influence.md](sessions-and-influence.md#entries)). The last stamp's `infl` commits to them. |
| `paztport/callId` | The call id, a string, which the `tools/call` binding covers. |

A member that is not a string is read as a token that does not read, and gets its reader's refusal
([Reading](#reading)). A result carries the token of the server's attestation in
`result._meta["paztport/attestation"]`:

```json
{ "chain": [ /* the response chain, v3 */ ], "labels": [{ "cid": "<b64url>", "cls": "private", "owner": "..." }],
  "proof": { /* proof for the server's route */ }, "resultHash": "<b64url>" }
```

`resultHash` is the result binding of the result it rides on. The attestation is a wire object with exactly the
members `chain`, `proof`, `labels` and `resultHash`: its `chain` is read as a [chain](#chains), its `proof` as a
[proof object](#proof-object), and each label has exactly `cls` and `cid` and, when it names an owner, `owner`, a
non-empty string. An attestation or a label with another member, or an attestation whose bytes are not its
canonical bytes, does not read (`CHAIN_MISSING`). A refusal carries the token of its verdict in
`result._meta["paztport/verdict"]` instead: `{ "reason": "<code>" }`, or `{ "reason": "<code>", "audit": true }`
when an audit-mode server ran the call anyway. A verdict is a wire object with exactly a string `reason` and,
optionally, an `audit` that is `true`; one with another member, or an `audit` of any other value, does not read. A
verdict is not signed ([verification.md](verification.md#the-mcp-server-and-client)). The handshake is the
JSON-RPC method `paztport/session`, whose params and result each carry one token
([sessions-and-influence.md](sessions-and-influence.md#the-handshake)).

### HTTP (v3)

A request carries Paztport in three headers, each a token, the base64url of the object's JCS bytes, read as
[wire bytes](#reading), and names its session in a fourth, which is plain text:

| Header | Value |
|---|---|
| `X-Path-Chain` | The chain, as a JSON array of v3 stamps, origin first. The last stamp's `rcv` is the receiving service, or the operation it is sent to as `<service>#<operation>`, and its `bind` the [HTTP binding](#bindings) of the request sent. |
| `X-Path-Proof` | The [proof object](#proof-object) for the full route, receiving service included. |
| `X-Path-Influence` | The influence entries the request was made under, as a JSON array ([sessions-and-influence.md](sessions-and-influence.md#entries)). An absent header means `[]`. The last stamp's `infl` commits to them. |
| `X-Path-Session` | The [session id](sessions-and-influence.md#the-session-id), as plain text, on a call made in a session opened by [the handshake over HTTP](sessions-and-influence.md#over-http). Inside a mesh, which has no handshake, it is absent. An absent header means no session; one that names no live session opened by the peer is refused `SESSION_UNKNOWN`. |

**Paztport's headers.** Every header whose name begins with `X-Path-` is Paztport's: the four above,
`X-Path-Response`, and any added later. Names are compared case-insensitively over ASCII, as HTTP compares field
names (RFC 9110 §5.1). A caller MUST send only the Paztport headers it stamped: before it sets them, it removes
every Paztport header the call already carries, with all its values. An origin that forwards a request it
received, such as a gateway's external processor, sends that request as its call, so it removes every Paztport
header the client sent; and since its client is outside the request tree, it also removes every Paztport header
from the response it passes back.

Why: setting only the headers it stamped would leave the rest as the client sent them, beside a chain the origin
signed: the client's own `X-Path-Proof` on a route this origin holds no proof for, its `X-Path-Influence` on a
call made under none, and its `X-Path-Session` on every call. A response's `X-Path-Response` names the services
that answered and the classes of what they read, which the client has no need to know. The rule names a prefix,
not a list, so a header added later is covered. `http-v3.json` pins it in `headerNames`.

A refusal carries no Paztport header. Its body is `{"reason":"<code>"}` and nothing else, so it never names the
suspect to the caller ([verification.md](verification.md#modes-and-refusals)).

A response carries the answering service's attestation in one header, also a token:

| Header | Value |
|---|---|
| `X-Path-Response` | The JSON object `{ "labels": [ ... ], "stamp": <v3 stamp> }`, with exactly those two members, the labels written as in an MCP attestation, each with exactly its members. A header that does not read as that is `CHAIN_MISSING`. |

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

[verification.md](verification.md#http-requests-and-responses) says how each side checks these. The Java and
Go SDKs speak v3 over HTTP, and `http-v3.json` pins it.

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
secret, not extra effort. A fixed depth means a proof's length says nothing about how many routes exist, and
random slots mean its `dirs` say nothing about where in the policy a route sits. A builder MUST NOT build a tree
with an unsalted leaf, MUST NOT reuse salts across builds, and MUST choose slots from a cryptographic random
source, never in policy order.

### Proof object

```json
{ "dirs": "LRL...", "leafSalt": "<b64url, 16 bytes>", "rootId": "...", "siblings": ["<b64url, 32 bytes>", ...] }
```

`siblings` runs from the leaf's level up to the level below the root. `dirs[i]` is `L` when the working hash is
the left input at level *i*, and `R` when it is the right. A verifier checks a proof for `route` against the
verifier's pinned roots like this, and any failure is "not proven":

1. The proof is read from its JCS bytes as [wire bytes](#reading), and is an object with exactly the four members
   shown: `leafSalt`, `dirs` and `rootId` strings and `siblings` an array of strings; `dirs` matches `^[LR]*$` and
   has as many characters as `siblings` has entries.
2. `rootId` is the `rootId` of a current pinned root, and steps 3–5 use that root. Roots that share a `rootId`
   are renewals of one tree, so any one of them serves.
3. `leafSalt` decodes to exactly 16 bytes, and each sibling to exactly 32.
4. Starting from `w = H(0x00 ‖ salt ‖ utf8(route))`, for each level *i*: `w = H(0x01 ‖ w ‖ sibling[i])` when
   `dirs[i]` is `L`, else `w = H(0x01 ‖ sibling[i] ‖ w)`.
5. `w` equals that root's bytes.

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

A route is the chain's origin, then the receiver each stamp names, joined with `/`:

```
route = svc₁ "/" rcv₁ "/" … "/" rcvₙ
```

Each `rcv` but the last is the next stamp's `svc`, or names an operation of it, so a route is the services a
request passed through, then its receiver, each with the operation it was asked for where one was named. The
verifier rebuilds the route from the stamps' signed `svc` and `rcv` fields, never from a claimed field. Where the
receiver is not on the route (a response, below), the last stamp's `rcv` is left off.

- A route has at least two nodes, because its proof is held by its caller (the service the node before the last
  names: [Proof bundles](#proof-bundles-and-who-holds-what)).
- A route node MUST be non-empty, MUST NOT be `.` or `..`, and MUST NOT contain `/`, `\`, `|` or a lone
  surrogate. Node names become route segments and file names (`proofs-<svc>.json`).
- A call's route ends at its receiver: `gateway/orders/payment`, `gateway/orders#createOrder/payment#charge`
  when the hops name [operations](#operations), or (the MCP profile) `session/pi/mcp:github.create_pull_request`.
- An MCP response's route (the MCP profile) is the server's own hops, `mcp-entry/github-tools`. Its receiver, the
  calling client, is not on it: the server's policy can't list every client.
- An HTTP response's route is the request's own, `gateway/orders/payment`, proven by the proof the caller sent.
  Its receiver, the caller, is already on it.
- A local step's route is `session/pi/local:<tool>`. Local steps belong to
  [the MCP profile](README.md#the-mcp-profile).
- A client's local folder rules (the MCP profile again) are pinned as one more route,
  `session/pi/rules:<rulesHash>`, where `rulesHash = b64url(H(utf8("local-rules\n" ‖ JCS(rules))))` and `rules` is
  the rule set `{ "folders": [...], "programs": [...], "v": 1 }` as read from the [file](#files) `rules.json` (its
  format is in the [pi-extension README](../../poc-demos/agents-mcp/pi-extension/README.md#local-tool-gating)). A
  client MUST NOT apply rules that the signed root does not cover.
- An [operation table](#operations) is pinned as one more route, `<svc>/ops:<opsHash>`.

## Operations

Over HTTP a service may name its operations, so that a policy can allow a route through one operation of a
service and not through another. An operation is one handler of the service, the code a request runs; one
entrance may serve several, told apart by a query parameter. A service that does publishes an operation table,
its callers name the operation each call invokes, and it confirms that operation itself. The MCP profile has no
operations: its receivers already name one tool.

**The table** is `ops-<svc>.json`, read as a [file](#files):

```json
{
  "operations": [
    {
      "method": "POST",
      "name": "charge",
      "template": "/charge"
    },
    {
      "method": "POST",
      "name": "refund",
      "query": {
        "mode": "refund"
      },
      "template": "/charge"
    }
  ],
  "service": "payment",
  "v": 1
}
```

- `service` is the service's name, and `v` is `1`.
- `operations` is a non-empty array of objects with the members `method`, `name` and `template`, each a string,
  and optionally `query`, and no others.
- `name` is a [route node](#routes) that holds no `#`, and no two operations share one.
- `method` is an HTTP method: one or more of the characters `A` to `Z`.
- `template` is `/`, or `/` and then segments joined with `/`, each one non-empty: either `{}`, which matches any
  one non-empty segment, or literal text holding none of `/`, `{`, `}`, `?` and `#`, which matches itself exactly.
- `query`, where present, is an object with exactly one member, a condition: the call's query holds that
  parameter with that value. Its name and its value are each one or more of the characters `A` to `Z`, `a` to
  `z`, `0` to `9`, `-`, `.`, `_` and `~`.
- The operations that share a `method` and a `template` are an entrance. No two operations of an entrance share
  a `query` or both have none; every `query` of an entrance names the same parameter.

A reader refuses a table that breaks any of these.

**Matching.** An operation matches a call when its `method` is the call's method, exactly, its `template`
matches the call's raw path (the path as sent, without the query and not percent-decoded, with as many segments
as the template and each matching), and its `query`, where it has one, holds. A `query` holds when the call's
raw query, split at each `&` into parameters and each parameter at its first `=` into a name and a value, none
of them percent-decoded, holds exactly one parameter with the condition's name, whose value is the condition's
value. A call whose raw query holds more than once a parameter that a `query` of an entrance names matches none
of that entrance's operations. When more than one operation matches, the first segment, from the left, at which
their templates differ decides: the template with a literal segment there wins. Of the operations of one
entrance, one whose `query` holds wins over the one with none. No tie is left: two templates that match one
path and agree on which segments are literal are the same template, and the conditions of an entrance name one
parameter with distinct values, so at most one holds. A call no operation matches has none.

**The hash and its route.** `opsHash = b64url(H(utf8("operations\n" ‖ JCS(table))))`, where `table` is the table
as read. The signed root covers a table as the route `<svc>/ops:<opsHash>`. A service and its callers MUST NOT
use a table the signed root does not cover.

**Naming an operation.** A caller that holds the receiver's table names, in its stamp's `rcv`, the receiver's
name, then `#`, then the call's operation: `orders#createOrder`. It MUST NOT send a call to that receiver that
matches no operation. A caller that holds no table for the receiver names the receiver alone. Either way the
route names what was asked for, so the policy says whether it is allowed.

**Confirming it.** The receiver does not take its operation from the request. Its operation is the handler its
framework will run: it works that out from its own routing and supplies it as part of `receiver`
([verification.md](verification.md#http-requests-and-responses)), so a chain that names another operation fails
check 4. A service that names operations MUST route each request that names one to a single handler by its
method, path and query condition alone, and a receiver whose routing would run another handler refuses the
request. A service's own operation is therefore named under the previous hop's signature and confirmed by the
service, never claimed by it: code running in a service can name only the operation it invokes on the next hop,
which that hop confirms in turn.

## The signed root

`root.json`, the value verifiers pin:

```json
{ "notAfter": <integer>, "root": "<b64url, 32 bytes>", "rootId": "...", "sig": "<b64url>" }
```

`sig` is the policy key's Ed25519 signature over:

```
utf8( "paztport-root\n" ‖ JCS({ "notAfter": notAfter, "root": root, "rootId": rootId }) )
```

with `root` as its base64url text. When it is valid is set out under [Expiry](#keys-and-files). A widened policy
can't be swapped in without the policy private key. A verifier MUST check the signature against the pinned policy
key before using the root. A root is read as a [file](#files), as a [token](#reading) (a record that holds it keeps
it so), or as part of a session message's [wire bytes](#reading), and a reader refuses one with any member but these
four.

The policy owner MUST sign a root only over a tree whose routes it currently allows; `notAfter` is when it stops
vouching for them. Renewing a root signs the same `root` text under the same `rootId` again, with a new
`notAfter` (the policy tools use the run's time plus the lifetime, which may be earlier than the old one), so
proof bundles stay valid and holders can pick up the renewed root one at a time. A renewed root keeps its
`rootId`, and two validly signed roots for one tree differ only in `notAfter`. Narrowing a policy is not
renewing: it needs a new tree, a new `rootId` and new proof bundles.

`v3.json` pins the signed bytes and signatures in `root`, all for the client policy under the `client-policy`
pin: a signed root, at its `notAfter` and 1 ms after, the largest `notAfter` and a renewed root, which verify; a
tampered `notAfter`, a `notAfter` added to a signature made over `utf8(rootId ‖ "|" ‖ root)`, a root signed by
another policy key and a keyring signature offered as a root signature, which fail; and a root with no `notAfter`,
one whose `notAfter` is not an integer, one of 2^53 and one whose file writes it `1798761600000.0`, which a reader
refuses, the first though its signature is the policy key's over `utf8(rootId ‖ "|" ‖ root)` and the last though
its value is the integer its signature is over.

## The signed keyring

`keyring.json` names the policy key and every service's public key, and is signed by the policy key:

```json
{ "notAfter": <integer>, "policy": "<policy public key>", "services": { "<svc>": "<public key>", ... }, "sig": "<b64url>" }
```

`sig` is the policy key's Ed25519 signature over:

```
utf8( "paztport-keyring\n" ‖ JCS({ "notAfter": notAfter, "policy": policy, "services": services }) )
```

When it is valid is set out under [Expiry](#keys-and-files). A keyring is read as a [file](#files) or as a
[token](#reading) (a record that holds it keeps it so), and a reader refuses one with any member but these four.
`services` is a map: each name in it is a service, held to the [route node](#routes) rules, and each value a
string. The rule holds wherever a keyring is read, as a file or as the `clientKeyring` and `serverKeyring` of the
session handshake, and a signer MUST refuse to sign a keyring with a name the rule refuses.

A keyring verifies under a pinned policy key only when its `policy` equals that key and `sig` verifies under it.
The prefix keeps a keyring signature from being read as any other message the policy key signs. Without the
signature, a session's keyring would be the client's own claim, and anyone who could open a session could name
their own keys. The policy owner MUST sign a keyring only after checking that each listed key is that service's
current key; `notAfter` is when it stops vouching for them. A retired key needs a new keyring, not a renewed one.

`v3.json` pins the signed bytes and signatures in `keyring`: a signed keyring, at its `notAfter` and 1 ms after,
and the largest `notAfter`, which verify; a tampered service key, a tampered `notAfter`, a `notAfter` added to a
signature made over `utf8("paztport-keyring\n" ‖ JCS({ "policy": policy, "services": services }))` and a root
signature offered as a keyring signature, which fail; and a keyring with no `notAfter`, one whose `notAfter` is not
an integer, one of 2^53, one whose file writes it `1798761600000.0` and one that names a service `a/b`, which a
reader refuses, the first and the last though their signatures are the policy key's over those same bytes.

The Java and TypeScript SDKs' keygens write signed keyrings, by default valid for seven days, and both their
policy tools sign roots, by default valid for seven days. The policy tools also re-sign the keyring on every
rebuild and renew.

## The reply certificate

`reply-cert.json` is the policy key's statement that `key` is service `svc`'s key until `notAfter`. It lets that
key sign what the policy key would otherwise have to sign online, a
[session reply](sessions-and-influence.md#the-reply), while the policy key stays offline:

```json
{ "key": "<that service's public key>", "notAfter": <integer>, "policy": "<policy public key>", "sig": "<b64url>", "svc": "<service>" }
```

`sig` is the policy key's Ed25519 signature over:

```
utf8( "paztport-reply-cert\n" ‖ JCS({ "key": key, "notAfter": notAfter, "policy": policy, "svc": svc }) )
```

`notAfter` is an integer number of milliseconds since the Unix epoch, in [0, 2^53 − 1], and is written as plain
decimal digits in the signed bytes. A writer MUST write it in the file as plain decimal digits too. A certificate
is read as a [file](#files), or as part of a session reply's [wire bytes](#reading), and a reader MUST refuse one
that is not a JSON object, whose `policy`, `svc`, `key` or `sig` is missing or not a string, whose `notAfter` is
missing or not a [protocol integer](#the-grammar), so `1.0` and `1e3` are refused, or that has any other member.

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
and one that names `client-policy`, all of which fail, one with an extra field, whose file a reader refuses, and
one with the largest `notAfter`.

## Events

A verifying service MAY send its responder an event for each request whose live verification does not give
`OK`, in audit mode as well as enforce mode, with the result's reason and suspect. The responder may act on it,
for example by isolating the named instance ([verification.md](verification.md#guidance-for-a-responder)). Anyone
who can reach the responder can send it a body, so an event counts only when a service the responder allows has
signed it. [verification.md](verification.md#receiving-an-event) says how the responder checks one.

### The envelope

```json
{ "payload": "<b64url>", "sig": "<b64url>", "signer": "<service>" }
```

| Field | Type | Meaning |
|---|---|---|
| `signer` | string | The service that signed the event. The responder looks its key up by this name. |
| `payload` | string | `b64url` of [the event](#the-event)'s JCS bytes. |
| `sig` | string | `b64url` of the Ed25519 signature, by `signer`'s key, over the signed bytes. |

The signed bytes are:

```
utf8( "paztport-event\n" ‖ payload )
```

with `payload` the base64url text exactly as sent. The signature covers that text, so the responder verifies the
bytes it was given, and MUST read the event from the payload it verified, never from a form written again.
`signer` is not signed, but a name other than the signer's own looks up another key, and the signature fails. The
body is the envelope's JCS bytes ([Canonical bytes](#canonical-bytes)), read as [wire bytes](#reading), and the
envelope has exactly these three members, each a string. The prefix keeps an event signature from being read as a
stamp, or as anything else the same key signs ([Encodings](#encodings)).

`events.json` pins the signed bytes and signatures in `envelope`: an attributed refusal, an audit event that
names no one, and one with non-ASCII text.

### The event

```json
{ "audit": false, "eventId": "...", "reason": "...", "rid": "...", "suspectInst": "...", "suspectSvc": "...", "ts": 0 }
```

| Field | Type | Meaning |
|---|---|---|
| `reason` | string | The [reason code](verification.md#reason-codes) the signer's verifier gave the request. |
| `suspectSvc`, `suspectInst` | string | The suspect that result names ([attribution](verification.md#receivers-the-peer-and-attribution)), or `""` for none. |
| `rid` | string | The `rid` of the refused chain's origin stamp, as received, or `""` when no chain was read. It is the sender's text, not verified, so it is for matching the event with the signer's own logs only. |
| `audit` | boolean | `true` when the signer runs in audit mode, so it reported the failure but did not refuse the request. |
| `ts` | integer | When the event was signed, in ms since the Unix epoch: a protocol integer. |
| `eventId` | string | This event's id. It MUST NOT be `""`; any other string is an id, one of only spaces included. A signer MUST NOT reuse one. It SHOULD be a random UUID (RFC 9562, version 4): one responder remembers the ids of every signer together, so a guessable id would let one signer spend another's. |

The payload is the event's JCS bytes, read as [wire bytes](#reading). The event has exactly these seven members,
and each is of the type shown, so no member is `null`: nothing is converted from another type or filled in when
absent, so that every implementation reads the same event from the same bytes. An event whose `eventId` alone is
absent or `null` is refused as having no id ([Receiving an event](verification.md#receiving-an-event)). `ts` is a
[protocol integer](#the-grammar), decided from its text: `1767225600000.0`, `1.7672256E12` and `-1` are not
protocol integers, so a payload holding one is not an event.

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

Over HTTP a service sends an event as a `POST` to its responder's `/events` path, with the envelope's JCS bytes as
the body and `Content-Type: application/json`. An event MUST NOT change the verdict it reports: a responder that is
down, slow or refuses the event leaves the refusal as it was. A sender that waits for the responder before
answering the refusal SHOULD bound that wait, so that a slow responder cannot hold refusals up (the Java SDK
waits at most `paztport.event-timeout-ms`; see the [Java SDK README](../java/README.md#paztport-spring)). The
responder answers `200` when it accepts an event and `403` when it refuses one, with the same body for every
refusal, so the answer tells a sender nothing about the allowed signers, the keyrings or the window.

## Proof bundles, and who holds what

`proofs-<svc>.json` holds the proofs a service attaches to the requests it sends:

```json
{ "proofs": { "<route>": { /* proof object */ }, ... }, "rootId": "...", "service": "<svc>" }
```

A bundle is read as a [file](#files), and a reader refuses one with any member but these three, or whose `service`
or `rootId` is not a string.
`proofs` is a map: each name in it is a [route](#routes), at least two route nodes joined by `/`, and each value a
[proof object](#proof-object), held to those of its checks that need no root.

A route's proof is held by its caller, the service the node before the last names (the node itself, or its text
before `#`), since that is the hop that sends the request the proof travels with. A table's route
`<svc>/ops:<opsHash>` is held by `<svc>` and by every service that holds a route ending at `<svc>`, so each of its
callers can check the table it names operations from.

| Party | Holds | Never holds |
|---|---|---|
| Policy owner | The policy private key, offline. It signs the root, the keyring and reply certificates. | |
| Each service | Its own private key, and its own proof bundle. An entry service that answers session handshakes in the [entry-key form](sessions-and-influence.md#the-reply) also holds a current reply certificate for its key, and signs the replies with that key. | Other services' keys, other routes' salts. |
| Each verifier | The pinned policy public key, and the signed roots and keyrings it pins: one of each, or more while a rollover is under way. | The tree, the route list or any salt but those in the proofs it is shown. |
| The other side of a session | The peer side's policy key, pinned in advance, and the root and keyring it sends in the handshake. A client also knows the server's entry service by name, from its own configuration, to check an entry-key reply. | Its map. |

A server that answers in the entry-key form needs its policy private key only offline, to sign its root, keyring
and reply certificates; one that answers in the policy-key form keeps it online to sign each reply. In the agents
demo neither side keeps its policy private key: the client's is deleted once it has signed the client root and
keyring, and the server's once it has signed the server root, keyring and a 30-day reply certificate for
`mcp-entry`'s key, since the demo's MCP server answers in the entry-key form.

The policy owner renews its root and keyring on a schedule, well before their `notAfter`, offline, where the policy
private key is kept. Renewing keeps the tree, so the proof bundles stay valid, and each holder can pick up the
renewed root and keyring on its own, one at a time. A rebuild is different: it changes the routes, so it is a new
tree with a new `rootId` and new proof bundles, and since a proof from one tree does not prove against the other's
root, it rolls out in three steps: every verifier pins the new root beside the old; then each holder of proofs
switches to the new bundle, one at a time; then every verifier unpins the old root. A service's new key rolls out
the same way with keyrings: pin the keyring that names it, switch the service to the key, unpin the old keyring.
While both are pinned, both are honoured: a route the rebuild removed, or a key the new keyring retires, stays
usable until the old one is unpinned, so a key retired because it was compromised is unpinned at once, with no
overlap. Both policy tools renew (`--renew`, or `PAZTPORT_RENEW=true` for the Java one) and rebuild (the default),
re-signing the keyring either way; they check that the keyring and, renewing, the root were signed by the policy
key before, and refuse, writing nothing, otherwise. That the keyring's keys are still the services' current keys,
and that the tree's routes are still allowed, is the policy owner's to ensure.
The Java policy tool also rotates one service's key (`--rotate <svc>`, or `PAZTPORT_ROTATE`): it writes the
service's new key and a keyring naming it beside the current ones, for the overlap above, and leaves the current
files as they are.
