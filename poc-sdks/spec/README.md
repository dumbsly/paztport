# Paztport protocol spec

This is the written Paztport protocol, for anyone implementing it in a new language. It gives every value
exactly: the byte layouts, field orders, prefixes, constants, the order of the checks and the code each check
fails with. Where it explains a rule, it says why in a clause.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

| File | What it holds |
|---|---|
| [wire.md](wire.md) | Encodings, how JSON is read and written, keys and files, stamps and their signed bytes, chains and receivers, every binding, how a chain is carried, the Merkle tree, routes, operations, the signed root, the signed keyring, the reply certificate, events, proof bundles and who holds what. |
| [verification.md](verification.md) | The live order of checks, freshness and nonce keys, the receiver and peer checks, attribution, the MCP wrappers, HTTP requests and responses, the two modes and what a refusal carries, offline verification, the reason codes, receiving an event, and guidance for a responder. |
| [sessions-and-influence.md](sessions-and-influence.md) | The session handshake, the session id, status and unsafe sessions, the server's decision, influence entries and their commitment, content labels, the owner-aware rule, trusted records, and the boundary attestation between organisations. |
| [vectors/](vectors) | The conformance vectors. |

## The protocol

The protocol is v3: a stamp carries `"v": 3`, and its signed bytes begin with `3|`. Versions 1 and 2 were earlier
revisions, never published; the number is kept so that a stamp's `v` and its signed bytes stay as the vectors pin
them. It travels over MCP (the TypeScript SDK) and over HTTP (the Java and Go SDKs).

Design choices:

- **The receiver check.** Every stamp names the hop it was handed to (`rcv`). A live call or chain stamped for a
  different receiver is `BINDING_MISMATCH`, found with the links, not a route failure later. So a chain forwarded
  unchanged does not blame its last signer.
- **Operations.** Over HTTP a receiver may name its operations, the handlers a request can run, so a policy can
  allow a route through one operation of a service and not another. The caller names the operation in `rcv`
  (`payment#charge`); the receiver works out its own from its routing, never from the request, and a chain naming
  another fails check 4, `BINDING_MISMATCH` ([wire.md](wire.md#operations)). An operation's table entry may declare a
  key, the path segment or query parameter that names the item a call acts on; a caller then calls it once per
  request tree for each item, not once.
- **One version.** A verifier, live or offline, takes only stamps whose `v` is 3. A chain holding any other `v`
  is `CHAIN_MISSING`.
- **One byte form.** Every Paztport object travels as its JCS bytes, or as their base64url, its token, and is
  read strictly from those bytes by the implementation's own reader, never by a transport's JSON parser
  ([wire.md](wire.md#json)). So every implementation accepts and refuses the same bytes, and one signed object has
  one token. A record keeps each object as the token received.
- **The signed keyring.** A keyring is signed by its policy key, and the session request carries that
  signature as `clientKeyringSig`, which is required: a request without it, or with one that is `null`, not a
  string or empty, is malformed and opens no session (JSON-RPC `-32602` over MCP, `400 INVALID_PARAMS` over
  HTTP). One whose signature is wrong is unsafe live and not attested offline. A server attests a session only
  for a client policy key it has pinned.
- **The transport peer.** A verifier given an authenticated peer checks it is the last signer
  (`PEER_MISMATCH`), and names it in every result but `POLICY_EXPIRED`.
- **Owners.** An influence entry and a content label may carry an `owner`, and one owner-aware rule decides
  public writes.

## Conformance

`vectors/` holds language-neutral vectors, so every implementation is held to one set of recorded answers.

| File | Covers | Replayed by |
|---|---|---|
| [`v3.json`](#v3json) | v3: stamps, the live and offline verifiers, influence and sessions | TypeScript (`@paztport/core`, `@paztport/mcp`), and Java (`paztport-core`) and Go (`poc-sdks/go`) for every section but `recordedLocalStep`, `responseAttestation`, `sessionParams`, `sessionResult`, `bindMcpCall` and `bindResult`, which belong to the [MCP profile](#the-mcp-profile) |
| [`http-v3.json`](#http-v3json) | v3 over HTTP | Java (`paztport-http`) and Go (`poc-sdks/go`), Go every section. The TypeScript SDK does not speak v3 over HTTP and does not replay it. |
| [`events.json`](#eventsjson) | Responder events | Written and replayed by Java (`paztport-core`), and replayed by TypeScript (`@paztport/core`) and Go (`poc-sdks/go`). |
| [`json.json`](#jsonjson) | Reading and writing JSON ([wire.md](wire.md#json)) | TypeScript (`@paztport/core`, and `@paztport/mcp` for `toolsCall`), every section but the `http` cases of `bindings`, and Java (`paztport-core`, and `paztport-http` for `http`) and Go (`poc-sdks/go`) for every section but `jcs` and the MCP profile's `bindings` (`toolsCall`, `result`, `localTool`), which belong to the [MCP profile](#the-mcp-profile). |

| Part | Java SDK | TypeScript SDK | Go SDK |
|---|---|---|---|
| v3: stamps, the live and offline verifiers, influence and sessions | yes | yes | yes |
| v3 over MCP ([the MCP profile](#the-mcp-profile)) | no | yes | no |
| Local steps ([the MCP profile](#the-mcp-profile)) | no | yes | no |
| v3 over HTTP | yes | no | yes |
| Operations over HTTP: reading tables, naming operations and their keys | yes | no | yes |
| Operations over HTTP: confirming them from the receiver's routing | yes | no | no |
| Responder events | yes | yes | yes |
| Reading and writing JSON (`json.json`) | yes | yes | yes |

A new implementation MUST pass `v3.json` and `json.json`, less their sections that belong to
[the MCP profile](#the-mcp-profile) if it does not implement it: `recordedLocalStep`, `responseAttestation`,
`sessionParams`, `sessionResult`, `bindMcpCall` and `bindResult` in `v3.json`, and `jcs` and the `toolsCall`,
`result` and `localTool` cases of `bindings` in `json.json`. It MUST pass `http-v3.json`, and the `http` cases of
`bindings` in `json.json`, if it speaks v3 over HTTP, less `operations` if it does not name operations, and
`events.json` if it sends or receives responder events.

`v3.json` is self-contained: every case carries its inputs, and keys and policies are named and defined in the
file. Its `about` field says how its keys, salts and padding are derived, so the file can be rebuilt byte for byte;
a verify case runs the live verifier `uses` times against one nonce cache, and the last result is the one expected.
An offline case runs the offline verifier once, with no peer, clock or nonce TTL: `recordedTs.last` is the recorded
time of the last stamp, and `seen` is the set of nonce keys already spent in the record set. A verify or offline
case may pin several keyrings and roots: `keyrings`, in place of `keyring`, is a list of `{keyring, notAfter}`, and
`roots` a list of `{policy, notAfter}`, whose roots the verifier pins; `policy` then names only where the case's
proof comes from. A case's one `keyring`, or `policy`'s root when it has no `roots`, is a single member whose
window is the case's `policyNotAfter` in a verify case and none in an offline case, and two `roots` naming one
policy are its root and a renewal of it. A verify case's members each have a `notAfter`, and its `policyNotAfter`
is the earlier of the latest `notAfter` among its keyrings and the latest among its roots (with one of each, the
earlier of the two). An offline member with no `notAfter` has no window. A `keyring`, `root` or `replyCert` case's
`signingBytes` is null when its `file` does not read: a reader refuses it, it never verifies, and its signature is
never consulted. `current`, when present, gives whether it is valid at each `at`.

A case carries an object it says was received as a token, beside the object's readable value, and a replay reads
only the token. Each `verify` and `offline` case, each call of a `recordedCall` case and each `recordedLocalStep`
case's `step` carries `chainToken` beside `chain` and `influenceToken` beside `influence`, a `recordedLocalStep`
step also carries `decisionToken`, the token of its `callId`, `resolved`, `verdict`, `routeAllowed` and `rulesHash`
together, and each policy carries its proofs' tokens once, as `proofTokens.<route>` beside `proofs`, for every case
that names the route. A token is the base64url of its value's JCS bytes, except in the `verify` case "stamp ts of
-2^63", whose chain token spells the `ts` exactly as the readable chain does, a number JCS cannot write. Each
`responseAttestation` case carries `attestationToken` beside `attestation`, the token of its readable value except in
the case "an attestation in wire member order", whose token writes the members as `chain`, `proof`, `labels`,
`resultHash`. Each `sessionReply` case, and each handshake of a `recordedHandshake` or `recordedCall` case, carries
`requestToken` beside `request` and `replyToken` beside `reply`, and each `sessionStatus` and `sessionRequest` case
`requestToken` beside `request`. A `sessionParams` or `sessionResult` case is the params or result as received,
whose `request` or `reply` is the token itself.

A case carries a file as its exact text, a JSON string beside the file's readable value, and a replay reads only
the text, as [a file](wire.md#files) is read. Each `keyring` and `root` case carries `file` beside `signed`, each
`replyCert` case `file` beside `cert`, and each `sessionStatus` case `serverRootFile` beside `serverRoot` and
`serverKeyringFile` beside `serverKeyring`. A file is its value in the file format, except where that format cannot
write the value's `notAfter` (1.5 and 2^53) and in the `keyring` and `root` cases "notAfter written
1798761600000.0": there it is the value's file with that number's own text in place of the `notAfter`, so each
reader meets the number as written.

The three record sections read a record set as [verification.md](verification.md#offline-verification) does, from
the spec's objects and times, never from any implementation's record format:

- A **`recordedHandshake`** case is a recorded handshake
  ([sessions-and-influence.md](sessions-and-influence.md#recorded-handshakes)): `request` and `reply` as
  recorded, read from `requestToken` and `replyToken`, `pin` (the server policy key the client pinned, by name in
  `keys`) and `serverEntry` (the server's entry service from the verifier's own configuration).
  `expected.attestedAt[i]` is whether it opened an attested session judged at `at[i]`, `attested` whether it did at
  all (judged at the earliest of its limits), `responseNotAfter` the `policyNotAfter` a response recorded in it is
  checked with (the server root's `notAfter`, or in the entry-key form the earlier of it and
  `serverKeyringNotAfter`), read from the reply's windows once the signatures covering them verify, whether or not
  the session is attested, and `null` otherwise.
  A recorded `request` may hold material a reader refuses as malformed (no `clientKeyringSig`, no
  `clientKeyringNotAfter`, or a client root without `notAfter`): the session it opened is never attested.
- A **`recordedCall`** case is one record set: `handshakes` in the `recordedHandshake` shape, then `calls`, checked
  in order against one set of spent nonce keys that starts empty. Each call names the handshake whose session it was
  made in by its index, `handshake`, and carries an offline case's chain inputs (`chain`, `expectedBind`,
  `influence`, `proofRoute` in `policy`, `receiver`, `receiverInRoute`, `nonceKey`, `rid`, `recordedTs`, `prompt`).
  It is checked by the offline verifier with the case's `allowedOrigins`, `callMaxAgeMs` and `runMaxAgeMs`, the
  client keyring and root of that handshake's request and the session id of its reply; then a call that verifies but
  whose `recordedTs.last` is past one of the session's limits is `OUTSIDE_SESSION`. `expected[i]` is the `reason` for
  `calls[i]`. Every handshake here is attested: the spec gives a call relying on one that is not no result.
- A **`recordedLocalStep`** case ([MCP profile](#the-mcp-profile)) is a recorded local step: `step` (`tool`,
  `callId`, `rid`, `now`, `input`, `resolved`, `verdict`, `routeAllowed`, `rulesHash`, `decisionToken`, `chain`,
  `proofRoute`, `influence`), the `client` it is checked against (`keyring` by name, the root of `policy`, in which
  `proofRoute` names the step's proof, the root's and keyring's windows `rootNotAfter` and `keyringNotAfter`, and
  `rules`), the `signers` (`svcs`, the origin service then the client hop, and their one `inst`), its `run`
  (`prompt` and start times `ts`), and `seen`, the nonce keys already spent. `expected` is the `reason`, the
  `verdict` the step signed when the record verifies (null when it does not).
- A **`responseAttestation`** case ([MCP profile](#the-mcp-profile)) is a response as a client receives it: the
  `attestationToken` of the `paztport/attestation` value (its readable value is `attestation`), the `result` it
  answers, the `call` (`rid`, `toolCallId`, `receiver`), and the `server` the stamps are checked against (`keyring`
  by name, the root of `policy`, `allowedOrigins`, `sess`, `policyNotAfter` and `nonceTtlMs`). The client checks it
  once at `now`, as [a response on the client](verification.md#the-mcp-server-and-client) does, and `expected` is
  the `reason`. Java and Go replay no case here.
- A **`sessionParams`** case ([MCP profile](#the-mcp-profile)) is `paztport/session`'s `params` as a server receives
  them, read as [the handshake](sessions-and-influence.md#the-handshake) says: `expected` is `OK` when they are a
  `request` token that reads as a request, with or without `_meta`, and `INVALID_PARAMS` (JSON-RPC `-32602`)
  otherwise. Java and Go replay no case here.
- A **`sessionResult`** case ([MCP profile](#the-mcp-profile)) is `paztport/session`'s `result` as a client receives
  it: `expected` is `OK` when it is a `reply` token, with or without `_meta`, that reads as a reply, and
  `MALFORMED_REPLY` otherwise. Its `OK` cases carry the reply of the `sessionReply` case "entry-key form attested",
  whose check that section pins. Java and Go replay no case here.

### v3.json

- `deriveSessionId`: the session id.
- `bindPrompt`, `bindResult`, `bindMcpCall` and `bindResponse`: the prompt, result, `tools/call` and response
  bindings.
- `commitInfluence`: the influence commitment.
- `merkle`: the Merkle leaves, nodes and proofs (with the encoded proof headers).
- `signingBytes` and `signatures`: v3 signed bytes and signatures.
- `influence`: influence with owners and its commitment.
- `rule`: the owner-aware rule's truth table.
- `keyring` and `root`: the signed keyring and the signed root (the signed bytes and signature, at its `notAfter`
  and 1 ms after, the largest `notAfter`, a renewed root, a tampered service key and a tampered `notAfter`, a
  `notAfter` added to a signature made without one, a `notAfter` that is not an integer, a `notAfter` of 2^53, one
  whose file writes it `1798761600000.0`, a root signature offered as a keyring's and the other way round, and a
  keyring and a root with no `notAfter`, each signed over its other fields alone, which a reader refuses and which
  are never valid; the root-as-keyring and keyring-as-root cases do not pin the domain prefixes, since their signed
  bodies differ and would fail without them: each case's literal signed bytes do).
- `replyCert`: reply certificates (the signed bytes and signature, a tampered `notAfter`, one signed by and one
  naming another policy key, one with an extra field and the largest `notAfter`).
- `sessionReply`: session replies (the entry-key and policy-key forms, the certificate's expiry, forged and
  malformed replies, one with a member a reply does not have among them, a server keyring or root `notAfter` moved,
  dropped or malformed, the server's root and keyring at their `notAfter` and expired, an expired root's window
  moved in a reply the entry key signed again, and a keyring window in a policy-key reply).
- `sessionStatus`: session status cases (the server's status for a request, against its own root and keyring and
  its pins: each side's root and keyring at its `notAfter` and expired, and a client window moved).
- `sessionRequest`: session request cases (a well-formed request, and one with no keyring signature, or a `null`,
  empty or numeric one, with no keyring `notAfter`, or with a client root without one, each malformed).
- `verify`: live verify cases (each kind of receiver, operations named in `rcv` (a route through them, a chain
  naming another operation, a receiver naming none, an inner `rcv` naming another service's operation, an empty
  operation, an inner operation holding a `/` or a `#`, and a proof for another operation's route), a stamp whose
  `v` is not 3, malformed `rcv` fields, the check order, the peer and attribution, replay, an altered owner, and
  the pinned policy's window: at it, past it, out of range, and past it before a bad signature or a malformed
  chain, and a stamp `ts` of −2^63, written exactly, and several pinned keyrings and roots: a proof under the
  second root, a `rootId` pinned nowhere, a rotated key only in the second keyring, a chain whose keys come from
  two keyrings, a proof under an expired root and one under a renewal of it, a key only in an expired keyring,
  every keyring or every root expired, and a proof relabelled with the other root's `rootId`).
- `offline`: offline cases (a recorded call, a stamp whose `v` is not 3, a broken receiver, the recorded time, age,
  prompt and replay checks, a record with no time, `recordedTs` `null`, and no age limits, `callMaxAgeMs` and
  `runMaxAgeMs` `null`, with the last stamp at the run window and 1 ms past it, and the origin at the call window
  after the last stamp and 1 ms past it, where a `null` is absent, never 0, and a record within only the second
  root's window, one at its `notAfter`, one past every root's window, one past every keyring's window, and one past
  every root's window whose chain is malformed).
- `recordedHandshake`: recorded handshakes (attested at a time, at all and the response limit, and none where the
  server's signatures do not verify, in both reply forms, at each kind of limit, and not attested, a reply the
  server signed that fails the client's shape check included, and a request without a client keyring signature or
  `notAfter`, or with a client root without one).
- `recordedCall`: recorded calls (the session's limits, a failing call past them, and replay across a record set, a
  repeated handshake included).
- `recordedLocalStep`: recorded local steps ([MCP profile](#the-mcp-profile): allowed, refused and unlisted steps,
  the client's root and keyring windows, each re-check, and a step at the run window and 1 ms past it).
- `responseAttestation`: response attestations ([MCP profile](#the-mcp-profile): an attested response, an
  attestation with a member it does not have, a label with a member labels do not have, an attestation in wire
  member order, and a result hash for another result).
- `sessionParams` and `sessionResult`: `paztport/session`'s params and result ([MCP profile](#the-mcp-profile): a
  request or reply token alone and with `_meta`, a member they do not have, the request or reply itself in place of
  its token, none, and a request token and a reply token that do not read).

### http-v3.json

- `resultHash`: the HTTP result hash.
- `requestBinding`: the request binding with and without a query.
- `headerNames`: Paztport's header names (a name and whether it begins with `X-Path-`, ASCII letters in any case,
  lookalikes refused).
- `responses`: response checks (a good response, one sent to the wrong receiver, altered labels, an altered status,
  a replay and one past the verifier's `policyNotAfter`, a response on a route through operations, which another
  operation's spent response key does not refuse and its own does, and responses from a keyed operation, which
  another item's spent response key does not refuse and its own does).
- `boundaryInfluence`: blinded boundary influence (the salts, the sent entries, and an opening that opens and one
  with an extra original that does not).
- `rules`: the HTTP rules a receiver, a caller, a partner and an egress follow
  ([below](#the-http-rules-in-http-v3json)).
- `operations`:
  - `table`: an operation table with its hash and route.
  - `shared`: an entrance with two operations told apart by a query condition.
  - `keyed`: a table whose operations declare keys.
  - `refused`: tables a reader refuses.
  - `match`: matching cases.
  - `keys`: cases giving a call's operation in `keyed` and its key value, null for none: a segment key, a query
    key, a key of 128 characters, and one of 200 under `maxLength` 256; no key value for a percent-encoded segment
    or query value, a dot or dot-dot segment, a key of 129 characters, a query key absent, repeated, with no value
    or repeated under an encoded name, a query holding a semicolon, or an operation with no key.
  - `receive`: how a receiver confirms the operation it dispatches to, and that it spends that operation's request
    key alone, one for each key value for an operation with a key.

It reuses `v3.json`'s keys and mesh policy by name, and adds a `payment` key derived by `v3.json`'s rule; `rules`
adds keys and material of its own, derived the same way.

### events.json

- `envelope`: the envelope's signed bytes and signatures.
- `verify`: the responder's checks (an accepted event, each refusal, `ts` at the window and 1 ms past it on both
  sides, replays with `uses` and across the window, refusals that spend no id, a wrong signer, a signer known only
  to the second of several keyrings, one whose key is the second of two keyrings naming it, and one in none (a
  case's `keyrings`, in place of the file's one, each map naming keys in `keys` by name), a tampered payload,
  malformed envelopes and payloads read strictly, with nothing coerced or filled in, and the check order).
- `attributable`: each allowed reason, the excluded ones, an audit event and an event naming no service or no
  instance, with whether a responder may act on it.

Its keys, `payment-next` among them, are derived by `v3.json`'s rule.

### json.json

Cases: each input given as bytes, and each refused input naming the reading step (`size`, `parse` or `canonical`)
that first refuses it.

- `wire`: bytes read as a base64url token (canonical bytes read, among them an empty object and array, the escapes
  JCS writes, non-ASCII written as itself, the characters beside the noncharacters, `__proto__`, integer-like names
  in code-unit order, the largest integers and the limits exactly, and refused: whitespace, members out of order or
  in code-point order, a repeated name, each escape JCS does not write, lone surrogates raw and escaped, raw
  noncharacters, a byte order mark, UTF-16 and UTF-32, invalid UTF-8 and overlong forms, raw control characters,
  every number that is not a protocol integer, malformed JSON, and the size and depth limits, at each and one past
  it).
- `file`: bytes read as a file (any whitespace, member order and escape read, and refused: a name repeated, also
  through an escape and when not adjacent, an escaped lone surrogate, noncharacters raw and escaped, invalid UTF-8,
  a byte order mark, every number that is not a protocol integer, and the file limits).
- `fileFormat`: a keyring, root, reply certificate, proof bundle and local rules file, integer-like names, a value
  given out of JCS order, and an empty object and array, each as written.
- `base64url`: the decoder's text read as canonical bytes or refused (padding; every last character after `A` and
  after `AA`, refused when its unused bits are not zero and accepted, with the bytes it decodes to, when they are;
  an impossible length; characters outside the url-safe alphabet; surrounding whitespace).
- `jcs` ([MCP profile](#the-mcp-profile)): hashed content as JCS writes it (RFC 8785's Appendix B numbers, its
  §3.2.2 sample and §3.2.3 sorting example, `-0`, a noncharacter, and a lone surrogate refused).
- `bindings`: each binding ([wire.md](wire.md#bindings)) refusing a lone surrogate in one string it hashes (the
  prompt text, a response's `resultHash` or `toolCallId`, a `tools/call`'s tool, call id or argument, a result, a
  local tool's name or input, a Merkle leaf's route, an HTTP request's method or target).

### The MCP profile

The MCP profile is the part of the protocol that only an MCP client and server speak: the `tools/call`, result and
local-tool [bindings](wire.md#bindings), the MCP tool call and response chains, and local steps (a client's own tool
calls, signed by the client alone, with their route, nonce key and recorded check). An implementation that speaks
the protocol over HTTP only need not implement the profile, and the HTTP rules never refer to it. An implementation
that claims the profile MUST implement all of it, and MUST pass its cases: in `v3.json`, the `bindMcpCall`,
`bindResult`, `recordedLocalStep`, `responseAttestation`, `sessionParams` and `sessionResult` sections, and in
`json.json`, the `jcs` section and the `toolsCall`, `result` and `localTool` cases of `bindings`. These are the
cases whose replay needs profile code. Every `verify` case is replayable by an HTTP-only implementation, since a
route and a receiver are opaque strings there. Three offline results belong to the profile alone (`PROOF_MISMATCH`,
`RULES_MISMATCH` and `VERDICT_MISMATCH`, [verification.md](verification.md#reason-codes)). Each passage of the spec
that belongs to it says so and links here.

### The HTTP rules in http-v3.json

`http-v3.json`'s `rules` holds the rules the spec sets for v3 over HTTP that the rest of the file does not reach:
how a receiver reads a request, who attests, the peer a certificate names, the partner's sessions and handshake
endpoint, the egress, what a response adds to the caller's influence, refusals and trusted records. Each case is
replayed through functions that take a request as it arrived, with no web framework, so nothing in the file is a
framework's choice. Its `about` says how its keys, material, trees and handshake nonces are derived, so the file
can be rebuilt byte for byte. Bodies and certificates are hex, headers are their values as sent, and every
expected refusal's `body` is its exact bytes, `{"reason":"<code>"}`. The functions that answer return the status and
the body only, so the file does not carry the header: every refusal, and every `refusals` and `boundaryRefusals` case
among them, is sent with `Content-Type: application/json` and no parameters
([verification.md](verification.md#modes-and-refusals)).

| Kind | Shape | What it pins |
|---|---|---|
| `requests` | receiver | A request at the receiver ([verification.md](verification.md#http-requests-and-responses)): the nonce key `<rid>\|<last svc>\|<last rcv>\|req`, which other directions', hops' and operations' keys do not spend, and each unreadable header: a chain (`CHAIN_MISSING`), a proof (no proof, so `PATH_NOT_ALLOWED`) and influence (`INFLUENCE_MISMATCH`). |
| `unreadableInfluence` | receiver | Influence that does not read is never dropped: `403` where verification refuses first, otherwise `400 INFLUENCE_MISMATCH`, in audit mode too, at a service that verifies only to attest and at one with no verifier; an origin carries none, so has none to drop ([verification.md](verification.md#modes-and-refusals)). |
| `attestation` | receiver | Who attests: only a chain that passed the live order at that service, whether or not it verifies requests under a mode; never a refusal, an audit failure, a forged or unsigned chain, a service with no verifier, a hop that is off, or an origin; and, where the receiver confirms its operation again at dispatch, only an answer whose handler it confirmed. |
| `peerCertificates` | table | The peer under mTLS: `svc` is the subject's one common name, a UTF8String or PrintableString, read as encoded and compared as it is, else `""`; `inst` is the address the connection came from. |
| `sessionHeader` | partner | `X-Path-Session` ([sessions-and-influence.md](sessions-and-influence.md#over-http)): no header is an unsafe session that believes nothing; an id is the call's only when the same issuer and name opened it, so an unknown id, another peer's, the same name under another issuer, no certificate, one naming no single service and a stamp made in another session are `SESSION_UNKNOWN`. |
| `sessionRegistry` | partner | Sessions by id: a handshake replaces none, a peer holds at most N and loses its least recently used, replicas sharing a certificate are one peer, another peer's handshakes evict none, a session idle for the idle period expires and a call starts that period again, and a handshake that opens no session changes none. |
| `unsafeEndpoints` | table | An endpoint is `<METHOD> <path pattern>` by the dispatched handler's pattern, and a `HEAD` is refused wherever its `GET` is. |
| `handshakeErrors` | partner | The handshake endpoint: `INVALID_PARAMS` for a body that is not JSON or not a readable request (a `null` or missing keyring window, a client root with no window, a keyring naming a service that is not a route node and a missing `clientKeyringSig` included, each body otherwise in JCS member order), `NO_SESSION` for one that opens none (a 15-byte nonce, a 63-byte root signature) and for no client certificate or one naming no single service; and a request that opens an attested and an unsafe session. |
| `egress` | egress | The egress's steps 1 to 7 ([sessions-and-influence.md](sessions-and-influence.md#between-organisations)): nothing sent, the handshake included, unless the chain passed the live order there; one boundary stamp and no internal one; blinded influence and the boundary route's proof; nothing but the session id in an unsafe session; the replacement after a 404 or a reply under another key, unsafe whatever it says, and a call that fails when the replacement is answered 404 too; each reply recorded as one `local-untrusted` entry; and a session dropped after `SESSION_UNKNOWN`. |
| `callerInfluence` | caller | A response at the caller: each label of a response that verifies becomes an entry with `src` `http:<target>` and `h` the result hash, the target the receiver's policy name without any operation, also when the caller holds the receiver's table (the case's `operations`) and its stamp names one; any other response adds exactly one `local-untrusted` entry. The cases with a table run on the `shop-operations` material, whose root covers `gateway/orders/payment#pay` and payment's table. |
| `sessionExpiry` | partner | A session's calls are `POLICY_EXPIRED` once the client's root or keyring passes its `notAfter`, and verify at it; a handshake after it is unsafe; and a partner whose own material lapses opens new sessions unsafe and keeps verifying the earlier ones ([sessions-and-influence.md](sessions-and-influence.md#status)). |
| `refusals` | receiver | What a refusal carries, in a mesh: the code alone, even where the result names a suspect. |
| `boundaryRefusals` | partner | The same at the boundary: the partner's refusals, unreadable influence included (a partner has no audit mode), and an unsafe session's switched-off endpoints refused `UNSAFE_SESSION`, with no session header too. |
| `trustedRecord` | receiver | Trusted records ([sessions-and-influence.md](sessions-and-influence.md#trusted-records)): a verified chain and no `third-party` or `local-untrusted` content, counting what the handler reads; `private`, `public` and owners do not count. The partner kinds' `trustedRecord` covers a call in an unsafe session, and `partnerTrustedRecord` the same rule at the boundary. |
| `partnerTrustedRecord` | partner | The same rule at the boundary: an attested call qualifies only with no `third-party` or `local-untrusted` content, counting what the handler reads; `private`, `public` and owners do not count. |

A **receiver** case enters `request` (`method`, `target`, `headers`, `body`) `uses` times at `service`: its `svc`
and `inst`, whether it is an `origin`, and whether it has a `verifier`, pinned to `material`. Every service holds
its stamp key. `mode` is the [mode](verification.md#modes-and-refusals) it verifies requests under, `enforce` or
`audit`; or `off`, which is no mode but a hop its deployment has switched Paztport off on; or null, a service that
verifies no requests and may still verify a chain to decide whether to attest. Each entry has `peer`, or none,
and one nonce cache that already holds the keys in `spent`; then the handler reads `read`. `expected` is the last
entry's answer: the `refusal`, or null; whether the chain `verified` at this hop; the `influence` the handler
starts from; whether the answer `attests`; and whether a `trustedRecord` may be written from it. A null `request`
is work outside any request.

A **partner** case runs `steps` against one partner (`partner`: its `material`, the client policy keys it has
`pinned`, `clientOrigins`, the endpoints it has switched off for unsafe sessions, `maxSessionsPerPeer`,
`sessionIdleMs`, its windows and the clock's `start`), its clock at each step's `at`. A peer is one of `peers`, a
client `certificate` and the `remoteAddr` it connected from, read as `peerCertificates` reads one, with its issuer
for the session's binding; null is no client certificate. A `handshake` posts the request `handshakes` names, as its
JCS bytes in `handshakeBodies`, or `body`; `as` names the session it opens, since the partner chooses the id. It
expects the `status`, the `error` of a `400`, and the reply's `sessionStatus` and `disabled` of a `200`. A `call`
names its session as `{"of": <as>}`, `{"id": <literal id>}`, or null for no `X-Path-Session`. Its `stamp`, when
present, is a boundary stamp signed with `key` as the step runs, in the session its `sess` names, binding the call's
method, its target and the stamp's own `body`, and committing to the stamp's `influence`; `proofHeader` and
`influenceHeader` go as given. `routePattern` is the pattern of the handler the call reaches, which an unsafe
session's switched-off endpoints are matched against. It expects the `refusal`, whether the call is `attested`, the
`influence` the handler starts from, and `trustedRecord`. A `call` may carry `read`, what the handler reads after
the call is accepted, in a receiver case's form; `trustedRecord` counts it after the call's influence, and no `read`
is the empty list.

An **egress** case enters `inbound`, a receiver case's inputs, at the egress (null: no request at all), then
sends each of `posts` to a scripted partner. Each handshake that carries a client root takes the next of
`partnerScript.handshakes`: `attested` or `unsafe`, a genuine reply in the entry-key form from the `psp`
material; `notFound`, a `404`; `wrongKey`, a reply in the policy-key form signed by and naming `stranger-policy`.
One with no client root gets a genuine reply whose status is `replacement`, and each call takes the next of
`calls`. A handshake or call the script has no answer for fails the replay, so a case whose script is empty
expects nothing to be sent. It expects each post's `outcome` (`answered`, with the partner's `status` and whether
the call went out `attested`; `refused`, the egress declining before anything is sent; or `failed`, no session
could be opened, so the call itself is not sent), everything the partner `received` in order, and the influence
the request holds afterwards, normalised. A received `handshake` says whether it carried a `clientRoot`. A
received `call` gives its `session` and `stampSession`, the position in `received` of the handshake whose reply
issued the id in its `X-Path-Session` and in its stamps' `sess`, then its `stamps` with `sess` and `sig` left out
(the partner chose the id, and `sig` covers it), and its `proof` and `influence` as decoded; each is null when the
header is absent. The replay also verifies every received stamp's `sig` under the key the egress's keyring (its
`material`'s) holds for the stamp's `svc`, over its fields as received, `sess` included; a stamp that does not
verify fails the case.

A **caller** case is a call by `caller` after the chain `inbound`, with `influence` so far, and the `response`
to it (`status`, `header`, `body`). It expects the sent stamp's `rcv`, the response check's `reason` (null when
the caller has no verifier and checks nothing) and the `influence` the response adds.

Some rules are not pinned by vectors and are tested in each HTTP SDK (`paztport-http`, `paztporthttp`): the startup
checks of a partner's and an egress's own material, the [wire limit](wire.md#limits), 256 KiB, on a handshake body,
clearing a session after `POLICY_EXPIRED`, the egress's own idle period, and the egress labelling its own response to
its caller `local-untrusted`, since a handler may relay what the partner said.

Cases may be added at any time. A recorded answer changes only with a protocol change.
