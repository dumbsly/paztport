# Paztport protocol spec

This is the written Paztport protocol, for anyone implementing it in a new language. It gives every value
exactly: the byte layouts, field orders, prefixes, constants, the order of the checks and the code each check
fails with. Where it explains a rule, it says why in a clause.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

| File | What it holds |
|---|---|
| [wire.md](wire.md) | Encodings, keys and files, stamps (v1, v2, v3) and their signed bytes, chains and receivers, every binding, how a chain is carried, the Merkle tree, routes, the signed root, the signed keyring, the reply certificate, events, proof bundles and who holds what. |
| [verification.md](verification.md) | The live order of checks, freshness and nonce keys, the receiver and peer checks, attribution, the MCP wrappers, HTTP requests and responses, the two modes and what a refusal carries, offline verification, the legacy rule, v1, the reason codes, receiving an event, and guidance for a responder. |
| [sessions-and-influence.md](sessions-and-influence.md) | The session handshake, the session id, status and unsafe sessions, the server's decision, influence entries and their commitment, content labels, the owner-aware rule, trusted records, and the boundary attestation between organisations. |
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
  (`PEER_MISMATCH`), and names it in every result but `POLICY_EXPIRED`.
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
| `v3.json` | v3 signed bytes and signatures, influence with owners and its commitment, the owner-aware rule's truth table, the signed keyring and the signed root in both forms (the new form's signed bytes and signature, at its `notAfter` and 1 ms after, the largest `notAfter`, a renewed root, a tampered `notAfter`, `notAfter` dropped from a new-form signature and added to an old-form one, a `notAfter` that is not an integer, a `notAfter` of 2^53, one written `1798761600000.0` and read by value, a root signature offered as a keyring's and the other way round, and an old-form keyring and root whose signatures verify, which only an offline verifier may rely on, and which are never valid; the root-as-keyring and keyring-as-root cases do not pin the domain prefixes, since their signed bodies differ and would fail without them: each case's literal signed bytes do), reply certificates (the signed bytes and signature, a tampered `notAfter`, one signed by and one naming another policy key, an ignored extra field and the largest `notAfter`), session replies (the entry-key and policy-key forms with new-form roots and keyrings on both sides, the certificate's expiry, forged and malformed replies, a server keyring or root `notAfter` moved, dropped or malformed, the server's root and keyring at their `notAfter`, expired and in the old form, an expired root's window moved in a reply the entry key signed again, and a keyring window in a policy-key reply), session status cases (the server's status for a request, against its own root and keyring and its pins: each side's root and keyring at its `notAfter`, expired and in the old form, and a client window moved), live verify cases (each kind of receiver, a v2 chain live, malformed `rcv` fields, the check order, the peer and attribution, replay, an altered owner, and the pinned policy's window: at it, past it, out of range, and past it before a bad signature or a malformed chain, and a stamp `ts` of −2^63, written exactly), offline cases (a legacy v2 call, with and without a stray `rcv`, a v3 call, a mixed chain, a broken receiver, the recorded time, age, prompt and replay checks), recorded handshakes (attested at a time, at all, the response limit and legacy, in both reply forms, at each kind of limit, in the old forms, and not attested), recorded calls (the session's limits, a failing call past them, and replay across a record set, a repeated handshake included) and recorded local steps ([MCP profile](#the-mcp-profile): allowed, refused and unlisted steps, the client's root and keyring windows, and each re-check). | TypeScript (`@paztport/mcp`), and Java (`paztport-core`) for every section but `recordedLocalStep`, which belongs to the [MCP profile](#the-mcp-profile) |
| `http-v3.json` | v3 over HTTP: the HTTP result hash, the request binding with and without a query, and response checks (a good response, one sent to the wrong receiver, altered labels, an altered status and a replay), blinded boundary influence (the salts, the sent entries, and an opening that opens and one with an extra original that does not), and in `rules` the HTTP rules a receiver, a caller, a partner and an egress follow ([below](#the-http-rules-in-http-v3json)). It reuses `v3.json`'s keys and mesh policy by name, and adds a `payment` key derived by `v3.json`'s rule; `rules` adds keys and material of its own, derived the same way. | Java (`paztport-http`) only. The TypeScript SDK does not speak v3 over HTTP and does not replay it. |
| `events.json` | Responder events: the envelope's signed bytes and signatures, and the responder's checks (an accepted event, each refusal, `ts` at the window and 1 ms past it on both sides, replays with `uses` and across the window, refusals that spend no id, a wrong signer, a tampered payload, malformed envelopes and payloads read strictly, with nothing coerced or filled in and nothing but JSON whitespace around them, `ts` read by value, and the check order), and in `attributable` each allowed reason, the excluded ones, an audit event and an event naming no service or no instance, with whether a responder may act on it. Its keys are derived by `v3.json`'s rule. | Written and replayed by Java (`paztport-core`), and replayed by TypeScript (`@paztport/core`). |

| Version | Java SDK | TypeScript SDK |
|---|---|---|
| v1 | yes, for `v1.json` | yes, for `v1.json` |
| v2 (offline, legacy) | yes | yes |
| v3: stamps, the live and offline verifiers, influence and sessions | yes | yes |
| v3 over MCP ([the MCP profile](#the-mcp-profile)) | no | yes |
| Local steps ([the MCP profile](#the-mcp-profile)) | no | yes |
| v3 over HTTP | yes | no |
| Responder events | yes | yes |

A new implementation MUST pass `v3.json`, less its `recordedLocalStep` section if it does not implement [the MCP
profile](#the-mcp-profile). It MUST pass `v2.json` if it reads records made before v3,
`http-v3.json` if it speaks v3 over HTTP, `events.json` if it sends or receives responder events, and `v1.json`
if it speaks the v1 HTTP format.

Known divergences, with no vector: a lone surrogate in a binding's plain strings ([wire.md](wire.md#bindings)).
The Java SDK's prompt and response bindings refuse one, as the spec requires, and its HTTP request binding
encodes it as `?`. The TypeScript SDK's bindings (prompt, response, `tools/call`, local tool and HTTP) encode it
as U+FFFD, so its prompt and response bindings break the rule.

Known divergences in reading an event, with no vector (all to be settled by a later pass over how every JSON number
and nesting limit is read): a `ts` that is zero but whose exponent overflows a 32-bit integer (`0e999999999999`,
`0.0e-99999999999`) is read by value as 0 by the TypeScript SDK, so the event is refused as outside the window, and
is refused as malformed by the Java SDK. A `ts` written in more than 1000 characters with a safe-integer value is
accepted by the TypeScript SDK and refused by the Java SDK, whose parser limits a number's length. When a member is
written twice in a payload or an envelope and the earlier value exceeds a parser limit (nesting depth or number
length) while the later one is valid, the TypeScript SDK takes the later value and the Java SDK refuses the body.

`v3.json` is self-contained: every case carries its inputs, and keys and policies are named and defined in the
file. Its `about` field says how its keys, salts and padding are derived, so the file can be rebuilt byte for
byte; a verify case runs the live verifier `uses` times against one nonce cache, and the last result is the one
expected. An offline case runs the offline verifier once, with no peer, clock or nonce TTL: `recordedTs.last` is
the recorded time of the last stamp, and `seen` is the set of nonce keys already spent in the record set. A
`keyring` or `root` case is in the new form exactly when `signed` has a `notAfter` member; its `signingBytes` is
null when that `notAfter` is not an integer in [0, 2^53 − 1], which a reader refuses, and `current`, when
present, gives whether it is valid at each `at`. The file writes one `keyring` and one `root` case's `notAfter`
as `1798761600000.0`, which a reader must read by value as the integer its signature is over, so a replay must
read the file's own text.

The three record sections read a record set as [verification.md](verification.md#offline-verification) does, from
the spec's objects and times, never from any implementation's record format:

- A **`recordedHandshake`** case is a recorded handshake
  ([sessions-and-influence.md](sessions-and-influence.md#recorded-handshakes)): `request` and `reply` as
  recorded, `pin` (the server policy key the client pinned, by name in `keys`) and `serverEntry` (the server's entry
  service from the verifier's own configuration). `expected.attestedAt[i]` is whether it opened an attested session
  judged at `at[i]`, `attested` whether it did at all (judged at the earliest of its limits), `responseNotAfter` the
  `policyNotAfter` a response recorded in it is checked with (2^53 − 1 when neither the server's root nor, in the
  entry-key form, its keyring has a window), read from the reply's windows whether or not the session is attested,
  and `legacy` whether it is attested from a request with no `clientKeyringSig`.
- A **`recordedCall`** case is one record set: `handshakes` in the `recordedHandshake` shape, then `calls`, checked in
  order against one set of spent nonce keys that starts empty. Each call names the handshake whose session it was
  made in by its index, `handshake`, and carries an offline case's chain inputs (`chain`, `expectedBind`,
  `influence`, `proofRoute` in `policy`, `receiver`, `receiverInRoute`, `nonceKey`, `rid`, `recordedTs`, `prompt`).
  It is checked by the offline verifier with the case's `allowedOrigins`, `callMaxAgeMs` and `runMaxAgeMs`, the
  client keyring and root of that handshake's request and the session id of its reply; then a call that verifies
  but whose `recordedTs.last` is past one of the session's limits is `OUTSIDE_SESSION`. `expected[i]` is the
  `reason` for `calls[i]` and whether it is `legacy` (only an `OK` from v2 stamps is). Every handshake here is
  attested: the spec gives a call relying on one that is not no result.
- A **`recordedLocalStep`** case ([MCP profile](#the-mcp-profile)) is a recorded local step: `step` (`tool`,
  `callId`, `rid`, `now`, `input`, `resolved`, `verdict`, `routeAllowed`, `rulesHash`, `chain`, `proofRoute`,
  `influence`), the `client` it is checked against (`keyring` by name, the root of `policy`, in which `proofRoute`
  names the step's proof, the root's and keyring's windows `rootNotAfter` and `keyringNotAfter` when they are in the
  new form, and `rules`), the `signers` (`svcs`, the origin service then the client hop, and their one `inst`), its
  `run` (`prompt` and start times `ts`), and `seen`, the nonce keys already spent. `expected` is the `reason`, the
  `verdict` the step signed when the record verifies (null when it does not), and `legacy`.

### The MCP profile

The MCP profile is the part of the protocol that only an MCP client and server speak: the `tools/call`, result and
local-tool [bindings](wire.md#bindings), the MCP tool call and response chains, and local steps (a client's
own tool calls, signed by the client alone, with their route, nonce key and recorded check). An implementation
that speaks the protocol over HTTP only need not implement the profile, and the HTTP rules never refer to it. An
implementation that claims the profile MUST implement all of it, and MUST pass its cases: in `v2.json`,
`bindMcpCall` and `bindResult`; in `v3.json`, the `recordedLocalStep` section. These are the cases whose replay
needs profile code. Every `verify` case is replayable by an HTTP-only implementation, since a route and a receiver
are opaque strings there. Three offline results belong to the profile alone
(`PROOF_MISMATCH`, `RULES_MISMATCH` and `VERDICT_MISMATCH`, [verification.md](verification.md#reason-codes)). Each
passage of the spec that belongs to it says so and links here.

### The HTTP rules in http-v3.json

`http-v3.json`'s `rules` holds the rules the spec sets for v3 over HTTP that the rest of the file does not reach:
how a receiver reads a request, who attests, the peer a certificate names, the partner's sessions and handshake
endpoint, the egress, what a response adds to the caller's influence, refusals and trusted records. Each case is
replayed through functions that take a request as it arrived, with no web framework, so nothing in the file is a
framework's choice. Its `about` says how its keys, material, trees and handshake nonces are derived, so the file
can be rebuilt byte for byte. Bodies and certificates are hex, headers are their values as sent, and every
expected refusal's `body` is its exact bytes, `{"reason":"<code>"}`. The functions that answer return the status and
the body only, so the file does not carry the header: every refusal, and every `refusals` and `boundaryRefusals` case
among them, is sent with `Content-Type: application/json` and no parameters ([verification.md](verification.md#modes-and-refusals)).

| Kind | Shape | What it pins |
|---|---|---|
| `requests` | receiver | A request at the receiver ([verification.md](verification.md#http-requests-and-responses)): the nonce key `<rid>\|<last svc>\|req`, which other directions' and hops' keys do not spend, and each unreadable header: a chain (`CHAIN_MISSING`), a proof (no proof, so `PATH_NOT_ALLOWED`) and influence (`INFLUENCE_MISMATCH`). |
| `unreadableInfluence` | receiver | Influence that does not parse is never dropped: `403` where verification refuses first, otherwise `400 INFLUENCE_MISMATCH`, in audit mode too, at a service that verifies only to attest and at one with no verifier; an origin carries none, so has none to drop ([verification.md](verification.md#modes-and-refusals)). |
| `attestation` | receiver | Who attests: only a chain that passed the live order at that service, whether or not it verifies requests under a mode; never a refusal, an audit failure, a forged or unsigned chain, a service with no verifier, a hop that is off, or an origin. |
| `peerCertificates` | table | The peer under mTLS: `svc` is the subject's one common name, a UTF8String or PrintableString, read as encoded and compared as it is, else `""`; `inst` is the address the connection came from. |
| `sessionHeader` | partner | `X-Path-Session` ([sessions-and-influence.md](sessions-and-influence.md#over-http)): no header is an unsafe session that believes nothing; an id is the call's only when the same issuer and name opened it, so an unknown id, another peer's, the same name under another issuer, no certificate, one naming no single service and a stamp made in another session are `SESSION_UNKNOWN`. |
| `sessionRegistry` | partner | Sessions by id: a handshake replaces none, a peer holds at most N and loses its least recently used, replicas sharing a certificate are one peer, another peer's handshakes evict none, a session idle for the idle period expires and a call starts that period again, and a handshake that opens no session changes none. |
| `unsafeOperations` | table | An operation is `<METHOD> <route pattern>` by the dispatched handler's pattern, and a `HEAD` is refused wherever its `GET` is. |
| `handshakeErrors` | partner | The handshake endpoint: `INVALID_PARAMS` for a body that is not JSON or not a readable request (a `null` window included), `NO_SESSION` for one that opens none (a 15-byte nonce, a 63-byte root signature) and for no client certificate or one naming no single service; and a request that opens an attested and an unsafe session. |
| `egress` | egress | The egress's steps 1 to 7 ([sessions-and-influence.md](sessions-and-influence.md#between-organisations)): nothing sent, the handshake included, unless the chain passed the live order there; one boundary stamp and no internal one; blinded influence and the boundary route's proof; nothing but the session id in an unsafe session; the replacement after a 404 or a reply under another key, unsafe whatever it says, and a call that fails when the replacement is answered 404 too; each reply recorded as one `local-untrusted` entry; and a session dropped after `SESSION_UNKNOWN`. |
| `callerInfluence` | caller | A response at the caller: each label of a response that verifies becomes an entry with `src` `http:<target>` and `h` the result hash, the target the receiver's policy name; any other response adds exactly one `local-untrusted` entry. |
| `sessionExpiry` | partner | A session's calls are `POLICY_EXPIRED` once the client's root or keyring passes its `notAfter`, and verify at it; a handshake after it is unsafe; and a partner whose own material lapses opens new sessions unsafe and keeps verifying the earlier ones ([sessions-and-influence.md](sessions-and-influence.md#status)). |
| `refusals` | receiver | What a refusal carries, in a mesh: the code alone, even where the result names a suspect. |
| `boundaryRefusals` | partner | The same at the boundary: the partner's refusals, unreadable influence included (a partner has no audit mode), and an unsafe session's switched-off operations refused `UNSAFE_SESSION`, with no session header too. |
| `trustedRecord` | receiver | Trusted records ([sessions-and-influence.md](sessions-and-influence.md#trusted-records)): a verified chain and no `third-party` or `local-untrusted` content, counting what the handler reads; `private`, `public` and owners do not count. The partner kinds' `trustedRecord` covers a call in an unsafe session. |

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
`pinned`, `clientOrigins`, the operations it has switched off for unsafe sessions, `maxSessionsPerPeer`,
`sessionIdleMs`, its windows and the clock's `start`), its clock at each step's `at`. A peer is one of `peers`, a
client `certificate` and the `remoteAddr` it connected from, read as `peerCertificates` reads one, with its issuer
for the session's binding; null is no client certificate. A `handshake` posts the request `handshakes` names, or
`body`; `as` names the session it opens, since the partner chooses the id. It expects the `status`, the `error` of
a `400`, and the reply's `sessionStatus` and `disabled` of a `200`. A `call` names its session as
`{"of": <as>}`, `{"id": <literal id>}`, or null for no `X-Path-Session`. Its `stamp`, when present, is a
boundary stamp signed with `key` as the step runs, in the session its `sess` names, binding the call's method,
its target and the stamp's own `body`, and committing to the stamp's `influence`; `proofHeader` and
`influenceHeader` go as given. `routePattern` is the pattern of the handler the call reaches, which an unsafe
session's switched-off operations are matched against. It expects the `refusal`, whether the call is `attested`,
the `influence` the handler starts from, and `trustedRecord`.

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

Some rules are the Java SDK's own and are tested in `paztport-http` rather than pinned: the startup checks of a
partner's and an egress's own material, the 256 KiB limit on a handshake body, clearing a session after
`POLICY_EXPIRED`, the egress's own idle period, and the egress labelling its own response to its caller
`local-untrusted`, since a handler may relay what the partner said.

Cases may be added at any time. A recorded answer changes only with a protocol change.
