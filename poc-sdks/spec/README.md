# Paztport protocol spec

This is the written Paztport protocol, for anyone implementing it in a new language. It gives every value
exactly: the byte layouts, field orders, prefixes, constants, the order of the checks and the code each check
fails with. Where it explains a rule, it says why in a clause.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

| File | What it holds |
|---|---|
| [wire.md](wire.md) | Encodings, how JSON is read and written, keys and files, stamps and their signed bytes, chains and receivers, the blocks that carry extensions' claims and the commitment to them, every binding, how a chain and its blocks are carried, the Merkle tree, routes, operations, the signed root, the signed keyring, the reply certificate, events, proof bundles and who holds what. |
| [verification.md](verification.md) | The live order of checks, checks 9a to 9c on the blocks, freshness and nonce keys, the receiver and peer checks, attribution, the MCP wrappers, HTTP requests and responses, the two modes and what a refusal carries, offline verification, the reason codes, receiving an event, and guidance for a responder. |
| [sessions.md](sessions.md) | Sessions, a profile: the handshake over MCP and over HTTP, the extensions a server's reply says it acts on, the session id, status and unsafe sessions, the server's decision, recorded handshakes, and the boundary attestation between organisations. |
| [influence.md](influence.md) | The extension `influence`: where it applies and what it does not cover, its classes, entries and content labels, the every-stamp rule, the owner-aware rule, trusted records, influence over MCP, and blinded influence at the boundary. |
| [vectors/](vectors) | The conformance vectors. |

## The protocol

The protocol is version 4: a stamp carries `"v": 4`, and signs the bytes of `"paztport-stamp\n"` then the JCS bytes
of the stamp without its `sig` ([wire.md](wire.md#fields-and-signed-bytes)). Versions 1 to 3 were earlier
revisions, and a verifier takes none of them. It travels over MCP and over HTTP; which SDK speaks which version is
under [Conformance](#conformance).

The **core** attests the path a request took: stamps and the chains they form, routes and the operations on them,
freshness, the binding of each stamp to what its hop sent and to the hop it was handed to, and replay. A
**profile** is a way of using the core that puts no claim of its own in the block slot extensions travel in: sessions
([sessions.md](sessions.md)), MCP ([the MCP profile](#the-mcp-profile)), response attestation, the responder of
events ([verification.md](verification.md#receiving-an-event)) and offline verification
([verification.md](verification.md#offline-verification)). An **extension** is a named kind of claim that a hop
attaches at its own point on the path, in a [block](wire.md#blocks) its stamp's `ext` commits to; the core
guarantees who made the claim and that it arrived intact, and never reads it. One extension exists, `influence`
([influence.md](influence.md)): a record of what content the context held when an action was decided. It guards a
component that can be steered by what it reads, a model, so it is for systems with a model in them; a mesh of
ordinary services runs the core alone.

Design choices:

- **The receiver check.** Every stamp names the hop it was handed to (`rcv`). A live call or chain stamped for a
  different receiver is `BINDING_MISMATCH`, found by [check 4](verification.md#the-live-order) once every
  signature and link holds, not a route failure later. So a chain forwarded unchanged does not blame its last
  signer.
- **Operations.** Over HTTP a receiver may name its operations, the handlers a request can run, so a policy can
  allow a route through one operation of a service and not another. The caller names the operation in `rcv`
  (`payment#charge`); the receiver works out its own from its routing, never from the request, and a chain naming
  another fails check 4, `BINDING_MISMATCH` ([wire.md](wire.md#operations)). An operation's table entry may declare a
  key, the path segment or query parameter that names the item a call acts on; a caller then calls it once per
  request tree for each item, not once.
- **One version.** A verifier, live or offline, takes only stamps whose `v` is 4. A chain holding any other `v`
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
  (`PEER_MISMATCH`) before the nonce key is recorded, so a request sent again by another peer spends nothing, and
  names the peer in every result but `POLICY_EXPIRED`.
- **Extensions.** A hop's claims are pinned to its own stamp: each stamp's `ext` commits to its signer's block, so
  a later hop cannot drop or alter a claim without failing [check 9a](verification.md#the-live-order) at every
  honest hop after it. A verifier that acts on no extension reads no item, and `influence`, with its owner-aware
  rule for public writes, is an extension, not part of the core.

## Conformance

The spec describes version 4. The TypeScript SDK speaks it over MCP, and `v4.json` records it. Java's `paztport-core`
speaks it too, and Java's `paztport-http` speaks it over HTTP, which `http-v4.json` records. The Go SDK's core (every package
but `paztporthttp` and its two packages) speaks it too, but for the MCP profile. Go's `paztporthttp` packages are between
versions: they stamp version 4 through the core, keep version 3's HTTP behaviour behind stopgaps, and their tests, which
replay `http-v3.json`, do not pass until the next plan. `v3.json` and `http-v3.json` record version 3: where those two files differ from
the four spec files above, they describe version 3, and the spec files give version 4. No SDK replays `v3.json` any
more; it stays, frozen, until the close.

`vectors/` holds language-neutral vectors, so every implementation of a version is held to one set of recorded
answers.

| File | Covers | Replayed by |
|---|---|---|
| [`v4.json`](#v4json) | Version 4: stamps and blocks, the live and offline verifiers and sessions, the [MCP profile](#the-mcp-profile), and the extension `influence` in its member `influence` | Written and replayed by TypeScript (`@paztport/core` for the session id, the prompt and response bindings, the block commitment and the Merkle tree, and `@paztport/mcp` for the rest). Replayed by Java (`paztport-core`) and by Go (`poc-sdks/go`, its core) for every section but the MCP profile's, `influence.response` and the `influence.request` cases whose `served` is not empty. |
| [`v3.json`](#v3json) | Version 3: stamps, the live and offline verifiers, influence and sessions | No SDK: Go's core moved to version 4 and replays `v4.json`, and the file stays, frozen, until the close. Go's `paztporthttp` tests still read its policies, which `http-v3.json`'s cases name, until the next plan. TypeScript's replay of `v4.json` reads it only to compare the sections version 4 left as they were ([below](#v4json)). |
| [`http-v4.json`](#http-v4json) | Version 4 over HTTP | Written and replayed by Java (`paztport-http`), every section, and by Go's core for `operations` but its `receive` cases, and `boundaryInfluence`. Go's `paztporthttp` tests replay `http-v3.json` until the next plan moves them to version 4. The TypeScript SDK does not speak HTTP and does not replay it. |
| [`http-v3.json`](#http-v3json) | Version 3 over HTTP | Go's `paztporthttp` tests (`poc-sdks/go`), every section, until the next plan moves them to version 4; they do not pass until then. Java does not replay it, and the TypeScript SDK does not speak HTTP. |
| [`events.json`](#eventsjson) | Responder events | Written and replayed by Java (`paztport-core`), and replayed by TypeScript (`@paztport/core`) and Go (`poc-sdks/go`). |
| [`json.json`](#jsonjson) | Reading and writing JSON ([wire.md](wire.md#json)) | TypeScript (`@paztport/core`, and `@paztport/mcp` for `toolsCall`), every section but the `http` cases of `bindings`, and Java (`paztport-core`, and `paztport-http` for `http`) and Go (`poc-sdks/go`) for every section but `jcs` and the MCP profile's `bindings` (`toolsCall`, `result`, `localTool`), which belong to the [MCP profile](#the-mcp-profile); Go replays the `http` bindings only in `paztporthttp/wire`, whose tests do not pass until the next plan. |
| [`ed25519.json`](#ed25519json) | The [signature rule](wire.md#signatures) | Written by a generator in `@paztport/core`'s tests, and replayed in full by TypeScript (`@paztport/core`), Java (`paztport-core`) and Go (`poc-sdks/go`). |

| Part | Java SDK | TypeScript SDK | Go SDK |
|---|---|---|---|
| v4: stamps and blocks, the live and offline verifiers and sessions | core | yes | core |
| v4 over MCP ([the MCP profile](#the-mcp-profile)) | no | yes | no |
| Local steps ([the MCP profile](#the-mcp-profile)) | no | yes | no |
| The extension `influence` in v4 (`v4.json`'s `influence`) | core | yes | core |
| v3: stamps, the live and offline verifiers, influence and sessions | no | no | no |
| v4 over HTTP | yes | no | no: between versions until the next plan (the core replays `operations` but its `receive` cases, and `boundaryInfluence`) |
| v3 over HTTP | no | no | no: between versions until the next plan |
| Operations over HTTP: reading tables, naming operations and their keys | yes | no | yes |
| Operations over HTTP: confirming them from the receiver's routing | yes | no | no |
| Responder events | yes | yes | yes |
| Reading and writing JSON (`json.json`) | yes | yes | yes |
| The signature rule (`ed25519.json`) | yes | yes | yes |

A new implementation of version 4 MUST pass `ed25519.json`; `json.json` less `jcs` and the `toolsCall`, `result` and
`localTool` cases of `bindings` if it does not implement [the MCP profile](#the-mcp-profile), and less the `http` cases
of `bindings` if it does not speak HTTP; and `v4.json` less its member `influence` and, if it does not implement the MCP
profile, less that profile's sections: `recordedLocalStep`, `responseAttestation`, `sessionParams`, `sessionResult`,
`bindMcpCall` and `bindResult`. Outside `influence`, only `recordedLocalStep` needs an extension's rules: the other
sections that hold blocks use made-up extensions, `example` among them, and name `influence` only as an opaque name, so
an implementation with no extension's rules passes them, since the core never reads an item, and a `responseAttestation`
case expects the core's reason alone. An implementation that acts on `influence` MUST also pass `influence`'s `entries`,
`labels`, `rule` and `recordedCall`, and the `request` cases whose `served` is empty, which are the extension's alone.
`influence.response`, and the `request` cases whose `served` is not empty, record the extension over MCP: what a client
adds for a response whose every stamp is the server's, and what a server decides with the classes it served in its
session. They belong to the MCP profile as well as to the extension, and an implementation MUST pass them if it acts on
`influence` and implements the MCP profile. One that implements the MCP profile acts on `influence`, since its local
steps do: a recorded local step's check reads the entries in its blocks, and derives the gate's verdict again under
their classes ([verification.md](verification.md#offline-verification), [influence.md](influence.md#over-mcp)). So it
passes all of `influence`. It MUST pass `events.json` if it sends or receives responder events, and `http-v4.json` if it
speaks version 4 over HTTP, less `operations` if it does not name operations and less the extension's cases if it does
not act on `influence`.

In `http-v4.json` the extension's cases are `boundaryInfluence` and every case of `rules` whose `actsOn` names
`influence`, a partner's or an egress's own for those kinds: a service that acts on `influence` reads each item it is
handed under that name ([influence.md](influence.md#entries)), and its answers hold what the extension decides,
`publicWrite`, `trustedRecord` and influence entries. They are all of `callerInfluence`, `trustedRecord` and
`partnerTrustedRecord`, every `influenceItems` case but one, every case of the partner and egress kinds but two, and
every case of `requests`, `servedUnverified`, `attestation` and `refusals` but nine. `responses` names `influence` only
as an opaque name, in its blocks and in the verifier's `actsOn`, as `v4.json`'s `verify` does, so an implementation with
no extension's rules passes it, since the core never reads an item.
So an implementation that does not act on `influence` is held today to `resultHash`, `requestBinding`, `headerNames`,
`responses`, `operations`, whose `receive` cases act on nothing, `rules`' `peerCertificates` and `unsafeEndpoints`,
which hold no extension, and the twelve cases of `rules` whose `actsOn` is empty: `influenceItems`' "enforce, at a
service that does not act on influence", `handshakeErrors`' "a partner that acts on no extension lists none",
`egress`' "an egress that does not act on influence: the block names nothing", less its `added`, the influence entry
that egress records for the partner's reply, and the nine receiver cases whose names end "at a service that acts on no
extension", three of `requests`, four of `servedUnverified`, one of `attestation` and one of `refusals`, which hold
the core's receiver rules at a service that acts on nothing. The file has no case yet that acts on nothing for a
partner's calls. An implementation that acts on `influence` MUST pass the extension's cases too.

An implementation of version 3 MUST pass `ed25519.json`, and `v3.json` and `json.json`
less their sections that belong to the MCP profile if it does not implement it: `recordedLocalStep`,
`responseAttestation`, `sessionParams`, `sessionResult`, `bindMcpCall` and `bindResult` in `v3.json`, and `jcs` and
the `toolsCall`, `result` and `localTool` cases of `bindings` in `json.json`. It MUST pass `http-v3.json`, and the
`http` cases of `bindings` in `json.json`, if it speaks v3 over HTTP, less `operations` if it does not name
operations, and `events.json` if it sends or receives responder events.

`v4.json` and `v3.json` are self-contained: every case carries its inputs, and keys and policies are named and defined
in the file. Each file's `about` field says how its keys, leaf salts and padding are derived, and `v4.json`'s also how
each policy's `rootId` and each handshake nonce are (`v3.json`'s gives the `rootId` of `mesh-second` alone, and holds
the others and its nonces as values), so either file can be rebuilt byte for byte; a verify case runs the live verifier
`uses` times against one nonce cache, and the last result is the one expected. An offline case runs the offline verifier
once, with no peer, clock or nonce TTL: `recordedTs.last` is the recorded time of the last stamp, and `seen` is the set
of nonce keys already spent in the record set. A verify or offline case may pin several keyrings and roots: `keyrings`,
in place of `keyring`, is a list of `{keyring, notAfter}`, and `roots` a list of `{policy, notAfter}`, whose roots the
verifier pins; `policy` then names only where the case's proof comes from. A case's one `keyring`, or `policy`'s root
when it has no `roots`, is a single member whose window is the case's `policyNotAfter` in a verify case and none in an
offline case, and two `roots` naming one policy are its root and a renewal of it. A verify case's members each have a
`notAfter`, and its `policyNotAfter` is the earlier of the latest `notAfter` among its keyrings and the latest among its
roots (with one of each, the earlier of the two). An offline member with no `notAfter` has no window. A `keyring`,
`root` or `replyCert` case's `signingBytes` is null when its `file` does not read: a reader refuses it, it never
verifies, and its signature is never consulted. `current`, when present, gives whether it is valid at each `at`.

A case carries an object it says was received as a token, beside the object's readable value, and a replay reads
only the token. Each `verify` and `offline` case, each call of a `recordedCall` case and each `recordedLocalStep`
case's `step` carries `chainToken` beside `chain`, and the token of its blocks beside their readable value:
`blocksToken` beside `blocks` in `v4.json`, and `influenceToken` beside `influence` in `v3.json`. A
`recordedLocalStep` step also carries `decisionToken`, the token of its `callId`, `resolved`, `verdict`,
`routeAllowed` and `rulesHash` together, and each policy carries its proofs' tokens once, as `proofTokens.<route>`
beside `proofs`, for every case that names the route. A token is the base64url of its value's JCS bytes, except in
the `verify` case "stamp ts of -2^63", whose chain token spells the `ts` exactly as the readable chain does, a
number JCS cannot write, and in `v4.json`'s `verify` case "a blocks token that does not read". Each
`responseAttestation` case carries `attestationToken` beside `attestation`, the token of its readable value except
in one case of each file, whose token writes the members out of JCS order: `v4.json`'s "an attestation whose
members are not in JCS order", as `chain`, `proof`, `blocks`, `resultHash`, and `v3.json`'s "an attestation in wire
member order", as `chain`, `proof`, `labels`, `resultHash`. Each `sessionReply` case, and each handshake of a
`recordedHandshake` or `recordedCall` case, carries `requestToken` beside `request` and `replyToken` beside `reply`,
and each `sessionStatus` and `sessionRequest` case `requestToken` beside `request`. A `sessionParams` or
`sessionResult` case is the params or result as received, whose `request` or `reply` is the token itself.

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
  ([sessions.md](sessions.md#recorded-handshakes)): `request` and `reply` as
  recorded, read from `requestToken` and `replyToken`, `pin` (the server policy key the client pinned, by name in
  `keys`) and `serverEntry` (the server's entry service from the verifier's own configuration).
  `expected.attestedAt[i]` is whether it opened an attested session judged at `at[i]`, `attested` whether it did at
  all (judged at the earliest of its limits), `responseNotAfter` the `policyNotAfter` a response recorded in it is
  checked with (the server root's `notAfter`, or in the entry-key form the earlier of it and
  `serverKeyringNotAfter`), read from the reply's windows once the signatures covering them verify, whether or not
  the session is attested, and `null` otherwise.
  A recorded `request` may hold material a reader refuses as malformed (no `clientKeyringSig`, no
  `clientKeyringNotAfter`, or a client root without `notAfter`): the session it opened is never attested.
- A **`recordedCall`** case is one record set: `handshakes` in the `recordedHandshake` shape, then `calls`, checked in
  order against one set of spent nonce keys that starts empty. Each call names the handshake whose session it was made
  in by its index, `handshake`, and carries an offline case's chain inputs (`chain`, `expectedBind`, its blocks,
  `proofRoute` in `policy`, `receiver`, `receiverInRoute`, `nonceKey`, `rid`, `recordedTs`, `prompt`). It is checked by
  the offline verifier with the case's `allowedOrigins`, `callMaxAgeMs` and `runMaxAgeMs`, the client keyring and root
  of that handshake's request and the session id of its reply; then a call that verifies but whose `recordedTs.last` is
  past one of the session's limits is `OUTSIDE_SESSION`. `expected[i]` is an object holding the `reason` for `calls[i]`.
  Every handshake here is attested: the spec gives a call relying on one that is not no result.
- A **`recordedLocalStep`** case ([MCP profile](#the-mcp-profile)) is a recorded local step: `step` (`tool`,
  `callId`, `rid`, `now`, `input`, `resolved`, `verdict`, `routeAllowed`, `rulesHash`, `decisionToken`, `chain`,
  `proofRoute` and its blocks), the `client` it is checked against (`keyring` by name, the root of `policy`, in which
  `proofRoute` names the step's proof, the root's and keyring's windows `rootNotAfter` and `keyringNotAfter`, and
  `rules`), the `signers` (`svcs`, the origin service then the client hop, and their one `inst`), its `run`
  (`prompt` and start times `ts`), and `seen`, the nonce keys already spent. `expected` is the `reason`, the
  `verdict` the step signed when the record verifies (null when it does not).
- A **`responseAttestation`** case ([MCP profile](#the-mcp-profile)) is a response as a client receives it: the
  `attestationToken` of the `paztport/attestation` value (its readable value is `attestation`), the `result` it
  answers, the `call` (`rid`, `callId`, `receiver`), and the `server` the stamps are checked against (`keyring`
  by name, the root of `policy`, `allowedOrigins`, `sess`, `policyNotAfter` and `nonceTtlMs`). The client checks it
  once at `now`, as [a response on the client](verification.md#the-mcp-server-and-client) does, and `expected` is
  the `reason`.
- A **`sessionParams`** case ([MCP profile](#the-mcp-profile)) is `paztport/session`'s `params` as a server receives
  them, read as [the handshake](sessions.md#the-handshake) says: `expected` is `OK` when they are a
  `request` token that reads as a request, with or without `_meta`, and `INVALID_PARAMS` (JSON-RPC `-32602`)
  otherwise.
- A **`sessionResult`** case ([MCP profile](#the-mcp-profile)) is `paztport/session`'s `result` as a client receives
  it: `expected` is `OK` when it is a `reply` token, with or without `_meta`, that reads as a reply, and
  `MALFORMED_REPLY` otherwise. Its `OK` cases carry the reply of the `sessionReply` case "entry-key form attested",
  whose check that section pins.

### v4.json

`v4.json` records version 4. It is written by TypeScript's exporter,
`poc-sdks/typescript/mcp/test/vectors-v4-export.ts`, and TypeScript's replay checks that the committed file is byte for
byte what the exporter writes. Its `keys` and `policies`, and the sections version 4 left as they were (`keyring`,
`root`, `replyCert`, `sessionStatus`, `sessionRequest`, `sessionParams`, `fixedInputs`, `deriveSessionId`, `bindPrompt`,
`bindMcpCall`, `bindResult`, `merkle`, and `influence.rule`, which is `v3.json`'s `rule`), are `v3.json`'s value for
value, and the replay checks that too: the seed strings its `about` names still say `v3` for that reason. To regenerate
the file:

```bash
cd poc-sdks/typescript && node mcp/test/vectors-v4-export.ts --write
```

- `blocks`: `read`, tokens read as a request's blocks, and `commit`, a block's JCS text and its stamp's `ext`
  ([wire.md](wire.md#blocks) lists the cases).
- `signingBytes` and `signatures`: version 4 signed bytes and signatures.
- `keyring`, `root` and `replyCert`: as in `v3.json` ([below](#v3json)).
- `verify`: live verify cases. As in `v3.json`: each kind of receiver; operations named in `rcv` (a route through them,
  a chain naming another operation, a receiver naming none, an inner `rcv` naming another service's operation, an empty
  operation, an inner operation holding a `/` or a `#`, and a proof for another operation's route); malformed `rcv`
  fields; a bad signature found before a bad receiver; the peer and attribution; replay; an origin not allowed, a stamp
  linked to another origin, a stamp with another `rid` and one from another session; the pinned policy's window; a stamp
  `ts` of −2^63, written exactly; and several pinned keyrings and roots. New or changed in version 4: a stamp whose `v`
  is 3 and one with `infl` in place of `ext`; an inner operation holding a `|`, `BINDING_MISMATCH` as for a `/` or a
  `#`; a `|` in `rid` and `inst`, which verifies, and in a service name, which has no key; a wrong peer found before an
  unproven route, which `v3.json`'s case of the same inputs found after it; an item altered, in place of an altered
  owner; the last stamp the call window before `now` and 1 ms more, and 1 ms more than the call window after it, and the
  origin the run's lifetime before `now` and the call window after it, and 1 ms more than each; a call id holding a
  noncharacter; the blocks: no token, an array of empty blocks, a token holding `null`, no token where a stamp commits
  to a block, an `ext` that is the hash of the empty block, one block too few, one too many and one for two stamps, two
  blocks swapped, a token that does not read and a block with a member blocks do not have; a name the allowed list does
  not hold, in `items` and only in the first block's `requires`, and the same name with no list; the caller's `requires`
  of an extension the receiver does not act on, and an earlier block's; `constructor` required, acted on where no block
  lists it, listed, and listed where the allowed list does not hold it; a block that only requires an extension the
  receiver acts on, and one naming `example` and `influence` at a receiver acting on both; five cases that each fail two
  of checks 8 to 10, which give the earlier check's code; a request sent by another peer, then once and then twice by
  its signer; and a request with no proof sent twice.
- `offline`: offline cases (as in `v3.json`, with a stamp whose `v` is 3; and an item altered, a name the allowed
  list does not hold, the same name with no list, and a last block requiring an extension the verifier does not act
  on, which is `OK`, since check 9c is live only).
- `recordedHandshake`: recorded handshakes, as in `v3.json`, and a reply without `extensions`, which is not
  attested, and one listing an extension, judged with no requirement, since step 5 is live only.
- `recordedCall`: recorded calls, as in `v3.json`.
- `recordedLocalStep`: recorded local steps ([MCP profile](#the-mcp-profile): as in `v3.json`; a block altered; an
  `influence` item that is not an entry, in the client hop's block, in the origin's, under an expired root, in an
  unlisted step, and beside a bad signature, which is found first; and a write into a public folder under untrusted
  and private entries, signed as refused and signed as allowed, with no entries, and with a private entry in the
  origin's block and the hop's block empty, signed as allowed and as refused, which the owner-aware rule alone
  decides).
- `responseAttestation`: response attestations ([MCP profile](#the-mcp-profile): an attested response; an
  attestation with a member it does not have, with `labels` in place of `blocks`, with no `blocks` or a `null` one
  while every `ext` is empty, with a `blocks` that is not an array of blocks, and with its members out of JCS order,
  none of which reads; one block for two stamps, and a block altered; a first stamp whose `rid` is not the call's,
  found before the chain is checked; a result hash for another result; a name the client's allowed list does not
  hold; the last block requiring an extension the client does not act on, and the first; and a call id holding a
  noncharacter).
- `sessionParams` and `sessionResult`: `paztport/session`'s params and result ([MCP profile](#the-mcp-profile)), as
  in `v3.json`.
- `sessionReply` and `sessionRequirement`: the client's check of a reply, and what a client that requires
  extensions may do after it ([sessions.md](sessions.md#the-clients-check-of-the-reply) lists the cases).
- `sessionStatus` and `sessionRequest`: as in `v3.json`.
- `fixedInputs`, `deriveSessionId`, `bindPrompt`, `bindResponse`, `merkle`, `bindMcpCall` and `bindResult`: the
  primitives the cases above rely on: the session id, the prompt and response bindings, the Merkle tree, and the
  MCP profile's `tools/call` and result bindings.
- `influence`: the extension's own sections, each cited where [influence.md](influence.md) states its rule:
  `entries` and `labels`, whether an item reads as an entry or a label; `rule`, the owner-aware rule's truth table;
  `request`, what an attested MCP server that acts on `influence` decides from the items handed on; `response`,
  the entries a client that acts on it adds for a response over MCP; and `recordedCall`, recorded calls at a verifier
  that acts on it. `response`, and the `request` cases whose `served` is not empty, belong to the MCP profile as well
  ([Conformance](#conformance)).

Beside the form above, `v4.json` carries these members. `blocks` is null where `blocksToken` is null (no token received,
which is one empty block per stamp), and in the two `verify` cases whose token does not read as an array: "a blocks
token holding null, every ext empty", whose token is the JCS of `null`, and "a blocks token that does not read". A
`responseAttestation` case's attestation holds one block per stamp of the response chain unless its name says otherwise.
On each `verify`, `offline`, `recordedCall` and `responseAttestation` case, `actsOn` is the extensions the verifier acts
on, and `allowedExtensions` the names it carries, null for unset, which carries any name. A `verify` or `offline` case's
`expected` is `{reason, suspectSvc, suspectInst, handOver}`: `handOver` is null unless the reason is `OK`, and then has
one member per name in `actsOn`, each an array of `{svc, items}`, one per stamp in chain order, with `items` null where
the stamp's block does not name the extension. A `verify` case may have `peers` in place of `peer`: use `i` is sent by
`peers[i]`, null for no peer. A nonce key, in `nonceKey` and `seen`, is the JCS text of its array of strings
([verification.md](verification.md#freshness-and-replay)); the `verify` case "a call id holding a noncharacter"'s
`nonceKey`, and the `responseAttestation` case of that name's `call.callId`, hold U+FFFF written as itself, as
`json.json` does, so a replay reads the file's own structure with any JSON reader, and only the tokens with the reader
under test. A `sessionReply` case's `requires`, `[]` when absent, is what the client requires of the server. A
`recordedLocalStep` step's blocks are, unless the case's name says otherwise, the origin's, naming `influence` with
`[]`, and the client hop's, holding the session's entries. The file's `about` gives the shape of `sessionRequirement`
and of each section of `influence`.

### v3.json

`v3.json` records version 3, which the Go SDK implemented until its core moved to version 4. Its exporter left the repository when the
TypeScript SDK moved to version 4.

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
  `v` is not 3, malformed `rcv` fields, the check order, the peer and attribution, replay, an altered owner, an
  origin not allowed, a stamp linked to another origin, a stamp with another `rid` and one from another session, and
  the pinned policy's window: at it, past it, out of range, and past it before a bad signature or a malformed chain,
  and a stamp `ts` of −2^63, written exactly, and several pinned keyrings and roots: a proof under the second root,
  a `rootId` pinned nowhere, a rotated key only in the second keyring, a chain whose keys come from two keyrings, a
  proof under an expired root and one under a renewal of it, a key only in an expired keyring, every keyring or
  every root expired, and a proof relabelled with the other root's `rootId`).
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

### http-v4.json

`http-v4.json` records version 4 over HTTP. It is written by Java's exporter,
`poc-sdks/java/http/src/test/java/org/paztport/http/VectorsHttpV4Export.java`, and Java's replay checks that the
committed file is byte for byte what the exporter writes.

- `resultHash`: the HTTP result hash.
- `requestBinding`: the request binding with and without a query.
- `headerNames`: Paztport's header names (a name and whether it begins with `X-Path-`, ASCII letters in any case,
  lookalikes refused; `X-Path-Extensions` among them, and `X-Path-Influence`, which version 3 used, still Paztport's
  by its prefix).
- `responses`: response checks (a good response, one sent to the wrong receiver, a block other than the one its stamp
  commits to, an altered status, a replay and one past the verifier's `policyNotAfter`; a block naming `influence`
  with a label, and that block altered; a header without `block`, one in version 3's shape and one with a member
  beside `block` and `stamp`, each `CHAIN_MISSING`; a last block requiring `influence`, at a caller that does not act
  on it and at one that does; a response on a route through operations, which another operation's spent response key
  does not refuse and its own does; and responses from a keyed operation, which another item's spent response key
  does not refuse and its own does).
- `boundaryInfluence`: blinded boundary influence (the salts, the sent entries, and an opening that opens and one
  with an extra original that does not).
- `rules`: the HTTP rules a receiver, a caller, a partner and an egress follow
  ([below](#the-http-rules-in-http-v4json)).
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

It reuses `v4.json`'s keys and its `mesh` and `ops` policies by name, and adds a `payment` key derived by `v4.json`'s
rule; `rules` adds keys and material of its own, derived the same way. Its seed strings are `http-v3.json`'s, so its
keys, its `boundaryInfluence`, and the keys, material, handshakes and peers of `rules` are `http-v3.json`'s value for
value, and so are `resultHash`, `requestBinding` and `operations` but `receive`, whose rules did not change;
`headerNames` holds each of `http-v3.json`'s cases. Its `about` says so. To regenerate the file:

```bash
cd poc-sdks/java && mvn -q -pl core,http test -Dtest=VectorsHttpV4Export -Dpaztport.exportHttpVectors=true \
  -Dvectors.out="$PWD/../spec/vectors/http-v4.json" -Dsurefire.failIfNoSpecifiedTests=false
```

### http-v3.json

`http-v3.json` records version 3 over HTTP, which Go's `paztporthttp` tests replay until the next plan. Its exporter left
the repository when Java's `paztport-http` moved to version 4; its `about` still names Java as its writer.

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
- `rules`: the HTTP rules of version 3, in the kinds of `http-v4.json`'s `rules`
  ([below](#the-http-rules-in-http-v4json)) but with `unreadableInfluence` in place of `influenceItems` and no
  `servedUnverified`, each case in version 3's shape; `http-v4.json`'s `rules.about` says what changed.
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

Its keys, `payment-next` among them, are derived by the rule of `v3.json`'s and `v4.json`'s `about`.

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
- `bindings`: each binding ([wire.md](wire.md#bindings)) but the HTTP result, which hashes no string it is given, and
  the Merkle leaf ([wire.md](wire.md#the-merkle-tree)), each refusing a lone surrogate in one string it hashes (the
  prompt text, a response's `resultHash` or `toolCallId`, a `tools/call`'s tool, call id or argument, a result, a local
  tool's name or input, a Merkle leaf's route, an HTTP request's method or target). The two `response` cases also carry
  a `labels` input, from version 3's response binding, which a replay of version 4 ignores.

### ed25519.json

Cases of the [signature rule](wire.md#signatures), each `{name, publicKey, message, signature, valid}`. `publicKey`
is the base64url of the bytes handed to the verifier as a public key; some of them are not the Ed25519
SubjectPublicKeyInfo. `message` and `signature` are base64url, and `valid` is the rule's answer. A replay hands the
three to the implementation's verify and expects `valid`; a key the platform refuses to decode counts as not valid.
`smallOrderY` lists the five `y` that rule 4 refuses, each as its 32 little-endian bytes in hex, ascending as
numbers. The file's `about` says which of them the case names call `y8`.

- A signature by the key and one over the empty message, both valid, and a signature over another message, which
  rule 5 refuses.
- `S` plus `L`, and `S` with its top bit set (rule 2).
- `R` the identity, `R` the identity with the sign bit set, `R` of order 8 with `S` made for the cofactored
  equation, `A` the identity and of orders 2, 4 and 8, under each sign bit where `x` is not 0, and `A` the identity
  and of order 2 with the sign bit set (rule 4); and the identity written with `y = p + 1`, as `R` and as `A`, and
  `A` of order 4 written with `y = p` (rule 3).
- `R` and `A` each with a small-order part, which pass rules 1 to 4 and satisfy only the cofactored equation, so
  rule 5 alone refuses them; and `A` with a small-order part whose `k` is a multiple of 8, which satisfies both and
  is valid.
- A key whose `y` is on no curve point (rule 5's decoding).
- Signatures of 63 and 65 bytes, and keys of 31 bytes, under the X25519 identifier, with the SPKI length written in
  long form, with a trailing byte, and with a bit string that claims an unused bit (rule 1).

The cases were crafted, and every answer worked out, by RFC 8032 arithmetic written for the generator,
`poc-sdks/typescript/core/test/vectors-ed25519-export.ts`, which imports nothing but Node's `node:` modules, so no
SDK or library confirms its own answers. The generator checks every answer against its own reading of the whole
rule, and checks more of the cases built for one rule:

- `S` plus `L`, and every case of rules 3 and 4 but `R` of order 8, satisfy rule 5's equation once their encodings
  are read leniently, so the equation does not refuse them; rule 5's decoding refuses those written with `y` at or
  above `p` or with the sign bit set on `x = 0`, as rules 3 and 4 do.
- The keys with the length in long form, with a trailing byte and with an unused bit claimed carry the signer's
  key: written as the Ed25519 SubjectPublicKeyInfo, it passes rules 1 to 4, and the signature satisfies rule 5's
  equation under it.
- `R` of order 8 and the two cases with a small-order part that rule 5 refuses satisfy the cofactored equation and
  not rule 5's. Those two, and the key whose `y` is on no curve point, pass rules 1 to 4.
- The valid case with a small-order part has a `k` that is a multiple of 8 and a 64-byte digest that is not, so
  rule 5's equation with the digest left unreduced refuses it.

The other cases have only the first check; of those meant for one rule, `S` with its top bit set is also refused by
rule 5's equation. The TypeScript replay checks that the committed file is what the generator writes, and that
the generator imports nothing else. Each SDK's replay also runs its bare library, with no check in front, and fails
if the library disagrees with the file on any case that rules 1 to 4 let through. To regenerate the file:

```bash
cd poc-sdks/typescript && node core/test/vectors-ed25519-export.ts --write
```

### The MCP profile

The MCP profile is the part of the protocol that only an MCP client and server speak: the `tools/call`, result and
local-tool [bindings](wire.md#bindings), the MCP tool call and response chains, and local steps (a client's own tool
calls, signed by the client alone, with their route, nonce key and recorded check). An implementation that speaks the
protocol over HTTP only need not implement the profile, and the HTTP rules never refer to it. An implementation that
claims the profile MUST implement all of it, and MUST pass its cases: the `bindMcpCall`, `bindResult`,
`recordedLocalStep`, `responseAttestation`, `sessionParams` and `sessionResult` sections of `v4.json` (and of `v3.json`
for version 3), and in `json.json`, the `jcs` section and the `toolsCall`, `result` and `localTool` cases of `bindings`.
These are the cases whose replay needs profile code. Its local steps act on the extension `influence`, so it passes
`v4.json`'s `influence` too ([Conformance](#conformance) says why). Every `verify` case is replayable by an HTTP-only
implementation, since a route and a receiver are opaque strings there. Three offline results belong to the profile alone
(`PROOF_MISMATCH`, `RULES_MISMATCH` and `VERDICT_MISMATCH`, [verification.md](verification.md#reason-codes)). Each
passage of the spec that belongs to it says so and links here.

### The HTTP rules in http-v4.json

`http-v4.json`'s `rules` holds the rules the spec sets for version 4 over HTTP that the rest of the file does not
reach: how a receiver reads a request and the items it is handed, check 9a at a service about to serve a request it
did not verify, who attests, the peer a certificate names, the partner's sessions and handshake endpoint, the egress,
what a response adds to the caller's influence, refusals and trusted records. Each case is replayed through functions
that take a request as it arrived, with no web framework, so nothing in the file is a framework's choice. Its `about`
says how its keys, material, trees and handshake nonces are derived, so the file can be rebuilt byte for byte. Bodies
and certificates are hex, headers are their values as sent, and every expected refusal's `body` is its exact bytes,
`{"reason":"<code>"}`. The functions that answer return the status and the body only, so the file does not carry the
header: every refusal, and every `refusals` and `boundaryRefusals` case among them, is sent with
`Content-Type: application/json` and no parameters ([verification.md](verification.md#modes-and-refusals)).

| Kind | Shape | What it pins |
|---|---|---|
| `requests` | receiver | A request at the receiver ([verification.md](verification.md#http-requests-and-responses)): the nonce key `[rid, last svc, last rcv, "req"]`, which other directions', hops' and operations' keys do not spend, and each unreadable header: a chain (`CHAIN_MISSING`), a proof (no proof, so `PATH_NOT_ALLOWED`) and blocks (`EXTENSION_MISMATCH`), and no `X-Path-Extensions` where a stamp's `ext` is not `""` (`EXTENSION_MISMATCH`). |
| `influenceItems` | receiver | An item on a request's block that does not read as an entry, at a service that acts on `influence` ([influence.md](influence.md#entries)): `400 INFLUENCE_MISMATCH` in either mode, verified or not, at a service that verifies only to attest, at one with no verifier and at a hop that is off; `403` where verification refuses first; an origin carries none, so has none to read; and a service that does not act on `influence` reads no item and serves the request. |
| `servedUnverified` | receiver | Check 9a at a service about to serve a request it did not verify ([verification.md](verification.md#http-requests-and-responses)): in audit mode after a failure, blocks that do not match their stamps, none where a stamp's `ext` is not `""`, and blocks that do not decode or are JSON `null`, each `400 EXTENSION_MISMATCH`, and a block altered refused the same way at a service that verifies only to attest, at one with no verifier and at a hop that is off; blocks that match, served with their items handed on as not verified; where the chain did not read, blocks that read as an array served with nothing handed on, and an object refused; check 9c following the mode; and an origin, which carries no blocks. |
| `attestation` | receiver | Who attests: only a chain that passed the live order at that service, whether or not it verifies requests under a mode; never a refusal, an audit failure, a forged or unsigned chain, a service with no verifier or an origin. A hop that is off attests nothing either, which `trustedRecord`'s case "a hop that is off" records in its `attests`. |
| `peerCertificates` | table | The peer under mTLS: `svc` is the subject's one common name, a UTF8String or PrintableString, read as encoded and compared as it is, else `""`; `inst` is the address the connection came from. |
| `sessionHeader` | partner | `X-Path-Session` ([sessions.md](sessions.md#over-http)): no header is an unsafe session that believes nothing; an unsafe session applies no check to the blocks a call carries; an id is the call's only when the same issuer and name opened it, so an unknown id, another peer's, the same name under another issuer, no certificate, one naming no single service and a stamp made in another session are `SESSION_UNKNOWN`. |
| `sessionRegistry` | partner | Sessions by id: a handshake replaces none, a peer holds at most N and loses its least recently used, replicas sharing a certificate are one peer, another peer's handshakes evict none, a session idle for the idle period expires and a call starts that period again, and a handshake that opens no session changes none. |
| `unsafeEndpoints` | table | An endpoint is `<METHOD> <path pattern>` by the dispatched handler's pattern, and a `HEAD` is refused wherever its `GET` is. |
| `handshakeErrors` | partner | The handshake endpoint: `INVALID_PARAMS` for a body that is not JSON or not a readable request (a `null` or missing keyring window, a client root with no window, a keyring naming a service that is not a route node and a missing `clientKeyringSig` included, each body otherwise in JCS member order), `NO_SESSION` for one that opens none (a 15-byte nonce, a 63-byte root signature) and for no client certificate or one naming no single service; a request that opens an attested and an unsafe session; and the reply's `extensions`, empty from a partner that acts on none. |
| `egress` | egress | The egress's steps 1 to 7 ([sessions.md](sessions.md#between-organisations)): nothing sent, the handshake included, unless the chain passed the live order there; one boundary stamp and no internal one; blinded influence and the boundary route's proof; nothing but the session id in an unsafe session; the replacement after a 404 or a reply under another key, unsafe whatever it says, and a call that fails when the replacement is answered 404 too; each reply recorded as one `local-untrusted` entry; a session dropped after `SESSION_UNKNOWN`; the requirement: calls in an attested session whose reply lists every required name, each boundary block requiring them, and none after a reply that does not list one, which is not followed by the replacement, nor in an unsafe session or the replacement's; with the switch, calls after a reply that lists one of two required names, requiring that one, and in an unsafe session with nothing but the session id; and what the boundary block names ([influence.md](influence.md#blinded-influence)): `influence` with `[]` where every internal stamp names it and no influence is held, and nothing where one does not or the egress does not act on it. |
| `callerInfluence` | caller | A response at the caller ([influence.md](influence.md#content-labels)): each label of a response that verifies and names `influence` becomes an entry with `src` `http:<target>` and `h` the result hash, the target the receiver's policy name without any operation, also when the caller holds the receiver's table (the case's `operations`) and its stamp names one; a response that names `influence` with no label adds nothing; any other response adds exactly one `local-untrusted` entry, and one refused at check 9c is also `refused`. The cases with a table run on the `shop-operations` material, whose root covers `gateway/orders/payment#pay` and payment's table. |
| `sessionExpiry` | partner | A session's calls are `POLICY_EXPIRED` once the client's root or keyring passes its `notAfter`, and verify at it; a handshake after it is unsafe; and a partner whose own material lapses opens new sessions unsafe and keeps verifying the earlier ones ([sessions.md](sessions.md#status)). |
| `refusals` | receiver | What a refusal carries, in a mesh: the code alone, even where the result names a suspect. |
| `boundaryRefusals` | partner | The same at the boundary: the partner's refusals, a block other than its stamp commits to and blocks that cannot be read included (`EXTENSION_MISMATCH`: a partner has no audit mode), an item that is not an entry (`400 INFLUENCE_MISMATCH`), and an unsafe session's switched-off endpoints refused `UNSAFE_SESSION`, with no session header too. |
| `trustedRecord` | receiver | Trusted records ([influence.md](influence.md#trusted-records)): a verified chain every stamp of which names `influence`, and no `third-party` or `local-untrusted` content, counting what the handler reads; `private`, `public` and owners do not count. A guarded public write on a verified chain whose origin's block does not name `influence`, or is a pass-along block, is `INFLUENCE_DENIED` whatever the entries say ([influence.md](influence.md#the-every-stamp-rule)). The partner kinds' `trustedRecord` covers a call in an unsafe session, and `partnerTrustedRecord` the same rule at the boundary. |
| `partnerTrustedRecord` | partner | The same rule at the boundary: an attested call qualifies only with no `third-party` or `local-untrusted` content, counting what the handler reads, and a boundary block that names `influence`, with nothing included; `private`, `public` and owners do not count. And the owner-aware rule over the boundary block's entries ([influence.md](influence.md#blinded-influence)): a guarded public write from a call holding `third-party` content beside alice's private data is `INFLUENCE_DENIED` to bob's destination and `OK` to alice's. |

A **receiver** case enters `request` (`method`, `target`, `headers`, `body`) `uses` times at `service`: its `svc`
and `inst`, whether it is an `origin`, and whether it has a `verifier`, pinned to `material`. Every service holds
its stamp key, acts on the extensions in `actsOn` and carries the names in `allowedExtensions` (null for unset,
which carries any name). `mode` is the [mode](verification.md#modes-and-refusals) it verifies requests under,
`enforce` or `audit`; or `off`, which is no mode but a hop its deployment has switched Paztport off on; or null, a
service that verifies no requests and may still verify a chain to decide whether to attest. Each entry has `peer`,
or none, and one nonce cache that already holds the keys in `spent`; then the handler reads `read`. `expected` is the
last entry's answer: the `refusal`, or null; whether the chain `verified` at this hop (false for every refusal);
`handedOn`, what the service is handed, null for nothing, else one member per name in `actsOn`, each an array of
`{svc, items}`, one per stamp, `items` null where the stamp's block does not name the extension; whether the answer
`attests`; and, at a service that acts on `influence`, the reason a guarded public write to a destination whose owner
is `destinationOwner` gets (`publicWrite`) and whether a `trustedRecord` may be written from it. Both are null for a
refusal and at a service that does not act on `influence`. A null `request` is work outside any request, which asks
only for the trusted record.

A **partner** case runs `steps` against one partner (`partner`: its `material`, the client policy keys it has
`pinned`, `clientOrigins`, the endpoints it has switched off for unsafe sessions, `maxSessionsPerPeer`,
`sessionIdleMs`, its windows, its `actsOn` and `allowedExtensions` as a receiver's, and the clock's `start`), its
clock at each step's `at`. A peer is one of `peers`, a client `certificate` and the `remoteAddr` it connected from,
read as `peerCertificates` reads one, with its issuer for the session's binding; null is no client certificate. A
`handshake` posts the request `handshakes` names, as its JCS bytes in `handshakeBodies`, or `body`; `as` names the
session it opens, since the partner chooses the id. It expects the `status`, the `error` of a `400`, and the reply's
`sessionStatus`, `disabled` and `extensions` of a `200`. A `call` names its session as `{"of": <as>}`,
`{"id": <literal id>}`, or null for no `X-Path-Session`. Its `stamp`, when present, is a boundary stamp signed with
`key` as the step runs, in the session its `sess` names, binding the call's method, its target and the stamp's own
`body`, and committing to the stamp's `block`; `proofHeader` and `extensionsHeader` go as given. `routePattern` is
the pattern of the handler the call reaches, which an unsafe session's switched-off endpoints are matched against.
It expects the `refusal`, whether the call is `attested`, what the handler is `handedOn`, as a receiver case records
it, and `trustedRecord`, null for a refusal. A `call` may carry `read`, what the handler reads after the call is
accepted, in a receiver case's form; `trustedRecord` counts it after what the call hands on, and no `read` is the
empty list. A `call` may also carry `destinationOwner`, the owner, from the partner's own records, of a destination the
handler asks about a guarded public write to; it then expects `publicWrite` too, as a receiver case records it, null
for a refusal.

An **egress** case enters `inbound`, a receiver case's inputs, at the egress `egress` (null: no request at all),
which acts on its `actsOn` and carries its `allowedExtensions` as a receiver does, requires `requires` of the
partner and goes on without them when `continueWithout` is true; then it sends each of `posts` to a scripted
partner. Each handshake that carries a client root takes the next of `partnerScript.handshakes`: `attested` or
`unsafe`, a genuine reply in the entry-key form from the `psp` material; `notFound`, a `404`; `wrongKey`, a reply in
the policy-key form signed by and naming `stranger-policy`. One with no client root gets a genuine reply whose status
is `replacement`, every reply lists `partnerScript.extensions`, and each call takes the next of `calls`. A handshake
or call the script has no answer for fails the replay, so a case whose script is empty expects nothing to be sent.
It expects each post's `outcome` (`answered`, with the partner's `status` and whether the call went out `attested`;
`refused`, the egress declining before anything is sent; `withheld`, no call made in a session that does not meet the
requirement, at most its handshake sent; or `failed`, no session could be opened, so the call itself is not sent),
everything the partner `received` in order, and the entries the request `added` at the egress. A received
`handshake` says whether it carried a `clientRoot`. A received `call` gives its `session` and `stampSession`, the
position in `received` of the handshake whose reply issued the id in its `X-Path-Session` and in its stamps' `sess`,
then its `stamps` with `sess` and `sig` left out (the partner chose the id, and `sig` covers it), and its `proof` and
`blocks` as decoded; each is null when the header is absent. The replay also verifies every received stamp's `sig`
under the key the egress's keyring (its `material`'s) holds for the stamp's `svc`, over its fields as received,
`sess` included; a stamp that does not verify fails the case.

A **caller** case is a call by `caller` after the chain `inbound`, which came with the blocks `inboundBlocks`, its
own block holding the entries in `added`, as a caller that acts on `actsOn` and carries `allowedExtensions`, and the
`response` to it (`status`, `header`, `body`), whose header is `{block, stamp}`. It expects the sent stamp's `rcv`,
the response check's `reason` (null when the caller has no verifier and checks nothing), whether the caller
`refused` the response, and the `influence` entries the response adds.

Some rules are not pinned by vectors and are tested in each HTTP SDK (`paztport-http`, `paztporthttp`): the startup
checks of a partner's and an egress's own material, the [wire limit](wire.md#limits), 256 KiB, on a handshake body,
clearing a session after `POLICY_EXPIRED`, the egress's own idle period, and the egress labelling its own response to
its caller `local-untrusted`, since a handler may relay what the partner said. `paztport-http` also tests the
[writer's limit](wire.md#writing) on the blocks it sends: a caller whose blocks token would pass 256 KiB signs and
sends nothing, and a responder whose `X-Path-Response` would pass it leaves the answer unattested, which its caller
counts as one `local-untrusted` entry ([influence.md](influence.md#content-labels)). It tests too that a service's
`actsOn` and `allowedExtensions` are one configuration, whether or not it has a verifier
([verification.md](verification.md#the-live-order)): a builder given settings that differ from its verifier's is
refused.

Cases may be added at any time. A recorded answer changes only with a protocol change.
