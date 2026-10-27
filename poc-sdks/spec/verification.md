# Verification

How a receiver checks a chain: the live order, freshness and replay, the receiver and peer checks, who a result
names, the offline order for recorded chains, and the reason codes. The bytes are in [wire.md](wire.md).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as described in RFC 2119.

Contents: [Inputs](#inputs) · [The live order](#the-live-order) · [Freshness and replay](#freshness-and-replay) ·
[Receivers, the peer and attribution](#receivers-the-peer-and-attribution) ·
[The MCP server and client](#the-mcp-server-and-client) · [Offline verification](#offline-verification) ·
[The legacy rule](#the-legacy-rule) · [v1](#v1) · [Reason codes](#reason-codes) ·
[Guidance for a responder](#guidance-for-a-responder)

## Inputs

A verifier MUST fail closed: a malformed input is a typed rejection, never an exception out of the verifier and
never a pass. Every input below comes from the verifier's own configuration or its transport, never from the
request.

| Input | Meaning |
|---|---|
| `stamps` | The chain as received. |
| `expectedBind` | The binding the receiver computed for what it received ([wire.md](wire.md#bindings)). |
| `influence` | The influence entries received with the chain. |
| `proof` | The route proof received with the chain. |
| `receiver` | What the last stamp's `rcv` must name: the receiver's own name, or for a response, the calling client's `svc`. |
| `receiverInRoute` | Whether the route ends at `receiver`: true for a call, false for a response. |
| `peer` | Optional. The sender the transport authenticated, `{ svc, inst }`: its service name and its network address, for example from an mTLS certificate. |
| `keyring` | Service name to public key, from a verified keyring. A key is looked up by own name only: inherited or default entries MUST NOT match. |
| `root`, `rootId` | The pinned signed root, already verified against its policy key. |
| `allowedOrigins` | The services that may sign an origin stamp. |
| `sess` | The session id every stamp must carry. |
| `nonces`, `nonceKey` | The replay cache and this chain's key in it. |
| `now` | The verifier's clock, in ms since the Unix epoch. |

## The live order

A live verifier accepts **v3 only**. It runs these checks in this order, and the first that fails is the result.
The order is part of the protocol: the vectors pin the code each case gives, so two implementations that order
the checks differently disagree.

| # | Check | Fails with |
|---|---|---|
| 1 | The stamps parse: a non-empty array of well-formed v3 stamps ([field rules](wire.md#stamp-field-rules)). A v2 stamp, or a mix, does not parse. | `CHAIN_MISSING` |
| 2 | No signed field of any stamp holds `|`, `rcv` included. | `BAD_SIGNATURE` |
| 3 | The origin's `svc` is in `allowedOrigins`. | `BAD_ORIGIN` |
| 4 | For each stamp in order: its `svc` has a key in `keyring` and its signature verifies under it (`BAD_SIGNATURE`), and its `prev` is `""` for the origin and the previous stamp's `sig` otherwise (`BROKEN_LINK`). Only after the whole chain passes that loop: each stamp's `rcv` is the next stamp's `svc`, and the last stamp's `rcv` is `receiver`. | `BAD_SIGNATURE`, `BROKEN_LINK`, then `BINDING_MISMATCH` |
| 5 | Every stamp carries the origin's `rid`. | `RID_MISMATCH` |
| 6 | Every stamp carries `sess`. | `SESSION_UNKNOWN` |
| 7 | Freshness: the last stamp's `ts` is within `CALL_MAX_AGE_MS` of `now`, either way; the origin's `ts` is at most `RUN_MAX_AGE_MS` before `now` and at most `CALL_MAX_AGE_MS` after it. A non-finite `now` or limit fails. | `EXPIRED` |
| 8 | The last stamp's `bind` equals `expectedBind`. | `BINDING_MISMATCH` |
| 9 | The influence parses, and the last stamp's `infl` equals its commitment. | `INFLUENCE_MISMATCH` |
| 10 | The nonce cache remembers keys for at least 2 × `CALL_MAX_AGE_MS`, and `nonceKey` is new to it. A new key is recorded. | `REPLAY` |
| 11 | The route, the stamps' `svc` values then `receiver` when `receiverInRoute`, is proven against the root ([proof checks](wire.md#proof-object)). | `PATH_NOT_ALLOWED` |
| 12 | With a `peer`, `peer.svc` equals the last stamp's `svc`. | `PEER_MISMATCH` |

Otherwise the result is `OK`.

Why this order:

- **Receivers after the signature loop.** A bad signature or link anywhere always beats a bad `rcv`, so a
  forged chain is reported as forged, not as misdirected.
- **A receiver mismatch is `BINDING_MISMATCH`.** `rcv` is part of what the stamp binds: a chain signed for
  another receiver is bound to another request, exactly as a chain spliced onto another body is.
- **The cache is checked before it is spent.** A cache that forgets sooner than twice the call window could
  forget a key while a replay of it is still fresh, so it fails closed before recording anything.
- **The peer check runs last**, so every other check keeps its code when a transport adds a peer.

## Freshness and replay

| Constant | Value | Meaning |
|---|---|---|
| `CALL_MAX_AGE_MS` | `5000` (5 s) | How far the last stamp's time may be from `now`, either way, and how far the origin may be in the future. |
| `RUN_MAX_AGE_MS` | `1800000` (30 min) | How long a run's origin stays usable. An agent run reuses one origin for many calls, so the origin may be older than one call window. |
| `NONCE_TTL_MS` | `15000` (15 s) | How long a nonce cache remembers a key. It MUST be at least 2 × `CALL_MAX_AGE_MS`. |

The nonce key names the request and the direction, so a call, its response and a local step with the same ids
can't spend each other's keys:

| Chain | `nonceKey` |
|---|---|
| MCP tool call (server side) | `<rid>|<callId>|req` |
| MCP response (client side) | `<rid>|<callId>|resp` |
| Local step | `<rid>|<callId>|local` |
| v1 HTTP hop | `<rid>|<last svc>` |

`<rid>` is the origin's `rid` and `<callId>` the call's `paztport/callId` (for a local step, the tool call id).
The vectors' v3 HTTP-hop case uses `<rid>|<last svc>|req`; no SDK verifies v3 over HTTP yet
([wire.md](wire.md#http-v1)).

## Receivers, the peer and attribution

**The receiver checks.** In a v3 chain every stamp names the hop it was handed to (check 4). So a chain
forwarded unchanged to a service it was not signed for fails `BINDING_MISMATCH`, wherever it is sent, before
the route is looked at. A receiver MUST supply its own name as `receiver` from its configuration, never from the
request. For a call that name is also the end of the route. For a response, `receiver` is the client's own
`svc` and `receiverInRoute` is false: the response route is the server's own hops, and the client is not on it.

**The peer check.** A transport that authenticates the sender (mTLS, for example) SHOULD pass it as `peer`. Check
12 then requires the last signer to be that sender. Only `svc` is compared: a certificate is issued per
service, not per instance, and `peer.inst` is the transport's address for the sender, not a signed value. With
no peer, check 12 is skipped.

**Attribution.** Every result carries `suspectSvc` and `suspectInst`, the party a responder may act against:

- **With a peer**, every result of the live order, 1 to 12, names the peer, `OK` included:
  `suspectSvc = peer.svc` and `suspectInst = peer.inst`. The transport authenticated that sender, so it is the
  party that really sent this request, whatever the chain says. The MCP wrappers' own pre-checks, below, run
  before the live order and name no one.
- **Without a peer**, only `OK` and `PATH_NOT_ALLOWED` name a suspect: `suspectSvc` is the last stamp's `svc`
  and `suspectInst` its `inst`. By then the signatures, links, receivers, times, binding and replay checks have
  held, so that service's key really signed this request for this receiver. Every other result leaves both
  empty, because the name would be unsigned, or the genuine stamp would belong to another request (a replayed
  or altered capture).
- Without a peer, `suspectInst` is the signing service's own claim. Its key proves the service, not the
  instance.

## The MCP server and client

The MCP transport wraps the live order with checks of its own, before the chain is verified.

**A tool call, on the server.** The server checks a call only in an attested session
([sessions-and-influence.md](sessions-and-influence.md#status)), against the client's root and keyring from the
handshake, with `allowedOrigins` = the client's origin service, `receiver = mcp:<serverId>.<tool>`,
`receiverInRoute = true` and `nonceKey = <rid>|<callId>|req`. In order:

1. `params` is an object with a string `name` and an object `_meta`, the name holds no `/` or `|`, the server
   id no `/`, `|` or `.`, `paztport/callId` is a string, and `paztport/chain` parses (`CHAIN_MISSING`).
2. The `tools/call` binding can be computed (`BINDING_MISMATCH`).
3. The live order, 1 to 12.
4. The server reports `PATH_NOT_ALLOWED` against the client's policy as `CLIENT_PATH_NOT_ALLOWED`, so its logs
   tell the client's policy from its own.

The influence is returned only when the call verifies. Then the server decides on the call
([sessions-and-influence.md](sessions-and-influence.md#the-server-decision)). A refusal is answered as a result
with `isError: true` and `paztport/verdict`, and is not signed.

**A response, on the client.** The client checks a response only in an attested session, against the server's
root and keyring from the signed handshake reply, with `allowedOrigins` = the server's entry service as the
client's own configuration names it (`["mcp-entry"]` in the agents demo), never a value from the reply,
`receiver` = the client's own `svc`,
`receiverInRoute = false`, `influence = []` and `nonceKey = <rid>|<callId>|resp`. In order:

1. The call's `rid` and `callId` are strings, `callId` holds no `\n`, and the attestation is an object with an
   array `chain`, a string `resultHash` and an array of well-formed `labels` (`CHAIN_MISSING`).
2. The first stamp's `rid` is the call's (`RID_MISMATCH`).
3. `resultHash` equals the result binding of the result received (`BINDING_MISMATCH`).
4. The live order, 1 to 12, with `expectedBind` = the response binding of `resultHash`, the call id and the
   labels.

The labels count as influence only when the whole response verifies. A response that fails, or arrives in an
unsafe session, counts as `local-untrusted`.

**A verdict, on the client.** A refusal is unsigned by design: it can only withhold a result, never add
influence. A client MUST treat a result with a non-audit `paztport/verdict` as "the tool did not run" and record
nothing from it. Its `reason` is server data that can reach a model, so a client MUST keep it only when it is one of
these codes, and MUST replace anything else, `OK` included, with `UNKNOWN`:

`CHAIN_MISSING`, `BAD_ORIGIN`, `BAD_SIGNATURE`, `BROKEN_LINK`, `EXPIRED`, `RID_MISMATCH`, `BINDING_MISMATCH`,
`REPLAY`, `PATH_NOT_ALLOWED`, `SESSION_UNKNOWN`, `CLIENT_PATH_NOT_ALLOWED`, `INFLUENCE_MISMATCH`,
`INFLUENCE_DENIED`, `UNSAFE_SESSION`, `SCOPE_DENIED`, `UNCHECKABLE`, `PEER_MISMATCH`.

That is every [reason code](#reason-codes) except `OK` and the offline-only `TIME_MISMATCH` and
`PROMPT_MISMATCH`.

## Offline verification

A record set, such as a client's evidence file, can be verified again later with no clock to be fresh against.
The offline verifier runs the live checks in the live order, with these differences:

| # | Offline |
|---|---|
| 1 | The stamps parse all v3, or all v2 as legacy. A mix is `CHAIN_MISSING`. |
| 3, 4 | With `signers`, for a chain that never leaves one process (a local step): the origin MUST report the expected instance (`BAD_ORIGIN`), and each stamp MUST be by the expected service and instance (`BAD_SIGNATURE`). |
| 4 | The receiver checks run for a v3 chain only. |
| 5 | Every stamp carries the `rid` the record files it under, which defaults to the origin's (`RID_MISMATCH`). |
| 7 | In place of freshness: the last stamp's `ts` equals the time recorded with it, and when the run's records give start times, the origin's `ts` is one of them (`TIME_MISMATCH`). With age limits, the last stamp is at most `RUN_MAX_AGE_MS` after the origin and the origin at most `CALL_MAX_AGE_MS` after the last stamp (`EXPIRED`). Then the origin binds the run's recorded prompt (`PROMPT_MISMATCH`); a run with no prompt, or a disputed one, fails. |
| 10 | The nonce key has not been spent anywhere in the record set (`REPLAY`). A live cache that forgets after its window can't show that. |
| 12 | There is no peer offline. |

Each kind of record is checked this way:

- **A recorded call**: the server-side call check above, with the offline chain verifier, the age limits and the
  time the calling hop recorded stamping it. A chain that verifies but names a different call id from the
  record's is `RID_MISMATCH`.
- **A recorded response**: the client-side response check, with the live chain verifier at the time the client
  recorded verifying it, and one nonce cache that never forgets across the record set. It also accepts a v2
  chain as legacy.
- **A recorded local step**: the offline chain verifier with `signers` (the origin service then the client hop,
  both on the client's one instance), `sess = ""`, the client's root and keyring, and `nonceKey =
  <rid>|<callId>|local`. Then the decision it signed is checked again against the signed rules.
- **A recorded handshake**: attested only when the reply is attested and verifies against the pin, both roots
  verify against their sides' policy keys, and, unless the request is legacy, the client keyring's signature
  verifies ([sessions-and-influence.md](sessions-and-influence.md#recorded-handshakes)).

## The legacy rule

Records made before v3 carry v2 stamps, which name no receiver, and session requests with no
`clientKeyringSig`. They can't be re-signed, so:

- **Live verifiers accept v3 only.** A v2 chain received live is `CHAIN_MISSING`.
- **Offline, an all-v2 chain is accepted as legacy.** It is checked with the v2 signed bytes and without the
  receiver checks; everything else is the same. A chain that mixes versions is `CHAIN_MISSING`, never a partial
  legacy pass.
- **A session request with no `clientKeyringSig` field** is legacy offline: the keyring check is skipped. Live,
  the server treats it as unsigned, so the session is unsafe. A `clientKeyringSig` that is present but malformed (not a string) or wrong: live, the server reads a non-string as `""`, which never verifies, so the session is unsafe; offline, it is a v3 request whose signature fails, not a legacy one.
- **A verifier MUST report legacy.** Each item that verified from v2 stamps, or from a request with no keyring
  signature, is marked legacy, so a reader can see that it was checked less strictly. A failure is never marked.
  The agents demo's `verify` writes `"legacy": true` on such items and counts them on its `OK` line
  ([eval README](../../poc-demos/agents-mcp/eval/README.md)).

## v1

The HTTP mesh's verifier, which the Java SDK (`paztport-core`) and the TypeScript SDK (`verifyV1` in
`@paztport/core`, with `@paztport/http` for the binding) implement, runs:

| # | Check | Fails with |
|---|---|---|
| 1 | `X-Path-Chain` is present, decodes and parses as a non-empty array of v1 stamps. | `CHAIN_MISSING` |
| 2 | The origin's `svc` is an allowed origin. | `BAD_ORIGIN` |
| 3 | Every signature verifies, and every `prev` links. | `BAD_SIGNATURE`, `BROKEN_LINK` |
| 4 | Every stamp carries the origin's `rid`; the origin's `ts` is at most the maximum age (5 s in the mesh) before `now`. | `RID_MISMATCH`, `EXPIRED` |
| 5 | The last stamp's `bind` equals the HTTP binding of the request received. | `BINDING_MISMATCH` |
| 6 | `<rid>|<last svc>` is new to the nonce cache. | `REPLAY` |
| 7 | The stamps' `svc` values then the receiver are proven against the root by `X-Path-Proof`. | `PATH_NOT_ALLOWED` |

v1 has no receiver, session, influence or peer. `OK` and `PATH_NOT_ALLOWED` name the last stamp; every other
rejection names no one. A v1 stamp does not bind its receiver, so a chain forwarded unchanged to another service
with a matching method and path can reach check 7 and name its innocent last signer.

## Reason codes

| Code | Given by | Meaning |
|---|---|---|
| `OK` | live, offline | Every check held. |
| `CHAIN_MISSING` | live, offline | No chain, or one that does not parse, or a malformed transport field around it. |
| `BAD_ORIGIN` | live, offline | The origin is not an allowed origin (or, offline, not the expected instance). |
| `BAD_SIGNATURE` | live, offline | A field holds `|`, a key is unknown, or a signature fails. |
| `BROKEN_LINK` | live, offline | A `prev` does not match. |
| `EXPIRED` | live, offline | Outside the freshness window, or offline, outside the age limits. |
| `RID_MISMATCH` | live, offline | The stamps don't share the `rid`, or name another request. |
| `BINDING_MISMATCH` | live, offline | A `rcv` names the wrong hop, or the binding does not match what was received. |
| `REPLAY` | live, offline | The nonce key was seen before. |
| `PATH_NOT_ALLOWED` | live, offline, client local | The route is not proven against the root. Also the local gate's verdict for a tool its route list doesn't have. |
| `SESSION_UNKNOWN` | live, offline | A stamp names another session. |
| `INFLUENCE_MISMATCH` | live, offline | The influence does not parse, or the last stamp does not commit to it. |
| `PEER_MISMATCH` | live | The authenticated transport peer is not the last signer. |
| `TIME_MISMATCH` | offline only | A stamp's time is not the one recorded with it. |
| `PROMPT_MISMATCH` | offline only | The origin does not bind the run's recorded prompt. |
| `CLIENT_PATH_NOT_ALLOWED` | server decision | An MCP server's name for `PATH_NOT_ALLOWED` against the client's policy. |
| `INFLUENCE_DENIED` | server decision, client local | The influence rule refused a public write. |
| `UNSAFE_SESSION` | server decision | The tool is disabled in an unsafe session. |
| `SCOPE_DENIED` | client local | The local gate: a path or program outside the signed rules. |
| `UNCHECKABLE` | client local | The local gate could not tell what the call would touch. |

"Live" codes come from a live verifier, and "server decision" codes from a server's decision on a call; both
are valid verdicts for a server to send. "Offline only" codes are never sent live, and a client MUST NOT accept
them as a server's verdict. "Client local" codes come from the client's own gate for its local tools. A server
has no reason to send them, but the client's verdict check keeps them, since they are not offline-only
([the verdict rule](#the-mcp-server-and-client)).

## Guidance for a responder

A responder acts on rejections, for example by isolating the named instance.

- **Only attributable rejections are triggers.** `INFLUENCE_DENIED` and `UNSAFE_SESSION` are about content and
  capability, not compromise: an honest component misled by poisoned input gets them. A responder MUST NOT
  quarantine on them. It SHOULD log them. The same holds for the client-local codes.
- **Act only on a named suspect.** A result with empty suspect fields names no one, by design: acting on it
  would let a forged chain point at anyone.
- **Under mTLS, `suspectInst` is the transport peer's address.** The responder resolves it to an instance on
  its own network; the address is the transport's evidence, not the chain's.
- **Keep the instance check.** A certificate is issued per service, so the peer proves the service, not the
  instance; and without a peer, `suspectInst` is the signer's own claim. Before acting, a responder MUST check
  that the instance it resolved runs the service named in `suspectSvc`.
