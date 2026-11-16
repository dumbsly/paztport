# Review path

This is a reading path for a reviewer judging whether Paztport's core holds. The
core attests the path a request took; the profiles and the one extension,
`influence`, are built on it
([the protocol](../poc-sdks/spec/README.md#the-protocol)). The first sitting reads
the spec's sections on path attestation, then the TypeScript core that implements
them. Each add-on after it is a further sitting, read the same way.
To report what you find, see [SECURITY.md](../SECURITY.md).

Each table gives the lines to read: lines as an editor numbers them, comments and
blank lines included; a spec section runs from its heading to the next heading of
the same or a higher level. `./run test` checks every count and every total against
the files.

## The afternoon: path attestation

Stamps and the chain they form, the route proof with operations, freshness, the
request binding, replay and the peer, and the order of checks a receiver runs. Read
the spec rows first, then the code. Each check of the live order, 0 to 12, has its
spec section and the file that runs it among the rows. Where a file also holds code
an add-on uses, its row says so.

| Read | What to look for | Lines |
|---|---|---|
| [spec: The protocol](../poc-sdks/spec/README.md#the-protocol) | What the core is, what a profile and an extension are, and the design choices: the receiver check, operations, one version, one byte form, the signed keyring, the transport peer, extensions. | 50 |
| [wire.md: Encodings](../poc-sdks/spec/wire.md#encodings) | Base64url, the domain prefixes, and the signature rule that every signature check applies (check 3). | 55 |
| [wire.md: JSON](../poc-sdks/spec/wire.md#json) | How an object is read strictly from its bytes and written as one byte form; check 1 reads the chain this way. | 173 |
| [wire.md: Keys and files](../poc-sdks/spec/wire.md#keys-and-files) | The one key form, and the files a service loads its material from. | 35 |
| [wire.md: Stamps](../poc-sdks/spec/wire.md#stamps) | A stamp's members, the ten its signature covers, and the rules each is held to. | 61 |
| [wire.md: Chains](../poc-sdks/spec/wire.md#chains) | How stamps link by `prev`, and how each `rcv` names the next hop or the receiver (check 4). | 42 |
| [wire.md: Blocks](../poc-sdks/spec/wire.md#blocks) | The claims a hop attaches, and the `ext` commitment that pins them to its stamp (checks 9a to 9c). | 84 |
| [wire.md: Bindings](../poc-sdks/spec/wire.md#bindings) | What each kind of `bind` covers: the request a stamp was made for (check 8). | 39 |
| [wire.md: The Merkle tree](../poc-sdks/spec/wire.md#the-merkle-tree) | Salted leaves, padding, the proof object and `rootId` (check 12). | 50 |
| [wire.md: Routes](../poc-sdks/spec/wire.md#routes) | Which route a chain proves, and the route nodes a policy may hold. | 32 |
| [wire.md: Operations](../poc-sdks/spec/wire.md#operations) | A receiver's handlers in its route, an operation's key, and the table a caller names them from. | 116 |
| [wire.md: The signed root](../poc-sdks/spec/wire.md#the-signed-root) | What the policy key signs over the tree, and its window. | 35 |
| [wire.md: The signed keyring](../poc-sdks/spec/wire.md#the-signed-keyring) | What the policy key signs over the services' keys, and its window. | 37 |
| [wire.md: Proof bundles, and who holds what](../poc-sdks/spec/wire.md#proof-bundles-and-who-holds-what) | Which service holds which proof, and which party holds which key. | 47 |
| [verification.md: Inputs](../poc-sdks/spec/verification.md#inputs) | What a verifier takes, and that every input comes from its own configuration or its transport, never from the request. | 34 |
| [verification.md: The live order](../poc-sdks/spec/verification.md#the-live-order) | Checks 0 to 12, why they run in this order, and what a service is handed on `OK`. | 73 |
| [verification.md: Freshness and replay](../poc-sdks/spec/verification.md#freshness-and-replay) | The time limits (check 7), the nonce keys and the cache (check 11), and duplicate delivery across replicas. | 51 |
| [verification.md: Receivers, the peer and attribution](../poc-sdks/spec/verification.md#receivers-the-peer-and-attribution) | Naming the receiver (check 4), the peer (check 10), and whom each result names as suspect. | 56 |
| [verification.md: Reason codes](../poc-sdks/spec/verification.md#reason-codes) | Every code and where it is given; only the live order's belong to this sitting. | 40 |
| [verify/verify-chain.ts](../poc-sdks/typescript/core/src/verify/verify-chain.ts) | The live order in one function: check 0 before any token is read, then checks 7, 10 and 11, the attribution rule, and the hand-over on `OK`. | 221 |
| [internal/chain-checks.ts](../poc-sdks/typescript/core/src/internal/chain-checks.ts) | Checks 1 to 6, 8, 9a to 9c and 12, shared with the offline verifier; `signers` and the `live` flag are there for offline verification and local steps. | 253 |
| [encoding/json.ts](../poc-sdks/typescript/core/src/encoding/json.ts) | The reader check 1 relies on: a token's length first, then its bytes as exactly their canonical form. `readFile` reads files, not tokens. | 296 |
| [encoding/json-rules.ts](../poc-sdks/typescript/core/src/encoding/json-rules.ts) | The limits, the error a reader gives, and the text a string field may hold. | 36 |
| [encoding/jcs.ts](../poc-sdks/typescript/core/src/encoding/jcs.ts) | The canonical bytes a stamp signs, and the writer that refuses what a reader refuses. | 163 |
| [encoding/b64url.ts](../poc-sdks/typescript/core/src/encoding/b64url.ts) | The one canonical decoding, so one value has one token. | 24 |
| [internal/fields.ts](../poc-sdks/typescript/core/src/internal/fields.ts) | The schema step every reader shares: exactly an object's members, each of its type. | 96 |
| [stamp/stamp.ts](../poc-sdks/typescript/core/src/stamp/stamp.ts) | A stamp's schema (check 1), the bytes its signature covers (check 3), and signing. | 138 |
| [stamp/names.ts](../poc-sdks/typescript/core/src/stamp/names.ts) | The signer's refusal to stamp a name no route can hold. | 25 |
| [crypto/crypto.ts](../poc-sdks/typescript/core/src/crypto/crypto.ts) | `verify`: the key form, then the strict encodings, then the library's equation (check 3). | 107 |
| [crypto/ed25519-strict.ts](../poc-sdks/typescript/core/src/crypto/ed25519-strict.ts) | Rules 2 to 4 of the signature rule, checked on the bytes before the library sees them. | 55 |
| [policy/routes.ts](../poc-sdks/typescript/core/src/policy/routes.ts) | `addressedTo` (check 4), the route string (check 12) and the node rules; `rulesRoute` belongs to local steps. | 65 |
| [stamp/block.ts](../poc-sdks/typescript/core/src/stamp/block.ts) | A block's schema and its commitment, `commitBlock` (check 9a). | 115 |
| [verify/extensions.ts](../poc-sdks/typescript/core/src/verify/extensions.ts) | The settings checks 9b and 9c read, and the hand-over's shape; `recordExtensionSettings` belongs to offline verification. | 62 |
| [internal/extension-names.ts](../poc-sdks/typescript/core/src/internal/extension-names.ts) | The names a verifier's settings take; a session's requirement uses it too. | 22 |
| [stamp/binding.ts](../poc-sdks/typescript/core/src/stamp/binding.ts) | The verifier only compares `bind` (check 8); a request's binding is its transport's. These three bindings belong to add-ons: a run's prompt, a local step and a result. | 30 |
| [verify/nonce.ts](../poc-sdks/typescript/core/src/verify/nonce.ts) | A nonce key as JCS text, and the cache that spends it (check 11). | 46 |
| [policy/merkle.ts](../poc-sdks/typescript/core/src/policy/merkle.ts) | The leaf and node hashes, the proof's schema and `provesPath` (check 12); `buildTree` is the policy owner's. | 172 |
| [policy/root.ts](../poc-sdks/typescript/core/src/policy/root.ts) | The signed root: its signed bytes, schema and signature check. | 67 |
| [policy/keyring.ts](../poc-sdks/typescript/core/src/policy/keyring.ts) | The signed keyring: its signed bytes, schema and signature check. | 63 |
| [internal/keyring-names.ts](../poc-sdks/typescript/core/src/internal/keyring-names.ts) | A keyring names each service by a route node. | 15 |
| [policy/validity.ts](../poc-sdks/typescript/core/src/policy/validity.ts) | A valid `notAfter`, and `policyNotAfter` from several keyrings and roots (check 0). | 34 |
| [policy/policy.ts](../poc-sdks/typescript/core/src/policy/policy.ts) | How the owner builds a tree: random slots, a fresh `rootId`, and each service's proof bundle. | 106 |
| [verify/reason.ts](../poc-sdks/typescript/core/src/verify/reason.ts) | The codes as types; only the live order's belong to this sitting. | 131 |
| **Total** | | 3,452 |

## Influence and the owner-aware rule

The one extension: a record of what content shaped a request, and the rules a
guarded public write and a trusted record are held to. The core carries its items
and never reads them.

| Read | What to look for | Lines |
|---|---|---|
| [influence.md](../poc-sdks/spec/influence.md) | Classes, entries and labels; the every-stamp rule; the owner-aware rule and trusted records; influence over MCP; blinded influence at the boundary, which the TypeScript core does not implement. | 446 |
| [influence/influence.ts](../poc-sdks/typescript/core/src/influence/influence.ts) | The classes, and an entry's schema. | 105 |
| [influence/label.ts](../poc-sdks/typescript/core/src/influence/label.ts) | A content label's schema. | 32 |
| [influence/label-entry.ts](../poc-sdks/typescript/core/src/influence/label-entry.ts) | A label as the entry a caller records. | 14 |
| [influence/request.ts](../poc-sdks/typescript/core/src/influence/request.ts) | Reading a request's items as entries, and `INFLUENCE_MISMATCH`; `recordedCallReason` belongs to offline verification. | 73 |
| [influence/response.ts](../poc-sdks/typescript/core/src/influence/response.ts) | The labels a response over MCP carries, or one `local-untrusted` entry. | 61 |
| [influence/influence-rule.ts](../poc-sdks/typescript/core/src/influence/influence-rule.ts) | The owner-aware rule, the every-stamp rule before it, and the condition for a trusted record. | 44 |
| [influence/server-decision.ts](../poc-sdks/typescript/core/src/influence/server-decision.ts) | An MCP server's decision on a verified call, with the classes it served in the session. | 47 |
| **Total** | | 822 |

## Sessions

How a client and a server, or two organisations, agree which policy material each
call is checked against.

| Read | What to look for | Lines |
|---|---|---|
| [sessions.md](../poc-sdks/spec/sessions.md) | The handshake over MCP and over HTTP, the session id, status and unsafe sessions, the server's decision, recorded handshakes, and the boundary between organisations. | 484 |
| [wire.md: The reply certificate](../poc-sdks/spec/wire.md#the-reply-certificate) | The policy key's statement that an entry service's key may sign a reply. | 50 |
| [session/session.ts](../poc-sdks/typescript/core/src/session/session.ts) | The request and reply, the session id, the reply's signature and the session's status. | 349 |
| [session/request.ts](../poc-sdks/typescript/core/src/session/request.ts) | Reading and building a request, and the replacement request with no root. | 61 |
| [session/reply-builder.ts](../poc-sdks/typescript/core/src/session/reply-builder.ts) | The server's reply, attested or unsafe. | 61 |
| [session/reply-check.ts](../poc-sdks/typescript/core/src/session/reply-check.ts) | The client's check of the reply. | 51 |
| [session/reply-cert.ts](../poc-sdks/typescript/core/src/session/reply-cert.ts) | The reply certificate: its signed bytes, schema and signature check. | 73 |
| [session/requirement.ts](../poc-sdks/typescript/core/src/session/requirement.ts) | What a client requires of the server's extensions, and whether it calls after the reply. | 50 |
| [session/server-gate.ts](../poc-sdks/typescript/core/src/session/server-gate.ts) | The tools an unsafe session refuses. | 17 |
| [stamp/origin.ts](../poc-sdks/typescript/core/src/stamp/origin.ts) | A run's origin stamp for one session. | 27 |
| **Total** | | 1,223 |

## The MCP binding in TypeScript

Version 4 over MCP, in `@paztport/mcp`: how a call and a result carry Paztport's
objects in `_meta`, the server's checks of a call around the live order, and the
client's handshake, its stamping of a call and its reading of a result. The
handshake's MCP form is in the sessions sitting's spec row.

| Read | What to look for | Lines |
|---|---|---|
| [wire.md: MCP](../poc-sdks/spec/wire.md#mcp) | How a call carries its chain over MCP, and a result its attestation. | 37 |
| [verification.md: The MCP server and client](../poc-sdks/spec/verification.md#the-mcp-server-and-client) | The server's checks of a call and the client's of a response, around the live order. | 67 |
| [mcp/src/index.ts](../poc-sdks/typescript/mcp/src/index.ts) | The package's exports. | 10 |
| [mcp/src/meta.ts](../poc-sdks/typescript/mcp/src/meta.ts) | The `_meta` names a call and a result carry, and the handshake's method. | 20 |
| [mcp/src/binding.ts](../poc-sdks/typescript/mcp/src/binding.ts) | `bindMcpCall`: what a tools/call's last stamp binds (check 8). | 12 |
| [mcp/src/verify-call.ts](../poc-sdks/typescript/mcp/src/verify-call.ts) | `verifyCall`: the server's check of a call, with the receiver and nonce key it derives itself; `verifyRecordedCall` belongs to offline verification. | 145 |
| [mcp/src/response.ts](../poc-sdks/typescript/mcp/src/response.ts) | `verifyMcpResponse`: a result's attestation handed to the core's response check. | 64 |
| [mcp/src/verdict.ts](../poc-sdks/typescript/mcp/src/verdict.ts) | A server's verdict on a call, read as server data. | 26 |
| [mcp/src/client.ts](../poc-sdks/typescript/mcp/src/client.ts) | Opening a session and replacing one, stamping a call, and reading a result and what it adds to influence. | 394 |
| [mcp/src/server.ts](../poc-sdks/typescript/mcp/src/server.ts) | The server's checks of its own policy, the handshake, `McpServerSession.checkCall` and its response stamps, and `handleToolCall`. | 489 |
| **Total** | | 1,264 |

## Response attestation

How a client checks that a response over MCP came from the server's own hops. The
attestation's form and the client's check are in the MCP sitting's spec rows.

| Read | What to look for | Lines |
|---|---|---|
| [session/attestation.ts](../poc-sdks/typescript/core/src/session/attestation.ts) | The attestation's schema, the response binding, and the live order run with the client as a receiver off the route. | 107 |
| **Total** | | 107 |

## Signed events and the responder's input

How a verifier reports a refusal to a responder, and what the responder may act on.

| Read | What to look for | Lines |
|---|---|---|
| [wire.md: Events](../poc-sdks/spec/wire.md#events) | The envelope, the event and how it is carried. | 87 |
| [verification.md: Receiving an event](../poc-sdks/spec/verification.md#receiving-an-event) | The responder's checks, in order. | 84 |
| [verification.md: Guidance for a responder](../poc-sdks/spec/verification.md#guidance-for-a-responder) | What a responder does with an event it accepted. | 24 |
| [event/envelope.ts](../poc-sdks/typescript/core/src/event/envelope.ts) | The signed envelope, its window and how long an event id is remembered. | 28 |
| [event/verifier.ts](../poc-sdks/typescript/core/src/event/verifier.ts) | The responder's checks of a body: the envelope, the signer, the event, freshness and replay. | 132 |
| [event/attributable.ts](../poc-sdks/typescript/core/src/event/attributable.ts) | Which codes a responder may act against a suspect for. | 26 |
| **Total** | | 381 |

## Offline verification of recorded calls

How a record set is checked after the fact, with recorded times in place of a clock.

| Read | What to look for | Lines |
|---|---|---|
| [verification.md: Offline verification](../poc-sdks/spec/verification.md#offline-verification) | How the offline order differs from the live one, and how a recorded call and a recorded local step are checked. | 65 |
| [offline/verify-offline.ts](../poc-sdks/typescript/core/src/offline/verify-offline.ts) | The offline order, reusing the live checks; recorded times in place of a clock. | 139 |
| [offline/records.ts](../poc-sdks/typescript/core/src/offline/records.ts) | A recorded handshake's session and its limits, and a record set's spent nonce keys. | 146 |
| **Total** | | 350 |

## Local steps

A client's own tool calls, signed by the client alone, part of the MCP profile.
The gate decides under the classes of `influence`, and a recorded step is checked
offline, so this sitting comes after those two.

| Read | What to look for | Lines |
|---|---|---|
| [spec: The MCP profile](../poc-sdks/spec/README.md#the-mcp-profile) | What the profile holds, local steps among it. | 15 |
| [policy/local-rules.ts](../poc-sdks/typescript/core/src/policy/local-rules.ts) | A client's local rules, the programs never allowed, and the hash that pins the rules. | 180 |
| [local/local-decision.ts](../poc-sdks/typescript/core/src/local/local-decision.ts) | The gate's verdict on one local call: route, then uncheckable, then scope, then influence. | 149 |
| [local/local-step.ts](../poc-sdks/typescript/core/src/local/local-step.ts) | The step's stamp and binding, which cover the call and the gate's decision. | 127 |
| [offline/local-step.ts](../poc-sdks/typescript/core/src/offline/local-step.ts) | The recorded step's check, the gate's decision derived again from the signed rules. | 178 |
| **Total** | | 649 |

## The HTTP binding in Go

Version 4 over HTTP at a service, in the Go module: the headers and binding in
`wire`, the receiver, caller and partner in `paztporthttp`, and the egress in
`boundary`. The handshake over HTTP and between organisations is in the sessions
sitting's spec row.

| Read | What to look for | Lines |
|---|---|---|
| [wire.md: HTTP](../poc-sdks/spec/wire.md#http) | The headers a request and a response carry. | 58 |
| [verification.md: HTTP requests and responses](../poc-sdks/spec/verification.md#http-requests-and-responses) | The receiver's and the caller's checks around the live order, and who attests. | 186 |
| [verification.md: Modes and refusals](../poc-sdks/spec/verification.md#modes-and-refusals) | Enforce and audit, and what a refusal carries. | 48 |
| [spec: The HTTP rules in http-v4.json](../poc-sdks/spec/README.md#the-http-rules-in-http-v4json) | The rules the HTTP vectors pin, kind by kind. | 109 |
| [wire/doc.go](../poc-sdks/go/paztporthttp/wire/doc.go) | The package's overview. | 29 |
| [wire/binding.go](../poc-sdks/go/paztporthttp/wire/binding.go) | A request's binding and a response's result hash. | 55 |
| [wire/headers.go](../poc-sdks/go/paztporthttp/wire/headers.go) | The header names, and how a value is read. | 68 |
| [wire/token.go](../poc-sdks/go/paztporthttp/wire/token.go) | The tokens the headers carry. | 65 |
| [wire/noncekey.go](../poc-sdks/go/paztporthttp/wire/noncekey.go) | The request's and the response's nonce keys. | 49 |
| [wire/response.go](../poc-sdks/go/paztporthttp/wire/response.go) | The caller's check of a response. | 182 |
| [doc.go](../poc-sdks/go/paztporthttp/doc.go) | The package's overview. | 79 |
| [inbound.go](../poc-sdks/go/paztporthttp/inbound.go) | A request as it arrived. | 109 |
| [mode.go](../poc-sdks/go/paztporthttp/mode.go) | The modes, and the two ways of having none. | 73 |
| [settings.go](../poc-sdks/go/paztporthttp/settings.go) | A service's extension settings, stated once. | 26 |
| [receiver.go](../poc-sdks/go/paztporthttp/receiver.go) | The receiver's decision on each request. | 218 |
| [accepted.go](../poc-sdks/go/paztporthttp/accepted.go) | What the receiver decided, attesting the answer, and the key of a delivery. | 144 |
| [answer.go](../poc-sdks/go/paztporthttp/answer.go) | A refusal's exact body, and the answer when the nonce cache cannot answer. | 54 |
| [forward.go](../poc-sdks/go/paztporthttp/forward.go) | What a request carries on to its handler's calls. | 17 |
| [peer.go](../poc-sdks/go/paztporthttp/peer.go) | The peer read from a client certificate. | 64 |
| [subject.go](../poc-sdks/go/paztporthttp/subject.go) | The DER walk that reads a certificate's subject and issuer. | 252 |
| [caller.go](../poc-sdks/go/paztporthttp/caller.go) | Stamping a call, naming the receiver by configuration, and checking its response. | 400 |
| [trusted.go](../poc-sdks/go/paztporthttp/trusted.go) | A guarded public write and a trusted record at a receiver and a partner. | 95 |
| [sessions.go](../poc-sdks/go/paztporthttp/sessions.go) | A partner's sessions: how many one peer holds, and when an idle one expires. | 218 |
| [handshake.go](../poc-sdks/go/paztporthttp/handshake.go) | The handshake endpoint. | 121 |
| [partner.go](../poc-sdks/go/paztporthttp/partner.go) | A partner's decision on each call, in the session it names. | 112 |
| [unsafe.go](../poc-sdks/go/paztporthttp/unsafe.go) | The endpoints an unsafe session refuses. | 29 |
| [boundary/doc.go](../poc-sdks/go/paztporthttp/boundary/doc.go) | The egress's steps, in order. | 58 |
| [boundary/egress.go](../poc-sdks/go/paztporthttp/boundary/egress.go) | The egress: the session, the boundary stamp and blinded influence. | 675 |
| **Total** | | 3,593 |
