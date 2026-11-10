# Java SDK

A Maven build (`paztport-sdk-parent`, JDK 25 or newer; the Spring starter needs
Spring Boot 4.1) of three libraries, two one-shot tools and a benchmark. Every
cryptographic primitive comes from the standard JDK; `keygen` uses Bouncy Castle
only to build its X.509 certificates, which the JDK signs.

It implements protocol v3 as the [spec](../spec/README.md) defines it, and carries
it over HTTP. It replays `spec/vectors/http-v3.json` and `events.json` in full,
`json.json` but its `jcs` section and the MCP profile's `bindings` (`toolsCall`,
`result` and `localTool`), and `v3.json` but the recorded local steps, the
response attestations, `paztport/session`'s params and result, and the result and
`tools/call` bindings (`recordedLocalStep`, `responseAttestation`, `sessionParams`,
`sessionResult`, `bindResult` and `bindMcpCall`), which belong to the
[MCP profile](../spec/README.md#the-mcp-profile) that an HTTP-only SDK need not
implement.

```bash
mvn -q install   # build, test, and install into the local Maven repository
```

The Java demo ([poc-demos/java-mesh](../../poc-demos/java-mesh/README.md)) depends on
the installed artifacts, so install the SDK before building it. `./run java-mesh` and
`./run test` do this for you.

## paztport-core

The protocol, with no transport. It never touches TLS or HTTP: a transport hands
the verifier the binding of what was received, the receiver's name and, when it
has one, the authenticated peer.

- **Stamps and chains.** `Stamp` signs and refuses a field holding `|`, a lone
  surrogate or a noncharacter, or a `ts` outside [0, 2^53 − 1]. `Chains` reads a
  chain off the wire strictly, from its bytes, as checks 1 and 2 of the live order,
  and never throws; a `ts` is a protocol integer, so `1.0` is refused. A stamp whose
  `v` is not 3 is `CHAIN_MISSING`. `Stamper` signs only for a service name and a
  receiver that are route nodes, since a policy can hold nothing else; `Stamp`
  itself does not check, so a verifier reaches its own reason codes.
- **Verifying.** A `VerifierConfig` pins one or more keyrings (`PinnedKeyring`) and
  roots (`PinnedRoot`), each with its own `notAfter`, so a rollover can pin the old
  and the new together. `Verifier` runs the live order: first its own policy's window
  (`POLICY_EXPIRED`, naming no one, once its clock passes `policyNotAfter`, the
  earlier of the latest keyring and the latest root `notAfter`), then the twelve
  checks, using only the keyrings and roots current at its clock: a stamp verifies
  under any key they give its service by its own name, and a proof against a current
  root with its `rootId`. `VerifierConfig.pinned` checks every keyring and root
  against the pinned policy key, and refuses to build a config if one fails or has
  expired; each service pins its own one of each, and a partner session its client's.
  `OfflineVerifier` re-checks a recorded chain. Given `Signers` in its
  `OfflineConfig`, it also checks a chain that never leaves one process, such as a
  client's local step: the origin must report the expected instance (`BAD_ORIGIN`),
  and each stamp must be by the expected service and instance (`BAD_SIGNATURE`); the
  rest of a recorded local step is the MCP profile's, above. Offline, a keyring or
  root counts for a record no later than its `notAfter` (`Long.MAX_VALUE` for none),
  and a record for which no keyring, or no root, counts is `POLICY_EXPIRED`; a record
  with no recorded time fails check 7 (`TIME_MISMATCH`), and each age limit the
  `OfflineConfig` leaves null is its live default (`VerifierConfig.RUN_MAX_AGE_MS`,
  `CALL_MAX_AGE_MS`), so no configuration leaves a chain's age unlimited.
- **Record sets.** `RecordedSession` reads a recorded handshake from its request and
  reply, each its wire bytes as text, the pin and the configured entry: attested at a
  time, at all (at the earliest of its limits) and the response limit, none where the
  server's signatures do not verify (`Sessions.responseNotAfterOffline`). `RecordSet`
  holds a record set's spent nonce keys and a response cache that never forgets, and
  `RecordSet.callInSession` limits a recorded call to its session
  (`OUTSIDE_SESSION`).
- **Stamping.** `Stamper` stamps a hop's outbound call, starting a chain only at
  an origin, and stamps a response as one more stamp on the request chain, back to
  the caller.
- **Bindings, influence and labels.** `Bindings` (the prompt and response
  bindings, which refuse a lone surrogate), `Influence`, `InfluenceRule` (the one
  owner-aware rule) and `ContentLabel`.
- **Sessions.** `Sessions`: the handshake as messages, with no transport. `status`
  and `checkReply` judge both sides' roots and keyrings at the handshake: past
  `notAfter` makes the session unsafe, or the reply `BAD_SIGNATURE`, and a partner
  whose own material has expired opens every session unsafe. `attestedOffline`
  reads a recorded handshake instead, at the time of the record judged. A root or
  keyring without a `notAfter` is malformed, refused by its reader.
- **JSON in and out.** The SDK has no JSON library, and no public signature names
  one: it reads and writes JSON with its own strict reader and writer, by the
  spec's rules ([wire.md](../spec/wire.md#json)). Each value type writes its wire
  form with `toJson()` and reads it with a static `parse(String)` on the type, such
  as `KeyringFile.parse` or `SessionRequest.parse`, which throws
  `IllegalArgumentException` for anything malformed, text that is not one JSON value
  included. A reader of a whole HTTP body also takes its bytes, `parse(byte[])`. A
  list is read and written by the class that owns it (`Influence.parse`,
  `ContentLabel.parseAll`, `Chains.parse`). A session request and reply are read
  from their wire bytes, by `SessionRequest.parse` and `SessionReply.parse`, with
  exactly their members; `Sessions.checkReply` takes a reply's text or bytes and
  reads it first, and `RecordedSession.of` takes both as text. The verifiers take
  the stamps, influence and proof as the JSON text received and read it themselves,
  so text that is not JSON is a typed rejection at the check that reads it. `Jcs`
  canonicalises JSON text. The `org.paztport.core.encoding` package states the rule.
- **Encodings and keys.** `Base64Url` (the canonical encoding only, as the spec's
  encodings require), `Jcs`, `KeyringFile` (the signed `keyring.json`), `ReplyCert`
  (`reply-cert.json`), `KeyFiles`, `SignedRoot`, the Merkle tree, `PolicyBuilder`,
  `PolicyOwner` (the checks before the policy owner signs), `Routes`, and
  `EventVerifier` for events sent to a responder, which takes one or more keyrings
  and accepts a signer any of them has a key for, with `AttestationEvent`, the
  verdict before it is signed. A service's own files are read by
  `KeyringFile.load`, `SignedRoot.load`, `ProofBundle.load`, `KeyFiles.loadPolicyPin`
  and `BoundaryInfluence.loadKey`, and `OwnMaterial.check` and `expiringSoon` say
  what it may start with and when to warn that it is ending.

## paztport-http

v3 over HTTP, with no web framework. `PaztportHeaders` names the five headers:
`CHAIN` (`X-Path-Chain`), `PROOF` (`X-Path-Proof`), `INFLUENCE`
(`X-Path-Influence`), the response's `RESPONSE` (`X-Path-Response`), and `SESSION`
(`X-Path-Session`), which names the session a call is in. `isPaztport` says whether
a name is Paztport's: any that begins with `X-Path-`, in any ASCII case.
`RequestBinding` computes `bind` over the method, the raw path plus `?` and the raw
query when there is one, and the body. `HttpWire` encodes the headers and decodes
them to the JSON text they carry, builds a request's verify input (nonce key
`<rid>|<last svc>|<last rcv>|req`, or
`<rid>|<last svc>|<last rcv>|<key value>|req` for a keyed operation), computes a
response's result hash over its status and body, and checks a response's attestation
against the chain the caller sent (nonce key `<rid>|<last rcv>|resp`, or
`<rid>|<last rcv>|<key value>|resp` for a keyed operation), `<last rcv>` naming the
operation when the last stamp names one. A service therefore calls a given receiver,
or a given operation of it, at most once per request tree, and an operation with a
key at most once per request tree for each key value. Calls to two operations of one
receiver spend two keys, and so do calls for two items of one keyed operation.
`HttpSessions` fixes the handshake's names (`PATH`, `/paztport/session`, and the
error codes `INVALID_PARAMS` and `NO_SESSION`) and writes `{"error":"<code>"}`; core
reads the bodies, a request with `SessionRequest.parse(byte[])` and a reply with
`Sessions.checkReply(byte[], ...)`, as their wire bytes: each body is exactly its
message's JCS bytes, so a newline after them is refused.

The receivers decide a request with no framework and keep no per-request state.
`HttpReceiver.accept(InboundRequest, Peer, VerificationMode)` decides one
request for a service and returns an `Accepted`: either a refusal to send in
place of the handler's answer (an `HttpAnswer`, `{"reason":"<code>"}`), or what
the handler starts from and whether its answer is attested, by
`Accepted.attest(status, body, labels)` once the framework holds the answer
whole. `PartnerReceiver.accept(InboundRequest, PeerCert)` does the same for a
partner, in the session the caller names. `Accepted.result()` is the
verification result the decision rests on, or null where none ran, for an
adapter to report; `PartnerAccepted.result()` is the same for a partner's call.
The caller is never told it. `Accepted.delivery()` is the request's `Delivery`
(`rid`, the last signer's `svc`, the receiver the last stamp names as `rcv`, with
the operation when it names one, the `key` value of a keyed operation, null when
there is none, and the last stamp's `bind`), or null unless its chain passed the
live order at this in-mesh hop; it is the key for the application's own idempotency
handling, which a duplicate delivery needs (a proxy's retry reaches another replica
with its own cache). The same key and `bind` is the same request sent again by that
signer; the same key with another `bind` is a different request under a reused key,
to refuse; a user's second click is a new `rid`. A `NonceCache` that cannot answer,
because its `seenBefore` throws, gives no verdict: the verifier wraps what it throws
in `NonceCacheUnavailableException`, and the receiver refuses the request as
unavailable (`HttpAnswer.unavailable()`, 503) in `ENFORCE`, with
`Accepted.cacheFailure()` set, or serves it unverified in `AUDIT`. The cache
owns its own timeouts. `PeerCert.of(certificate, address)` reads the peer
and its issuer from a client certificate. `PartnerSessions` keeps a partner's
sessions; its `builder()` refuses own material no client could accept, naming
each `Fault`. `HttpSessions.serve` answers one handshake, and `UnsafeEndpoints`
says what an unsafe session may not do. The starter's filters, gate and
handshake endpoint are adapters over these, and another framework would adapt
the same functions.

`HttpCaller` is a service's side of its own calls.
`HttpCaller.stamp(method, uri, body, inbound, influence)` stamps one call over its
raw target and answers the headers to set, and
`HttpCaller.check(sent, status, xPathResponse, body)` checks its response against the
chain that was sent and answers what it adds to the request's influence: its labels,
each with `src` `http:<target>`, when it verifies, and otherwise one
`local-untrusted` entry. `check` also logs the response's `PAZTPORT_TRACE response`
line, so a mirror in another language logs the same line wherever it checks a
response. It names the receiver by its policy name: the URI's host with its ASCII
letters in lower case, unless its builder's `receivers(Map)` maps that host to
another name. A host with a character outside ASCII (or none) gets no name, and
`stamp` refuses the call (`IllegalArgumentException`) before anything is signed; so
does a null or empty method. An empty path binds as `/` (`http://host?q=1` binds
`/?q=1`), as a client sends it. The stamper behind it refuses a signing name or
receiver that is not a route node, on every path (`next`, `boundary`, `respond`).
`stampFromContext(method, uri, body)` and `recordToContext(...)` are the same two in
the blocking binding below, which read and add to the request's context, and record
nothing outside a scope. The layers do not mix: inside a scope, `recordToContext`
refuses a call that was not stamped from the context (`IllegalStateException`, before
anything is checked or logged) rather than silently drop what its response adds, so a
call the function stamped is checked with `check`. It refuses a call stamped in a
scope that has since closed in the same way, inside a later scope or outside any,
since its request is over and what its response adds would go to another.

A chain may name the operation each hop invokes (`rcv` `orders#getOrder`).
A caller names it when its builder is given the receivers' operation tables
(`operations(Collection<OperationTable>)`, one per service): the call's method and
raw path, without the query and not percent-decoded, are matched to the table, and
a call no operation matches is refused before anything is signed, naming the
receiver and the method. A call to a receiver with no table is named by the
service alone. The response's target, its `src` and `Outbound.receiver()` keep the
bare service name. A receiver is told the operation its framework will dispatch to
(`InboundRequest.operation`, null for none) and verifies the request as received
by `orders#getOrder`; a chain naming another operation, or one when nothing is
dispatched, is refused `BINDING_MISMATCH` (or served and published under `AUDIT`),
and a chain that names no operation is verified under the service alone.

An operation may declare a key, the item it acts on
([the key value](../spec/wire.md#operations)). A caller that matches a keyed
operation reads the call's key value from its raw target, by the operation's
template, and keeps it as `HttpCaller.Outbound.key()` for the response's nonce key; a
keyed call that gives no key value (a percent-encoded, over-long or absent one, say)
is refused (`IllegalArgumentException`) before anything is signed. A receiver reads
key values from its own table only, given by
`HttpReceiver.Builder.operations(OperationTable own)`, whose `build()` refuses a
table whose service is not the receiver's. For the operation its framework will
dispatch to, it reads the key value from the raw request target by that operation's
template, never from anything else the request says, and `Accepted.key()` is the
value the nonce key carried. A keyed operation whose target gives no key value is
treated as dispatched to no operation, so a chain naming it is refused
`BINDING_MISMATCH` before any nonce key is spent. A receiver given no table reads no
key value: a chain naming a keyed operation is then verified with the operation's
unkeyed nonce key, and the delivery's `key` is null.

`BoundaryClient` is the egress's side: `BoundaryClient.builder()` takes this
service's stamper, proofs, root, keyring and policy key, the partner's entry
service, `https` URL and pinned policy key, the boundary key, a listener, the JDK
`HttpClient` that presents this service's certificate to the partner (the client
owns it and shuts it down when closed) and a read timeout (30 s unless set), and
its `build()` refuses a setting no partner could use, naming each `Fault`. Its
`post(path, json)` reads the verified chain from `RequestContext`, below. The
starter's egress bean builds one from `paztport.boundary.*`; it logs as
`org.paztport.http.boundary.BoundaryClient`.

`RequestContext` is the blocking Java binding of the receivers: a thread-local
scope, for servlet and other thread-per-request code, that the handler, the caller
and `PublicWrites` read. An adapter runs each request's receiver through
`RequestContext.accept(receiver, request, …)`, which ends a scope other code left
open on the thread (with a warning), opens the request's own, and only then runs
the receiver, so the listener and the event publisher run in that scope too, and
no stale scope outlives a request, refused or not. It is not the protocol: a
reactive framework, or another language, carries the same results its own way.
Its verified chain is set only from the result of the receiver it ran.

It also holds what any server needs beside the protocol: `VerificationMode` (`OFF`,
`AUDIT`, `ENFORCE`) and the `ModeHolder` that switches it at runtime, the
`ReceivedRequestListener` hook, and the event publishers in
`org.paztport.http.event`, which log an event or send it, signed, to the responder.
They log through slf4j.

## paztport-spring

Glue, configured through `paztport.*` properties. It is built for Spring Boot 4.1
(Spring Framework 7) and does not run on Boot 3: it uses classes Boot 3 doesn't
have, such as `org.springframework.boot.restclient.RestClientCustomizer`.

No SDK type is a JSON tree, and the SDK has no JSON library at compile or runtime
scope, so it works beside whichever Jackson the application uses: Boot 4's web
layer and `RestClient` use Jackson 3 (`tools.jackson`). An SDK value's JSON, such
as `Opening.toJson()`, goes to Spring MVC or a `RestClient` as that `String`,
labelled `application/json`, so it is written exactly as it stands; a body goes to
the SDK as the bytes or text it arrived in, as the starter's handshake endpoint
hands a session request's body to `HttpSessions.serve`.

### Quick start

Install the SDK first (`mvn -q install`, above); the starter is then the artifact
`org.paztport:paztport-spring`, which brings paztport-core and paztport-http with it:

```xml
<dependency>
    <groupId>org.paztport</groupId>
    <artifactId>paztport-spring</artifactId>
    <version>0.1.0-SNAPSHOT</version>
</dependency>
```

A service that verifies every request, attests what it answers and calls nobody needs
its name, its stamp key, the keyring, the root and the policy pin, and the entry
points it accepts. This is the mesh demo's `mailer`, less its mutual TLS, its mode
switch and its environment overrides:

```yaml
paztport:
  service-name: mailer
  verify: true              # verify every request; mode defaults to enforce
  key-path: /config/keys/mailer.key
  keyring-path: /config/keys/keyring.json
  root-path: /config/policy/root.json
  policy-key-path: /config/keys/policy.pub
  origins: gateway
```

The files come from the [keygen](#toolskeygen) and the
[policy tool](#toolspolicy-tool). A service that calls others adds `proofs-path`, its
route proofs; mutual TLS adds `tls-bundle`, beside Boot's own `server.ssl` and
`spring.ssl.bundle` settings ([Mutual TLS](#mutual-tls)); probes or operator
endpoints on the application port go in `unverified-paths`
([Unverified paths](#unverified-paths)). [Properties](#properties) lists every
setting.

A handler asks the starter's `PublicWrites` bean whether a public write may be made,
and labels what it answers with `RequestContext.label` (both in `org.paztport.http`).
From the demo's `mailer` and `orders` (`Recipients`, `Mail` and `OrderBook` are the
demo's own):

```java
@RestController
public class MailerController {

    private final Recipients recipients;
    private final PublicWrites writes;

    public MailerController(Recipients recipients, PublicWrites writes) {
        this.recipients = recipients;
        this.writes = writes;
    }

    @PostMapping("/send")
    public ResponseEntity<Map<String, String>> send(@RequestBody Mail mail) {
        // An email is a public write: the owner-aware rule decides it, with the
        // address's owner from the mailer's own records, never from the request.
        if (writes.decide(recipients.ownerOf(mail.to())) != ReasonCode.OK) {
            return ResponseEntity.status(403)
                    .body(Map.of("reason", ReasonCode.INFLUENCE_DENIED.name()));
        }
        return ResponseEntity.ok(Map.of("status", "SENT"));
    }
}
```

```java
@GetMapping("/orders/{id}")
public ResponseEntity<?> byId(@PathVariable String id) {
    OrderBook.Order order = book.byId(id);
    if (order == null) {
        return ResponseEntity.status(404).body(Map.of("reason", "NO_ORDER"));
    }
    // An order is its customer's private data, and the attested answer says so.
    RequestContext.label(InfluenceClass.PRIVATE, order.customer());
    return ResponseEntity.ok(order);
}
```

`decide` returns `OK` or `INFLUENCE_DENIED`
([The request context](#the-request-context)), and the response stamp binds the
labels ([Response attestation](#response-attestation)).

### Properties

Every property the starter binds, from `PaztportProperties`; the jar carries Boot's
configuration metadata, so an IDE completes and describes them too. A list is
comma-separated, or a YAML list. "Required" says when the service does not start
without the property, or without a valid value; the subsection linked from each row
says the rest.

| Property | Default | Required | Meaning |
|---|---|---|---|
| `paztport.service-name` | none | Checked only on a partner's entry, but every service needs it | This service's policy name: the `svc` of its stamps, and the receiver a chain sent to it must name. |
| `paztport.instance` | `HOSTNAME`, else the host's name, else `service-name` | No | This instance's id, the `inst` of its stamps; a blank value counts as unset. |
| `paztport.origin` | `false` | No | Makes the service an entry point, which starts every request tree afresh and never attests ([The inbound filter](#the-inbound-filter)). |
| `paztport.verify` | `false` | No; needs `keyring-path`, `root-path` and `policy-key-path`, and is refused beside `partner.enabled` | Verifies every request in the current mode ([Modes and events](#modes-and-events)). |
| `paztport.mode` | `enforce` | No; read where `verify` is `true` | `enforce`, `audit` or `off`; a value the starter cannot read is `enforce`. |
| `paztport.admin-token` | none | No | Where it has text, a service with `verify` set to `true` registers `/admin/mode`, which answers only a request whose `X-Admin-Token` matches it and is verified unless `unverified-paths` lists `/admin`; unset or blank, there is no endpoint ([Unverified paths](#unverified-paths)). |
| `paztport.responder-url` | none | No; read where `verify` is `true` | The responder that events are also posted to, signed ([Modes and events](#modes-and-events)). |
| `paztport.event-key-path` | none | Where `responder-url` is set on a service with `verify` set to `true` | The private key that signs the events sent to the responder. |
| `paztport.event-timeout-ms` | `2000` | Positive, where events go to a responder | How long each event to the responder may take ([Timeouts](#timeouts)). |
| `paztport.key-path` | none | On the egress and on a partner's entry | This service's stamp key: it stamps the service's calls, attests its answers where it has a verifier, and signs a partner entry's session replies. |
| `paztport.keyring-path` | none | Wherever `verify`, an `overlap.*` or `operations.*` property, `boundary.url` or `partner.enabled` is set | `keyring.json`; with `root-path` and `policy-key-path` it gives the service a verifier, which also checks responses and decides attestation ([Lifetimes](#lifetimes)). |
| `paztport.root-path` | none | As `keyring-path` | `root.json`, the signed root. |
| `paztport.policy-key-path` | none | As `keyring-path` | `policy.pub`, the pinned policy key, under which the keyring and the root must verify. |
| `paztport.origins` | none | Wherever `keyring-path`, `root-path` and `policy-key-path` are set | The service names allowed to start a chain: the entry points this service accepts. |
| `paztport.proofs-path` | none | On the egress, and with either `operations.*` property | `proofs-<svc>.json`, this service's route proofs, which its calls carry. |
| `paztport.max-age-ms` | `5000` | No | How old the last stamp may be, in milliseconds: the call window, which also sizes the replay cache ([The replay cache](#the-replay-cache)). |
| `paztport.run-max-age-ms` | `max-age-ms` | No | How old the origin's stamp may be, in milliseconds; unset, it is `max-age-ms`, since inside one mesh a request tree is a single call. |
| `paztport.unverified-paths` | none | No; each entry must be one first path segment, or the service does not start | Path prefixes that are neither verified nor attested ([Unverified paths](#unverified-paths)). |
| `paztport.receiver-names.<host>` | none | No | The policy name of the receiver at a host that is not its name ([Outbound calls and response checks](#outbound-calls-and-response-checks)). |
| `paztport.tls-bundle` | none | No | The SSL bundle the service presents on its calls and its events; `false` is the same as unset ([Mutual TLS](#mutual-tls)). |
| `paztport.read-timeout-ms` | `30000` | Positive, in a service that uses it | How long a call through the starter's TLS client, or the egress's to the partner, may wait for its answer ([Timeouts](#timeouts)). |
| `paztport.overlap.keyring-paths` | none | No; needs `keyring-path`, `root-path` and `policy-key-path` | Further keyrings to pin beside `keyring-path` ([Overlap material](#overlap-material)). |
| `paztport.overlap.root-paths` | none | As `overlap.keyring-paths` | Further roots to pin beside `root-path`. |
| `paztport.operations.table-path` | none | No; needs `proofs-path`, `keyring-path`, `root-path` and `policy-key-path` | This service's own operation table: the inbound filter confirms each request's operation, and reads a keyed operation's key value ([Operations](#operations)). |
| `paztport.operations.receiver-tables` | none | As `operations.table-path` | The tables of the receivers this service calls, from which each call names its operation and key value. |
| `paztport.boundary.url` | none | No | The partner's `https` base URL; setting it makes the service the egress ([The egress](#the-egress)). |
| `paztport.boundary.partner` | none | Where `boundary.url` is set | The partner's entry service. |
| `paztport.boundary.tls-bundle` | none | Where `boundary.url` is set | The SSL bundle presented to the partner, apart from `tls-bundle`. |
| `paztport.boundary.partner-policy-key-path` | none | Where `boundary.url` is set | The partner's pinned policy key. |
| `paztport.boundary.blinding-key-path` | none | Where `boundary.url` is set | The egress's boundary key, 32 bytes as base64url. |
| `paztport.boundary.session-idle-ms` | `600000` | Positive, on the egress | How long the egress keeps a session no call has used, in milliseconds. |
| `paztport.partner.enabled` | `false` | No; refused beside `verify` set to `true` | Makes the service a partner's entry ([Partner mode](#partner-mode)). |
| `paztport.partner.reply-cert-path` | none | Where `partner.enabled` is set | `reply-cert.json`, the policy key's certificate for the key at `key-path`. |
| `paztport.partner.client-policy-key-paths` | none | Where `partner.enabled` is set | The `policy.pub` of each organisation whose sessions may be attested. |
| `paztport.partner.client-origins` | none | Where `partner.enabled` is set | The service names allowed to start a chain in a client's attested session. |
| `paztport.partner.unsafe-disabled` | none | No | Endpoints refused in an unsafe session, as `METHOD /pattern`. |
| `paztport.partner.max-sessions-per-peer` | `16` | At least 1, on a partner's entry | How many sessions one client certificate may hold. |
| `paztport.partner.session-idle-ms` | `900000` | Positive, on a partner's entry | How long the partner keeps a session no call has used, in milliseconds. |

### The inbound filter

The inbound filter caches the body, runs `HttpReceiver` through
`RequestContext.accept`, and serves the request in the scope that opens, which keeps
the received chain and influence there for the outbound calls. Where
`paztport.verify=true` it verifies the request in the current mode; such a service
also needs a keyring, a root and the policy pin (`paztport.policy-key-path`) and the
entry points it accepts (`paztport.origins`, required wherever those three paths are
set), or it refuses to start. Influence it can't read is answered
`400 {"reason":"INFLUENCE_MISMATCH"}` in every mode, unless verification refused the
request first. An origin (`paztport.origin=true`) starts every request tree afresh:
it ignores the chain and the influence a request brings.

A limit of the starter: each request body is held whole in memory, with no cap on its
size. The filter reads it before the receiver runs, since the request binding covers
all of it, on every path it filters, whether or not the service verifies; the partner
filter does the same. That suits the small bodies mesh calls carry, not large
uploads: a service that accepts larger bodies needs a size limit in front of the
filter.

### Unverified paths

`paztport.unverified-paths` lists path prefixes, each one first path segment: a `/`
and then letters, digits or `.` `_` `~` `-`, such as `/admin,/debug,/actuator`. An
entry that is blank, is `/` alone, or has a second `/`, a dot segment, a `;`, a `%`
or a `\` stops the service starting, so a trailing comma cannot leave an empty entry
and so every path unverified. The list is empty by default, so the inbound filter and
the partner filter verify every path, actuator included. A request whose raw request
URI is a listed prefix, or starts with one followed by `/`, and has no dot segment
and no encoded or backslash separator, is not filtered. The match is by whole
segment, so with `/admin` listed, `/admin/mode` is skipped but `/administration` is
verified. A dot segment is any segment that is `.` or `..` once a `;` parameter is
dropped and `%2e`, in either case, is read as `.`: `/admin/../pay`,
`/admin/%2e%2e/pay` and `/admin/..;/pay` are all verified, since whatever resolves
the dots could hand the request to a data-path handler. A URI holding `%2f` or `%5c`,
in either case, or a literal `\` is verified too, since something downstream might
read it as a separator. Only the plain spelling is skipped: with `/admin` listed,
`/%61dmin/mode`, `//admin/mode`, `/admin;x`, `/admin.` and `/ADMIN/mode` are all
verified, as is everything under a context path, which is part of the URI. So an
operator must call these endpoints by their plain path.

A path is listed because nothing calls it with a chain, so verifying it would
refuse every request in `enforce`: a probe, a scrape, an operator endpoint. A
handler there runs with no request scope: no influence, no verified chain, no
attestation, and at a partner it counts as unsafe. So keep data-path handlers off
these paths, and protect the endpoints themselves. For actuator, Boot's separate
management port (`management.server.port`) keeps it off the application port, so
nothing on the application port needs listing for it; `/admin/mode` is registered
only where `paztport.admin-token` has text, needs `X-Admin-Token` to match it, and
is listed here only if the service is to answer it without a chain.

### Modes and events

`paztport.mode` is `enforce` (the default), `audit` or `off`, and `/admin/mode`
switches it at run time. The first two are the protocol's
[modes](../spec/verification.md#modes-and-refusals): `enforce` refuses a request that
fails, and `audit` runs every check, refuses nothing (influence it can't read aside)
and reports each failure as an event with `audit: true`. `off` is not a protocol mode
but a deployment switch: the hop is not running Paztport. It verifies nothing,
attests nothing and sends no events, though it still carries the chain and influence
so its own calls are stamped, and its callers count its responses `local-untrusted`.
It is the baseline to measure Paztport against. A value the starter cannot read is
`enforce`.

A request that fails verification under `audit` or `enforce` is reported as an event,
logged as a `PAZTPORT_EVENT` line. Where `paztport.responder-url` is set it is also
signed with the key at `paztport.event-key-path` and posted to the responder's
`/events`, each event within `paztport.event-timeout-ms` ([Timeouts](#timeouts)); a
service with a responder and no event key does not start.

Every refusal, in the mesh and at a partner, is `{"reason":"<code>"}` and nothing
else, with `403` (or `400` for unreadable influence). The one exception is the `503`
with an empty body that a request gets under `enforce` when the nonce cache cannot
answer. The caller, who is usually the suspect, is never told who is suspected. The
event carries the attribution, `suspectSvc` and `suspectInst`. The
`PAZTPORT_TRACE request` line names only the authenticated peer's service
(`peer=<svc> (mTLS)`, or `peer=none`), not its address and not a suspect without a
peer. A partner sends no events, so for its refusals that trace line is all that is
kept: the peer's service, and no instance.

An optional `ReceivedRequestListener` hook lets an application observe each request
the filter receives. The SDK captures nothing itself: the mesh demo's request
capture, for its replay scenario, is a listener on that hook.

### Operations

A service may name its [operations](../spec/wire.md#operations) in an operation
table, `ops-<svc>.json`, which the policy tool covers in the signed root:

| Property | Meaning |
|---|---|
| `paztport.operations.table-path` | This service's own table (env `PAZTPORT_OPERATIONS_TABLEPATH`). The inbound filter then confirms each request's operation, and hands the receiver this table, from which it reads a keyed operation's key value. Default none. |
| `paztport.operations.receiver-tables` | The tables of the receivers this service calls, at most one per receiver, comma-separated (env `PAZTPORT_OPERATIONS_RECEIVERTABLES`). Each call to one of them names the operation it invokes. Default none. |

A table is used only where the signed root covers it: the service's proof bundle
holds a proof of the route `<svc>/ops:<opsHash>` that proves it against a pinned
root, the overlap's included. So either property needs `paztport.proofs-path`
and the keyring, root and policy pin, or the service does not start. At startup:
- the service's own table must be its own and covered, and each of its operations
  must be exactly one handler: an annotated handler mapping whose method (or
  none, which takes every method) is the operation's, whose pattern normalises to
  the operation's template (each whole-segment variable, `{id}` or `{id:\d+}`,
  becomes `{}`), and whose `params` condition is the operation's `query`
  (`params = "mode=refund"` for `{"mode": "refund"}`), or none for an operation
  without one. An entrance, the operations that share a method and a template,
  may so carry several operations, `charge` and `refund` on `POST /charge`, told
  apart by a query condition. The start fails where a mapping on a table entrance
  has a `params` condition the entrance does not hold (`!mode`, `mode`, two
  expressions, or a value no operation has), or where two handlers on one entrance
  share a `params` condition and are told apart only by headers, a media type
  (`consumes`, `produces`), a pattern's regex or a method condition (one mapped
  for the method, one for every method), or where one handler is two operations
  of an entrance; `consumes` on an entrance's only handler is allowed. Two beans
  that inherit one handler method are two handlers. A mapping on no table
  entrance is allowed; it is reachable only by routes that name no operation;
- a receiver's table the bundle holds no proof for is set aside, with one line
  naming the receiver, and calls to it name no operation, so the receiver then
  needs a route that names none;
- a proof that is in the bundle but does not verify against any pinned root stops
  the start.

The receiver never takes its operation from the request. Before it verifies, and
before the handler runs, the filter asks Spring's handler mappings, in the
`DispatcherServlet`'s order, which handler the request will reach, and the operation
is that handler, at the request's method and its pattern's template (the pattern
`HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE` holds). A request that will reach no
handler, a handler that is in no table, or a pattern with a wildcard, a rest-of-path
variable or a segment that mixes text and a variable, has no operation. So a request
the caller's table and Spring read differently, `/orders/` with a trailing slash,
`/items/abc` against `{id:\d+}`, a percent-encoded segment, or `?mode=%72efund`,
which Spring decodes to `refund` where a caller matches the raw query, is confirmed
as what Spring will run, or as nothing, and a chain naming the caller's choice is
refused `403 {"reason":"BINDING_MISMATCH"}` before any handler runs. Static
resources, router functions and other handlers that are not annotated have no
operation. A partner's entry names none.

An operation may declare a key, the item it acts on
([the key value](../spec/wire.md#operations)). The inbound filter hands the receiver
this service's own table, so `paztport.operations.table-path` alone makes keys work:
the receiver reads a keyed operation's key value from the raw request target, a chain
naming that operation is verified with the value in its nonce key, and a chain naming
it whose target gives none (a percent-encoded segment Spring decoded to reach the
handler, say) fails `BINDING_MISMATCH` before any nonce key is spent: refused
`403 {"reason":"BINDING_MISMATCH"}` under `enforce`, served unattested elsewhere. A
caller that holds the receiver's table (`paztport.operations.receiver-tables`) reads
the key value from the target it sends, and a call with none fails with
`IllegalArgumentException` before anything is signed
([paztport-http](#paztport-http)).

A service routes by method, path and query alone, and a request whose routing a
body field changes is refused under `enforce`. The operation is named from the
method, path and query. Spring's `params` condition reads the request's
parameters, which also hold a form body's fields (on a `POST` through
Paztport's filter, on `PUT`, `PATCH` and `DELETE` through Boot's form content
filter), while a caller's table matches the query alone. So a form body
(`application/x-www-form-urlencoded`) that meets a `params` condition makes
Spring choose another handler than the one named, and the request is caught at
dispatch, below: refused under `enforce`, served unattested elsewhere, whatever
the method. Handlers see form fields as usual. A handler that switches on a body
field is one operation, whatever it does: operations are told apart by the query
only.

A filter that changes the request's method, path or parameters after Paztport's
filter has run makes another handler run than the one confirmed. Such a filter is
caught, whether it wraps the request, forwards it, includes another path or
dispatches async work elsewhere, when the first handler the request reaches is about
to run: where the chain named an operation, the operation is worked out again from
that handler, and where it differs one warning names both operations and the answer
is not attested. For a keyed operation the key value is read again from the request
the handler gets, and a different value, or none, counts as another operation. Under
`enforce` the request is refused `403 {"reason":"BINDING_MISMATCH"}`, and no handler
runs for it afterwards; since an included handler cannot set the status, Paztport's
filter writes that refusal once the chain returns, unless the response is already
committed. In `audit`, and on a service that verifies only to decide attestation, it
is served unattested. A forward or include the confirmed handler starts itself, and
async work it resumes, are not checked again; the error page is not checked; and a
chain that names no operation had none confirmed, so it is not checked. The check
sees only handlers that a `DispatcherServlet` mapping runs: a forward or include to
another registered servlet is not checked. Such a servlet still runs, and where the
chain named an operation, an answer whose handler the check never saw (one a filter
writes itself, such as a 401, or another servlet's), or that an interceptor writes
when it stops the request before the handler runs, is not attested, while on a chain
that names no operation it is, there being no operation to vouch for. Paztport's own
last interceptor, registered at the lowest precedence, records that the handler was
reached, so an application interceptor ordered after it is not told apart. It is
registered through Spring MVC's configuration, so a handler mapping that an
application declares as a bean of its own does not run it, and that mapping's answers
to a chain naming an operation are not attested. A refusal here counts as served in
the `paztport.request` observation, which ends before the handler runs. Spring's
method-override filter, `HiddenHttpMethodFilter`
(`spring.mvc.hiddenmethod.filter.enabled`), is also refused at start: a service with
its own table does not start beside it.

Under `server.servlet.context-path` no operation matches: callers match the
full raw path, context path included, so such calls are refused at the source.
A `GET` mapping does not make `HEAD` an operation. The start check reads
annotated handler mappings only, so a table operation served by a router
function fails the start.

### Response attestation

A service attests a response only to a request whose chain passed the full live order
there: its own verifier, itself as receiver, the request's proof and influence, and
the peer under mutual TLS. That needs a stamp key and a keyring, root and policy pin,
and holds whether or not the service verifies requests: where `paztport.verify` is
false, the filter verifies the chain for attestation alone, and a failure only
withholds the attestation. The reason is that a response stamp is shaped like a
request stamp: attesting a chain nobody checked would let whoever sent it mint stamps
under the service's key. An origin never attests, nor does a service with no
verifier. A service that verifies requests and is in `off` mode, set at startup or
through `/admin/mode`, verifies nothing and attests nothing: `off` turns Paztport off
on that hop. That is fail-safe, because its callers record an unattested response as
`local-untrusted`. The stamp binds the status, the body and the labels its handler
added with `RequestContext.label`, and is sent as `X-Path-Response`. Refusals and
audit-mode failures are not attested. The stamp covers the whole body, so the body is
held until the handler returns, or, where a forward carries the request elsewhere,
until the forward returns, when the container closes the response. A forward's answer
is attested then where the forward writes into Paztport's buffer directly, and never
behind another filter's response wrapper: behind one that does not buffer the body it
arrives whole, and behind one that buffers it (`ShallowEtagHeaderFilter`, a logging
`ContentCachingResponseWrapper`) the body is lost, as the container has closed the
response before that filter copies it. A forward made through a named dispatcher
(`ServletContext.getNamedDispatcher`) does not pass through URL-mapped filters, so
its answer is finished only after the forward returns, and its body is lost. An async
response is not attested: its body is sent whole when the async work completes, with
no `X-Path-Response`.

Put together, an answer carries `X-Path-Response` only where all of these hold: the
receiver attests it, its chain having passed the live order here as above; the
response is not yet committed when the answer is finished; and, only where the chain
named an operation and the filter recorded it on the request's own dispatch, the
handler was checked as it was about to run, was reached, and was not found to be
another operation's ([Operations](#operations)). An answer to a chain that names no
operation is still attested, there being no operation to vouch for. So is the answer
to a forward that the filter verifies afresh, one an unverified path's handler starts:
the filter records no operation there, so that answer is attested when its chain
passes, with no dispatch check.

### The request context

**The context scope.** Influence is recorded only inside a `RequestContext`
scope. The filter opens one per request; background work, such as a scheduled
job, can open its own around one unit of work. Outside one, calls are still
stamped and responses still checked, but nothing is carried. A scope that other
code opened on a request thread and never closed is ended when the next request
arrives there, refused or not, with a warning from the logger
`org.paztport.http.RequestContext`; an answer whose rid or labels the response
binding cannot carry is served unattested, with a warning from
`org.paztport.http.HttpReceiver`.

**The verified chain.** `RequestContext.verifiedChain()` is the request's chain
once it has passed the full live order at this hop, and is null otherwise: in `off`
mode, after an audit-mode failure, at an origin, at a hop with no verifier, and
outside a request scope. Only `RequestContext.accept` sets it, from the result of
the receiver it ran: the one that decides attestation. Nothing is signed at the
boundary over anything else. `RequestContext.delivery()` is the delivery key of
that same request, set and cleared under the same conditions, and is null at a
partner.

**`PublicWrites`.** A bean with two methods. `decide(destinationOwner)` runs the
owner-aware rule over the request's influence and returns `OK` or
`INFLUENCE_DENIED`. The service supplies the destination owner from its own
records, never from request content; an unknown owner, or no request scope,
refuses. The rule judges the influence in the context, which is verified only
where the request's chain verified here: in `off` mode, after an audit-mode
failure, or in an unsafe partner session it may be incomplete or empty, and the
rule cannot refuse for what it is not shown, so a partner must list its public
writes in `paztport.partner.unsafe-disabled`. `shapedOnlyByTrusted()` answers
whether a write into the service's own trusted records (who holds a card, say)
may be made: true only in a scope whose chain verified here, with no `third-party`
and no `local-untrusted` influence, so that untrusted text cannot write a record
the rule later takes as fact. Each logs one `PAZTPORT_TRACE decision` line.

### Outbound calls and response checks

The outbound interceptor stamps every `RestClient` call through `HttpCaller`,
attaches the proof and the influence so far, having first removed every `X-Path-`
header the application set, and reads each response whole. The receiver it stamps, as
the last stamp's `rcv`, is the URL's host in lower case, so by default a service's
policy name is the host its callers reach it by (in the mesh demo, Docker Compose
service names): `https://payment:8443/pay` is stamped for `payment`. A call to a host
with no name (one holding a non-ASCII character) fails with
`IllegalArgumentException` before anything is signed. The same name is the response's
`<target>`. The [spec](../spec/verification.md#receivers-the-peer-and-attribution)
requires the receiver's policy name, so a destination reached by any other host (an
address, a load balancer's name) fails at the receiver (`BINDING_MISMATCH`), unless
it is mapped.

**Receiver names.** `paztport.receiver-names.<host>=<policy name>` names the receiver
for a host that is not its policy name:
`paztport.receiver-names.orders-internal=orders` stamps a call to
`https://orders-internal/x` for `orders`, and that call's response must then be
attested by `orders` and is recorded as `http:orders`. A dotted host is written as it
stands (`paztport.receiver-names.pay.svc.cluster.local=payment`), and a host not
listed is still its own name, so with nothing set nothing changes. The mapping is
configuration: nothing a request or a destination says changes it. Outside the
starter it is `HttpCaller.builder(...).receivers(Map)`. A name is a service, never an
operation: a call names the operation from the receiver's table
([Operations](#operations), above), so a name holding `#` is refused. A host is
matched as `URI.getHost()` gives it, its ASCII letters in lower case and nothing else
(a key that is not ASCII is refused when the table is built), and Spring Boot reads a
map key in brackets as written inside them:
- An IPv6 host keeps its brackets, so its key is written in two pairs:
  `paztport.receiver-names.[[::1]]=orders`, or `"[[::1]]"` in YAML or JSON.
- A trailing dot is not normalised: `orders.` and `orders` are different hosts,
  so list each spelling callers use. Boot drops a key's trailing dot unless the
  key is in brackets: `paztport.receiver-names.[orders.]=orders`.
- In an environment variable's name Boot reads `_` as a dot and lowercases the
  key, so `PAZTPORT_RECEIVERNAMES_PAY_SVC_CLUSTER_LOCAL=payment` maps a dotted
  host. A shell cannot name a variable with a hyphen, a bracket or a colon,
  though, so a key with one, `orders-internal` for instance, goes in
  `SPRING_APPLICATION_JSON` or a config file.

**Response checks.** Wherever there is a keyring, a root and the policy pin, the
interceptor checks the response's attestation: verified labels become influence
entries, and any other response becomes one `local-untrusted` entry (`src`
`http:<target>`, `h` the result hash).

### The replay cache

The verifier's replay cache forgets a key after `max(15 s, 2 × paztport.max-age-ms)`:
never sooner than twice the call window, which the verifier requires, and never so
late that it grows without end. An application that defines its own `NonceCache`
bean, to share one store across replicas, replaces it for requests only. Define at
most one: two `NonceCache` beans, neither `@Primary`, fail startup with Spring's own
error naming both. Startup also fails if that cache's `ttlMs()` is under
`2 × paztport.max-age-ms`. Responses are still checked with the starter's own
in-memory cache (the `ResponseVerifier` bean), since only the replica that sent a
call can check its answer, and a store that is down then fails no call the downstream
has already acted on. A cache that throws gives no verdict: under `enforce` the
filter answers 503 with an empty body and no content type, under `audit` it serves
the request unverified, and either way the `paztport.request` observation records the
error with reason `none`.

### Mutual TLS

`paztport.tls-bundle` names the Spring Boot SSL bundle the service presents on its
calls and its events. Both go out on one `PooledTlsClient` per application, a JDK
`HttpClient` speaking HTTP/1.1 that pools its connections, checks the server's name
against its certificate and honours the bundle's protocols and ciphers; its
`builder()` gives a client with TLS and no stamping, for calls that set their own
headers. Its timeouts are under [Timeouts](#timeouts), below.
`paztport.tls-bundle=false` is the same as leaving it unset, as for any Spring
condition: there is no `PooledTlsClient`, so the calls and the events both go without
one, which suits tests that mount no certificates. On a request that came with a
client certificate, `PeerCert` makes the verifier's peer from the leaf: the subject's
common name when there is exactly one and it is a UTF8String or a PrintableString,
else `""`, at the TCP address the connection came from. It reads the name, by the
[spec's rule](../spec/verification.md#http-requests-and-responses), from the
subject's DER bytes as they stand in the certificate's `TBSCertificate`, the bytes
the CA signed, and not from the JDK's `X500Principal`, which can hand back an
encoding rebuilt from its own parse. So `CN=a+CN=a`, a common name of any other type
(BMPString or IA5String, say), and a subject not in DER's shortest form name no
service. The keygen's certificates use UTF8String. A certificate that names no
service is still a peer, so the check runs and fails (`PEER_MISMATCH`); its trace
reads `peer="" (mTLS)`. Responses are checked with no peer.

### Timeouts

Every client the starter builds has them, so that a peer that takes a call and never
answers cannot hold the calling thread for ever. Both settings must be positive; one
that is not fails the startup, naming it, in a service that uses it.

| Property | Default | What it bounds |
|---|---|---|
| `paztport.read-timeout-ms` | `30000` | Each call through the `PooledTlsClient` (with `paztport.tls-bundle` set, every call on the shared `RestClient.Builder`, and its `builder()`'s), and each of the egress's calls to the partner: the whole exchange, from sending the request to the end of the response's body, on any JDK, so a peer that sends its headers and then stops part way through the body is cut off too. For that the pooled client reads each response whole, and holds it in memory, before the caller sees it, as the stamping interceptor does: it suits the small bodies mesh calls carry, not large streamed downloads, and a call through its `builder()` cannot stream its response. A call past it fails as a timeout: a `ResourceAccessException` from a `RestClient`, an `UncheckedIOException` from `BoundaryClient.post`. |
| `paztport.event-timeout-ms` | `2000` | Each event to the responder, whole: connecting, sending and reading the answer to its end, on any JDK, with a TLS bundle or without. An event is sent on the request thread before the refusal is answered, so a slow or silent responder would otherwise hold every refusal for as long as it liked; this caps that at this long per refusal, after which the event is given up and logged and the refusal goes ahead. Forged requests sent fast enough can still keep request threads busy, each for up to this long. |

Two more are fixed: the pooled client connects within 5 s, and the egress's
handshake has 10 s, whatever `paztport.read-timeout-ms` is. Without
`paztport.tls-bundle` the shared builder keeps the application's own request
factory, and its timeouts are the application's to set.

### The egress

Setting `paztport.boundary.url` makes the service the egress to another organisation,
with a `BoundaryClient` whose `post(path, json)` is the one way out. It needs
`paztport.boundary.partner` (the partner's entry service), `paztport.boundary.url`
(`https`, a scheme and an authority, no path; any other scheme fails the startup, as
`BoundaryClient.builder()` refuses one), `paztport.boundary.tls-bundle` (its own SSL
bundle, apart from `paztport.tls-bundle`, so the partner's CA is trusted only for the
partner), `paztport.boundary.partner-policy-key-path` (the partner's pinned policy
key) and `paztport.boundary.blinding-key-path` (its boundary key, 32 bytes as
base64url, which the keygen writes as `boundary.key`; any other length fails the
startup), as well as its own stamp key, proofs, keyring, root and policy pin; the
context fails naming what is missing. The boundary key never leaves the organisation
and belongs to this one egress service: the salts it derives do not name the egress,
so it must not be shared with another service. Replicas of the egress share it.

The first call opens a session and every call after it shares it. `post` throws
`IllegalStateException` before anything, the handshake included, is sent when
`verifiedChain()` is null. In an attested session it sends the influence blinded: one
entry per class and owner, `src` `boundary:<this service>`, `h` a salted commitment
to that group's originals (see
[blinded influence](../spec/sessions-and-influence.md#blinded-influence)). It signs
one boundary stamp over that list and sends the proof for `<this service>/<partner>`;
in an unsafe one it sends only `X-Path-Session`. A `BoundaryListener` bean, if there
is one, gets `sent(rid, partner, originals, sent)` in each attested call, after the
session opens and before the request goes; if it throws, the request is not sent and
`post` throws. Keep the originals it is given: `opening(rid, cls, owner, originals)`
gives what to reveal to open the entry sent for that group, its salt derived again
from the key. Nothing about the originals is logged.

A reply that fails the client's check, an HTTP or I/O error (a `404` too) or no
answer in 10 s, the handshake's timeout, is followed by a handshake with no root, and
the session is unsafe. That is the **fallback session**: the egress took it because
it got no answer it could check, not because the partner said unsafe, so it is kept
for at most 30 s from when it was opened (or less, if no call uses it for the idle
period below). In it calls carry only `X-Path-Session`, as in any unsafe session. A
passing failure (a partner restarting, a network blip) therefore does not leave the
egress unsafe for the life of the process: the first call after the 30 s tries the
full handshake again. A genuine unsafe reply to the full handshake (the partner has
not pinned this organisation) is the partner's answer, not a fallback, and is kept
like an attested session.

Each call has the read timeout, `paztport.read-timeout-ms` ([Timeouts](#timeouts));
one past it throws `UncheckedIOException` and keeps the session, as any failed call
does, and is not retried. A `403 SESSION_UNKNOWN` clears the session, so the next
call opens a new one; the refused call is not retried. A `403 POLICY_EXPIRED` clears
it too: once the egress's own root or keyring passes its `notAfter` while it runs,
the partner refuses every call in the attested session with it, and the next call's
handshake gives an unsafe session. The egress logs one warning naming which of its
own files has expired; renew them and restart it. Since a refused call is not
retried, the egress also drops a session no call has used for
`paztport.boundary.session-idle-ms` (default `600000`, 10 minutes), before the
partner forgets it, and the next call opens a new one. Keep it below the partner's
`session-idle-ms`.

Every partner reply becomes one `local-untrusted` entry, and the request's own
response is labelled `local-untrusted`, so a handler that relays the reply passes it
on as untrusted. A path that would change the host or not be sent as given is refused
before any I/O. `BoundaryClient`'s builder refuses a root or keyring that does not
verify under the service's own policy key.

### Partner mode

`paztport.partner.enabled=true` makes the service a partner's entry. It answers
`POST /paztport/session` and registers `PartnerFilter` in place of `InboundFilter`:
no modes, no responder events, no attested responses. It cannot be combined with
`paztport.verify=true`. It needs `paztport.service-name`, `paztport.keyring-path`,
`paztport.root-path`, `paztport.policy-key-path` and `paztport.key-path`, the entry
service's own key, which signs its session replies, plus:

| Property | Meaning |
|---|---|
| `paztport.partner.reply-cert-path` | `reply-cert.json`: the policy key's [reply certificate](../spec/wire.md#the-reply-certificate) for the key at `paztport.key-path`. Required. |
| `paztport.partner.client-policy-key-paths` | The `policy.pub` of each organisation whose sessions may be attested. Required. |
| `paztport.partner.client-origins` | The service names allowed to start a chain in a client's attested session. Required. |
| `paztport.partner.unsafe-disabled` | Endpoints refused in an unsafe session, as `METHOD /pattern`; the reply's `disabled`. |
| `paztport.partner.max-sessions-per-peer` | How many sessions one client certificate (issuer and common name) may hold; its least recently used is evicted when it opens one more. Default `16`. |
| `paztport.partner.session-idle-ms` | How long a session no call has used is kept, in milliseconds. Default `900000` (15 minutes). |

The policy private key is not configured anywhere: a reply carries the policy
key's signature over the keyring and the certificate, and is signed with the
entry service's key. Startup fails, naming the property, unless the keyring
verifies under the pin and holds `paztport.service-name`, that entry is the key at
`paztport.key-path`, and the certificate verifies under the pin, names that service
and that key, and has not expired. Clients refuse a reply once its certificate has
expired, so reissue it (the policy tool's `PAZTPORT_REPLY_CERT_SVC`) and restart the
service before then. Setting `paztport.key-path` also gives the service a stamper
and the stamping customizer, which a partner's entry does not use.

Sessions are kept by id, each with the issuer and common name of the client
certificate that opened it. A handshake adds a session and replaces none, so
replicas sharing a certificate each keep their own up to the cap, beyond which
they evict each other's least recently used sessions, and a call that then names
an evicted session is refused (the client opens a new one on its next call); a
peer can evict only its own sessions, so memory is bounded by the peers the
trusted CAs vouch for times the cap. A handshake body over 256 KiB is
`INVALID_PARAMS`, and a certificate with no single common name is `NO_SESSION`.
A replica's sessions share its one in-memory nonce cache. A call with no
`X-Path-Session` is unsafe; one naming no live session opened by the same issuer
and common name (another peer's, an evicted or an expired one; issuers are told
apart by their distinguished name, not by the CA's key) is `403 SESSION_UNKNOWN`.
In an attested session the chain is verified by that session's own verifier, and
the handler gets the verified influence and chain. The client's boundary chain is
also the handler's `inboundChain()`, so a partner entry should not call into its
own mesh from a partner request: its stamps would append to the client's chain.
`PartnerGate`, a handler interceptor, refuses with `403 UNSAFE_SESSION` any request
outside an attested session that matches an `unsafe-disabled` entry, by the
handler Spring dispatched to, so `/refund;x=1` is `POST /refund`; a `HEAD` is
refused where the matching `GET` is. The handshake endpoint and the
[unverified paths](#unverified-paths) are not filtered, so a handler there runs
with no influence and counts as unsafe.

### Lifetimes

Every service that loads `paztport.keyring-path` and `paztport.root-path` (the mesh
verifier, the egress `BoundaryClient`, the partner) refuses to start if either has no
`notAfter` (its reader refuses it as malformed) or is past it, the latter with a
message naming the property and saying to re-sign with the policy tool
(`PAZTPORT_RENEW=true` renews without rebuilding), and logs one warning naming the
file and its `notAfter` when 42 hours (a quarter of the default week) or less remain.
A partner whose own root or keyring expires *while running* does not stop, since that
would cut off callers it serves without attestation too: it opens only unsafe
sessions, as it would for any unattested caller, and logs the reason once. Renew the
files and restart it.

### Overlap material

A verifier can pin more than its own keyring and root, to roll out a rebuilt root (a
new tree, with new proof bundles) or a rotated key:

| Property | Meaning |
|---|---|
| `paztport.overlap.keyring-paths` | Further `keyring.json` files to pin beside `paztport.keyring-path`, comma-separated (env `PAZTPORT_OVERLAP_KEYRING_PATHS`). Default none. |
| `paztport.overlap.root-paths` | Further `root.json` files to pin beside `paztport.root-path`, comma-separated (env `PAZTPORT_OVERLAP_ROOT_PATHS`). Default none. |

Each must verify under `paztport.policy-key-path` and be current at startup, or the
service does not start, and they need the verifier's own three paths too. They add
only to what the verifier accepts: the service's own keyring and root still serve its
partner replies and its egress. Roll out in three steps, each service restarting as
its properties change: every verifier adds the new root (or keyring) to
`paztport.overlap.root-paths` (`keyring-paths`); then each holder switches to the new
tree's proof bundle (`paztport.proofs-path`), or the rotated service to its new key
(`paztport.key-path`) and the new keyring as its `paztport.keyring-path`; then every
verifier makes the new file its `paztport.root-path` (`paztport.keyring-path`) and
drops the overlap entry, which unpins the old. While both are pinned, both are
honoured, so a key retired because it was compromised is unpinned at once, with no
overlap: every verifier takes the new keyring as its `paztport.keyring-path` in one
step.

### Trace lines

The starter logs one `PAZTPORT_TRACE` line per request verified, including one
verified only to decide attestation, and per response received (with `reason=-` where
no verifier is configured to check it). Besides the request and response lines, each
value passed through `LogSafe`:
- `PAZTPORT_TRACE session partner=<svc> check=<ReplyCheck>|- status=attested|unsafe`,
  at the egress after a handshake; `check` is `-` when the first handshake got no
  reply.
- `PAZTPORT_TRACE boundary rid=<rid> receiver=<partner> session=attested|unsafe
  status=<http> classes=<a,b>|-`, at the egress after a call; the classes are those
  actually sent, so `-` when unsafe.
- `PAZTPORT_TRACE session peer=<svc> status=attested|unsafe`, at the partner.
- `PAZTPORT_TRACE request … session=attested|unsafe`, at the partner: the request
  line plus the session's status; one with no session header carries `reason=-`
  and is not verified, and a `SESSION_UNKNOWN` refusal carries `session=unknown`.
- `PAZTPORT_TRACE decision rid=<rid>|- receiver=<svc>
  rule=public-write|trusted-record|unsafe-session reason=<code> ✓|✗ classes=<a,b>|-`,
  from `PublicWrites` and from `PartnerGate`; it never names an owner.

### Metrics

The filters and the outbound interceptor record each verification result as a
Micrometer observation, so an application with Spring Boot's observation and
metrics auto-configurations (Actuator, for one) gets a timer for each, with no
setting of the starter's. Where the context has no `ObservationRegistry` bean the
starter records into `ObservationRegistry.NOOP` and the application runs exactly
as before; with Boot's observation auto-configuration but no meter registry, the
registry has no meter handler and nothing becomes a meter. The names, keys and
values are those of `PaztportObservation`:

| Observation | Recorded by | Keys | Values |
|---|---|---|---|
| `paztport.request` | `InboundFilter` | `mode`, `reason`, `outcome` | `mode`: `off`, `audit` or `enforce` where the service verifies requests (`paztport.verify=true`), otherwise `none`. |
| `paztport.partner.request` | `PartnerFilter` | `session`, `reason`, `outcome` | `session`: `attested` where the call was verified in an attested session, served or refused; `unknown` where it names a session its peer does not hold, or where the decision threw; otherwise `unsafe`. |
| `paztport.response` | `OutboundInterceptor` | `reason` | |

`reason` is the name of the verification result's reason code (`OK`, `CHAIN_MISSING`,
…), or `none` where no verification ran or its result was not available: a hop
switched `off`, an unsafe or unknown partner session, a caller with no verifier to
check its response, or a decision that threw. A service that does not verify requests
has `mode` `none` but records the reason of the check that decides whether it
attests. `outcome` is `refused` when the request is answered with a refusal in
place of the handler's answer, or when the decision threw, otherwise `served`.
It is there because the reason alone does not show every refusal: under `audit`,
a request whose influence the filter cannot read is refused `400` while its
reason is the verifier's code, `INFLUENCE_MISMATCH` unless an earlier check
failed, a code `audit` otherwise serves; under `off`, and where the service does
not verify requests, its reason is `none`. Only `outcome` says it was refused.
Where a decision throws, the observation carries the error and is stopped before
the exception goes on.

Actuator with a Prometheus registry exports each as a timer, such as
`paztport_request_seconds_count`, `_sum` and `_max`, labelled `mode`, `reason` and
`outcome` and also `error`, which Micrometer adds. The count is the number of
requests. A long-task timer goes with each, created when the observation starts, so
it carries only the tags known then: `paztport.request.active` carries `mode`, and
`paztport.partner.request.active` and `paztport.response.active` carry none, since
`session`, `reason` and `outcome` are set at stop.

Each timer spans the decision only: `RequestContext.accept` for the filters and the
response check for the interceptor. It is stopped before the handler runs, so it
says nothing of how long the handler takes or of an answer written later. The
decision does include what the receiver calls out to: the `ReceivedRequestListener`,
where there is one, and, for a request that fails verification under `audit` or
`enforce` where a responder is configured (`paztport.responder-url`), the event
POST, which is sent before the request is answered and is bounded by
`paztport.event-timeout-ms`. The `_sum` and `_max` of failures include that wait.

The starter's filters run at `HIGHEST_PRECEDENCE`, outside Boot's
`ServerHttpObservationFilter` (`HIGHEST_PRECEDENCE + 1`), so `http.server.requests`
does not count a request Paztport refuses, and with tracing neither filter's span
is a child of the server span.

Nothing from a request is a tag: no service name, request id, suspect, peer or
target. A tag from traffic would make a series for each value, and a count that
names a service or a peer is more than a metric needs to know; every value the
starter sets is one of the fixed words above or a reason code's name, so the series
stay few whatever arrives. Those values are in the `PAZTPORT_EVENT` and
`PAZTPORT_TRACE` logs, which are unchanged. The control plane (the handshake
endpoint and the unverified paths) is not observed.

Boot's standard property switches an observation off by name:
`management.observations.enable.paztport.request=false`, or
`management.observations.enable.paztport=false` for all three.

## tools/keygen

One-shot job, `keygen <outDir> <service>... [--tls-only name...] --org <name>`:

- a per-service Ed25519 stamp key (`<svc>.key`) and a policy key (`policy.key`);
- `keyring.json`, signed by the policy key, valid for `PAZTPORT_POLICY_DAYS` days
  (default 7), and `policy.pub`, the pin;
- one CA per run, named by `--org`, whose key is written alone to
  `ca/ca.key`, outside `tls/`, so it sits apart from the certificates and keys that
  services mount (each service mounts only its own files, one by one);
- `tls/ca.crt`, and `tls/<name>.crt` and `.key` for every service and every TLS-only
  name (those after `--tls-only`; none if it is left out), which get a certificate
  but no stamp key, so they never enter the keyring. Certificates are ECDSA P-256
  with `CN` and a DNS `SAN` of the name, subject and authority key identifiers, and
  are valid as both server and client;
- `boundary.key`, the egress's boundary key (32 random bytes as base64url), written
  only when it does not exist: every other key is new on each run, but a new
  boundary key would make the influence entries sent under the old one unopenable.
  An existing one that is not 32 bytes is refused, naming the file, and nothing is
  written. It is for the mesh's one egress service and its replicas.

Private keys and the boundary key are written owner-read/write only.

## tools/policy-tool

One-shot job, `policy-tool [--renew] [paths.yaml] [keysDir] [outDir]` (defaults
`policy/paths.yaml`, `out/keys`, `out/policy`). It reads `keysDir/policy.key` and
`keysDir/keyring.json`, and signs the root and the keyring, both valid for
`PAZTPORT_POLICY_DAYS` days (default 7). `paths.yaml` is read by SnakeYAML with its
safe constructor: one mapping whose only key is `paths`, no duplicate keys, no type
tags. It has two modes:

- **Rebuild**, the default: `paths.yaml` → salted tree → signed `outDir/root.json`
  plus one proof bundle per service (depth `PAZTPORT_PROOF_DEPTH`, default 8), and
  `keyring.json` re-signed beside it. The tree is new, so the `rootId` and every
  bundle change, and every service holding a root or proofs must reload them
  together. Rebuild when the routes change. It also reads every `ops-<svc>.json`
  beside `paths.yaml`: an operation table in the [spec](../spec/wire.md#operations)'s
  file format, whose `service` must be the `<svc>` in its name. Each table's route
  `<svc>/ops:<hash>` joins the tree, its proof goes in the bundles of `<svc>` and of
  every service holding a route that ends at `<svc>`, whether or not that route names
  an operation, and the table is copied to `outDir/ops-<svc>.json` after the bundles.
  A route node `<svc>#<op>` must name an operation of that table, or the run is
  refused (exit 2, nothing written); a service with a table may still be named alone
  in a route. A rebuild prints one line for each keyed operation, such as
  `policy-tool: orders#reserve is keyed by path segment 1, at most 128 characters`,
  so the owner sees what each table opens to a caller's choice.
- **Renew**, with `--renew` or `PAZTPORT_RENEW=true` (so the same command line serves
  both): `outDir/root.json` and `keyring.json` signed again with a new `notAfter`,
  keeping the root's `root` and `rootId`, so the proof bundles stay valid and are not
  touched, and holders can pick up the renewed files one at a time. The new
  `notAfter` is the run's time plus `PAZTPORT_POLICY_DAYS`, so a renewal can shorten
  a longer existing window. `paths.yaml` is not read. Renewal is the routine
  operation, run well before `notAfter`; expired files are renewed all the same.
  Tables are not read.

Either mode first checks that the keyring has a `notAfter` and verifies under the
policy key it names, expired or not, and that that key is the one in `policy.key`;
renewing also checks the root verifies under it. Rebuilding also refuses a route node
the [spec](../spec/wire.md#routes) forbids (empty, `.`, `..`, or holding `/`, `\`,
`|` or a lone surrogate). The checks are core's `PolicyOwner` and `Routes`; the tool
only reads arguments and files. Any of these failing is refused, exit 2, with nothing
written. The keyring is written in place (truncated and rewritten, never renamed
over), so it can be a single file mounted writable into the tool. It is written
first, so a keyring the tool cannot write stops the run with
`policy-tool: cannot write <file>: <reason>`, the file system's reason
(`Read-only file system`, `Permission denied`, `No space left on device`), and
nothing written. I/O errors like that one exit 1, not 2. Writing in place is not
atomic: a crash or a full disk part-way through leaves the keyring empty or
truncated, which the next run refuses, and since the tool only re-signs a keyring,
recovering means new keys from the keygen. A rebuild vouches that the routes in
`paths.yaml` are the ones allowed now; a renewal, that the existing tree's routes all
still are, since narrowing a policy is a rebuild. Re-signing the keyring vouches that
each listed key is still its service's current key: the tool can check only that this
policy key signed the keyring before, so retiring a key, which needs a new keyring
rather than a renewed one, is the policy owner's to ensure.

A third run rotates one service's key, `policy-tool --rotate <svc> [keysDir]` or
`PAZTPORT_ROTATE=<svc>` (exclusive with `--renew`; usage and exit 2 if both are
given). It reads `keysDir/policy.key` and `keysDir/keyring.json` and writes
`keysDir/<svc>.next.key`, a new key in the keygen's format, and
`keysDir/keyring.next.json`, the keyring with that service's key replaced and every
other kept exactly, signed by the policy key and valid for `PAZTPORT_POLICY_DAYS`.
`keyring.json` and `<svc>.key` are left as they are. It checks the keyring as the
other modes do, refuses a service the keyring does not name, and refuses, writing
nothing, if either output exists already (exit 2). The rollout, which the
[spec](../spec/wire.md#proof-bundles-and-who-holds-what) describes as the overlap, is
then, in the Spring starter: every verifier adds `keyring.next.json` to
`paztport.overlap.keyring-paths`; the service switches its `paztport.key-path` to
`<svc>.next.key` and its `paztport.keyring-path` to `keyring.next.json`; then every
verifier makes `keyring.next.json` its `paztport.keyring-path` and drops the overlap
entry, which unpins `keyring.json`. Once the rollout is done, the policy owner moves
`keyring.next.json` over `keyring.json` and `<svc>.next.key` over `<svc>.key`, before
any later `--renew` or `--rotate`, which read `keyring.json`: a later `--renew` of
the old `keyring.json` would re-sign the retired key. A key retired because it was
compromised gets no overlap: every verifier takes `keyring.next.json` as its
`paztport.keyring-path` at once, as the spec says.

When `PAZTPORT_REPLY_CERT_SVC` names a service, building or renewing also writes
`outDir/reply-cert.json`, a
[reply certificate](../spec/wire.md#the-reply-certificate) for that service's key in
the keyring, valid for `PAZTPORT_REPLY_CERT_DAYS` days (default 7), set apart from
the policy's lifetime. It refuses, writing nothing, a service the keyring has no key
for. A rotation writes no certificate and ignores `PAZTPORT_REPLY_CERT_SVC`, though
with it set a malformed `PAZTPORT_REPLY_CERT_DAYS` still refuses the run (exit 2),
since the settings are read before the mode runs. The tool prints only file names,
their `notAfter`, the certificate's service and the keyed operations.

## tools/bench

[JMH](https://github.com/openjdk/jmh) micro-benchmarks of the primitives a verifying
hop pays for, the timed rows of the mesh demo's
[cost table](../../poc-demos/java-mesh/README.md#measurements): the depth-8 Merkle
proof walk (`MerkleProof.verify`), the request binding of the `POST /pay` that
`orders` sends (`RequestBinding.compute`: method and target checked as well-formed,
joined with the body by newlines, hashed with SHA-256 and base64url encoded), and
Ed25519 signing and verifying of one stamp's signed bytes (`Crypto.sign`,
`Crypto.verify`). The inputs are built as the mesh builds them at `payment`: a
keyring the policy key signs, a root over the mesh's routes at the policy tool's
default depth, and the two-stamp chain `gateway` and `orders` sign, with its proof.
The setup checks that the keyring, the root, the proof and the signature all verify,
so every benchmark times the path a legitimate request takes.

`./run bench` from the repository root builds the module and runs JMH on the JDK
Maven uses, with the module's classes and its dependencies on the class path, so the
mesh demo's figures, taken on JDK 25, the services' runtime, are reproduced with
`JAVA_HOME=<a JDK 25> ./run bench`; JMH's output names the JDK it ran on. Options
after `bench` go to JMH (`-f 3` for three forks, `-rf json` for a results file);
JMH's own help is `./run bench -h`. `mvn verify` builds the module but runs no
benchmark. JMH is GPLv2 with the Classpath Exception. No built artefact bundles it,
and the libraries and the demos don't use it.
