# Java SDK

A Maven build (`paztport-sdk-parent`, JDK 25 or newer; the Spring starter needs
Spring Boot 4.1) of three libraries and two one-shot tools. Every cryptographic
primitive comes from the standard JDK; `keygen` uses Bouncy Castle only to build
its X.509 certificates, which the JDK signs.

It implements protocol v3 as the [spec](../spec/README.md) defines it, and is the
SDK that carries v3 over HTTP. It replays `spec/vectors/v3.json`, the Java-exported
`http-v3.json`, `v1.json`, and all of `v2.json` but the result and `tools/call`
bindings, which only MCP uses.

```bash
mvn -q install   # build, test, and install into the local Maven repository
```

The Java demo ([poc-demos/java-mesh](../../poc-demos/java-mesh/README.md)) depends
on the installed artifacts, so install the SDK before building it.
`./run java-mesh` and `./run test` do this for you.

## paztport-core

The protocol, with no transport. It never touches TLS or HTTP: a transport hands
the verifier the binding of what was received, the receiver's name and, when it
has one, the authenticated peer.

- **Stamps and chains.** `StampV3` signs and refuses a field holding `|` or a lone
  surrogate, or a `ts` outside ±(2^53 − 1). `Chains` reads a chain off the wire
  strictly, as checks 1 and 2 of the live order, and never throws; `ts` is read by
  value, so `1.0` is 1. A v2 chain parses only as legacy, and a v1 chain, which has
  no `v`, not at all.
- **Verifying.** `VerifierV3` runs the live order: first its own policy's window
  (`POLICY_EXPIRED`, naming no one, once its clock passes the earlier `notAfter` of
  its keyring and root), then the twelve checks. `VerifierConfigV3.pinned` checks the
  keyring and the root against the pinned policy key, and refuses to build a config if
  either fails, is in the old form or has expired. `OfflineVerifier` re-checks a
  recorded chain, all v3, or all v2 as legacy.
- **Stamping.** `StamperV3` stamps a hop's outbound call, starting a chain only at
  an origin, and stamps a response as one more stamp on the request chain, back to
  the caller.
- **Bindings, influence and labels.** `Bindings` (the prompt and response
  bindings, which refuse a lone surrogate), `Influence`, `InfluenceRule` (the one
  owner-aware rule) and `ContentLabel`.
- **Sessions.** `Sessions`: the handshake as messages, with no transport. `status`
  and `checkReply` judge both sides' roots and keyrings at the handshake: old form or
  past `notAfter` makes the session unsafe, or the reply `BAD_SIGNATURE`, and a
  partner whose own material has expired opens every session unsafe.
- **JSON in and out.** No public signature names a JSON library. Each value type
  writes its wire form with `toJson()` and reads it with a static `parse(String)` on
  the type, such as `KeyringFile.parse` or `SessionRequest.parse`, which throws
  `IllegalArgumentException` for anything malformed, text that is not one JSON value
  included. A reader of a whole HTTP body also takes its bytes, `parse(byte[])`. A
  list is read and written by the class that owns it (`Influence.parse`,
  `ContentLabel.parseAll`, `Chains.parse`). A session reply is judged as received, so
  it has no reader: `Sessions.checkReply` takes its text or bytes. The verifiers take
  the stamps, influence and proof as the JSON text received and read it themselves,
  so text that is not JSON is a typed rejection at the check that reads it. `Jcs`
  canonicalises JSON text. The `org.paztport.core.encoding` package states the rule.
- **Encodings and keys.** `Base64Url` (the TypeScript SDK's decode rule exactly),
  `Jcs`, `KeyringFile` (the signed `keyring.json`), `ReplyCert` (`reply-cert.json`),
  `KeyFiles`, `SignedRoot`, the Merkle tree and `PolicyBuilder`, `Routes`, and
  `EventVerifier` for events sent to a responder.
- **v1**, kept for `v1.json` only: `StampV1`, `PathChainV1`, `VerifierV1` and the
  rest carry a `V1` suffix.

## paztport-http

v3 over HTTP, with no web framework. `PaztportHeaders` names the five headers:
`X-Path-Chain`, `X-Path-Proof`, `X-Path-Influence`, the response's
`X-Path-Response`, and `SESSION`, `X-Path-Session`, which names the session a call
is in. `RequestBinding` computes `bind` over the method, the raw path plus `?` and
the raw query when there is one, and the body. `HttpV3` encodes the headers and
decodes them to the JSON text they carry, builds a request's verify input (nonce
key `<rid>|<last svc>|req`), computes a response's result hash over its status and
body, and checks a response's attestation against the chain the caller sent (nonce
key `<rid>|<target>|resp`). A service therefore calls a given receiver at most
once per request tree. `HttpSessions` fixes the handshake's names (`PATH`,
`/paztport/session`, and the error codes `INVALID_PARAMS` and `NO_SESSION`) and
writes `{"error":"<code>"}`; core reads the bodies, a request with
`SessionRequest.parse(byte[])` and a reply with `Sessions.checkReply(byte[],
...)`, as strictly as `HttpV3` reads a header (trailing tokens are refused).
`HttpVerifyRequestsV1` is the v1 equivalent, kept for `v1.json`.

## paztport-spring

Glue, configured through `paztport.*` properties. It is built for Spring Boot 4.1
(Spring Framework 7) and does not run on Boot 3: it uses classes Boot 3 doesn't
have, such as `org.springframework.boot.restclient.RestClientCustomizer`.

No SDK type is a JSON tree, so the SDK works beside whichever Jackson the
application uses: Boot 4's web layer and `RestClient` use Jackson 3
(`tools.jackson`), and the SDK reads with Jackson 2 inside. An SDK value's JSON,
such as `Opening.toJson()`, goes to Spring MVC or a `RestClient` as that `String`,
labelled `application/json`, so it is written exactly as it stands; a body goes to
the SDK as the bytes or text it arrived in, as the starter's
`PartnerSessionController` hands a session request to `SessionRequest.parse`.

- **The inbound filter** caches the body, opens a `PaztportContext` scope for the
  request, and keeps the received chain and influence there for the outbound
  calls. Where `paztport.verify=true` it verifies the request in the current mode;
  such a service also needs a keyring, a root and the policy pin
  (`paztport.policy-key-path`), or it refuses to start. Influence it can't read is
  answered `400 {"reason":"INFLUENCE_MISMATCH"}` in every mode, unless verification
  refused the request first. An origin (`paztport.origin=true`) starts every
  request tree afresh: it ignores the chain and the influence a request brings.
- **Modes.** `paztport.mode` is `enforce` (the default), `audit` or `off`, and
  `/admin/mode` switches it at run time. The first two are the protocol's
  [modes](../spec/verification.md#modes-and-refusals): `enforce` refuses a request
  that fails, and `audit` runs every check, refuses nothing (influence it can't
  read aside) and reports each failure as an event with `audit: true`. `off` is not
  a protocol mode but a deployment switch: the hop is not running Paztport. It
  verifies nothing, attests nothing and sends no events, though it still carries the
  chain and influence so its own calls are stamped, and its callers count its
  responses `local-untrusted`. It is the baseline to measure Paztport against. A
  value the starter cannot read is `enforce`.
- **Refusals.** Every refusal, in the mesh and at a partner, is
  `{"reason":"<code>"}` and nothing else, with `403` (or `400` for unreadable
  influence). The caller, who is usually the suspect, is never told who is
  suspected. The event carries the attribution, `suspectSvc` and `suspectInst`.
  The `PAZTPORT_TRACE request` line names only the authenticated peer's service
  (`peer=<svc> (mTLS)`, or `peer=none`), not its address and not a suspect without
  a peer. A partner sends no events, so for its refusals that trace line is all
  that is kept: the peer's service, and no instance.
- **Unverified paths.** Neither the inbound filter nor the partner filter runs on
  the control plane: a request whose raw request URI is `/admin`, `/debug` or
  `/actuator`, or starts with one of them followed by `/`, and has no dot segment.
  The match is by whole segment, so `/admin/mode` and `/actuator/health` are
  skipped but `/administration` and `/debugger` are verified. A dot segment is any
  segment that is `.` or `..` once a `;` parameter is dropped and `%2e`, in either
  case, is read as `.`: `/admin/../pay`, `/admin/%2e%2e/pay` and `/admin/..;/pay`
  are all verified, since whatever resolves the dots could hand the request to a
  data-path handler. Only the plain spelling is skipped: `/%61dmin/mode`,
  `//admin/mode`, `/admin;x`, `/admin.` and `/ADMIN/mode` are all verified, as is
  everything under a context path, which is part of the URI. So an operator must
  call these endpoints by their plain path. They are skipped because they are operator endpoints, not
  steps on a request's path: nothing calls them with a chain, so verifying them
  would refuse every one in `enforce`. A handler there runs with no request scope:
  no influence, no verified chain, no attestation, and at a partner it counts as
  unsafe. So keep data-path handlers off these paths, and protect the endpoints
  themselves; `/admin/mode` needs `X-Admin-Token` to match `paztport.admin-token`,
  and is disabled without one.
- **Response attestation.** A service attests a response only to a request whose
  chain passed the full live order there: its own verifier, itself as receiver, the
  request's proof and influence, and the peer under mutual TLS. That needs a stamp
  key and a keyring, root and policy pin, and holds whether or not the service
  verifies requests: where `paztport.verify` is false, the filter verifies the chain
  for attestation alone, and a failure only withholds the attestation. The reason
  is that a response stamp is shaped like a request stamp: attesting a chain nobody
  checked would let whoever sent it mint stamps under the service's key. An origin
  never attests, nor does a service with no verifier. A service that verifies
  requests and is in `off` mode, set at startup or through `/admin/mode`, verifies
  nothing and attests nothing: `off` turns Paztport off on that hop. That is
  fail-safe, because its callers record an unattested response as `local-untrusted`.
  The stamp binds the status, the body and the labels its handler added with
  `PaztportContext.label`, and is sent as `X-Path-Response`. Refusals and audit-mode
  failures are not attested. The stamp covers the whole body, so the body is held
  until the handler returns. An async response is not attested: its body is sent
  whole when the async work completes, with no `X-Path-Response`.
- **The outbound interceptor** stamps every `RestClient` call through `StamperV3`,
  attaches the proof and the influence so far, and reads each response whole. The
  receiver it stamps, as the last stamp's `rcv`, is the URL's host, so by default a
  service's policy name is the host its callers reach it by (in the mesh demo,
  Docker Compose service names): `https://payment:8443/pay` is stamped for
  `payment`. The same name is the response's `<target>`. The
  [spec](../spec/verification.md#receivers-the-peer-and-attribution) requires the
  receiver's policy name, so a destination reached by any other host (an address,
  a load balancer's name) fails at the receiver (`BINDING_MISMATCH`).
  Wherever there is a keyring, a root and the policy pin, it checks the response's
  attestation: verified labels become influence entries, and any other response
  becomes one `local-untrusted` entry (`src` `http:<target>`, `h` the result
  hash). The verifier's replay cache forgets a key after
  `max(15 s, 2 × paztport.max-age-ms)`: never sooner than twice the call window,
  which the verifier requires, and never so late that it grows without end.
- **The context scope.** Influence is recorded only inside a `PaztportContext`
  scope. The filter opens one per request; background work, such as a scheduled
  job, can open its own around one unit of work. Outside one, calls are still
  stamped and responses still checked, but nothing is carried.
- **Mutual TLS.** `paztport.tls-bundle` names the Spring Boot SSL bundle the
  service presents on its calls and its events. Both go out on one
  `PooledTlsClient` per application, a JDK `HttpClient` speaking HTTP/1.1 that
  pools its connections, checks the server's name against its certificate and
  honours the bundle's protocols and ciphers; its `builder()` gives a client with
  TLS and no stamping, for calls that set their own headers. Its timeouts are
  under **Timeouts**, below. On a request that came with a client certificate,
  `PeerIdentity` makes the verifier's peer: the subject's common name when there
  is exactly one and it is a DirectoryString, else `""`, at the TCP address the
  connection came from. It reads the name from the subject's DER encoding, by the
  [spec's rule](../spec/verification.md#http-requests-and-responses), so
  `CN=a+CN=a` and an IA5String common name both name no service. A
  certificate that names no service is still a peer, so the check runs and fails
  (`PEER_MISMATCH`); its trace reads `peer="" (mTLS)`. Responses are checked with
  no peer.
- **Timeouts.** Every client the starter builds has them, so that a peer that
  takes a call and never answers cannot hold the calling thread for ever. Both
  settings must be positive; one that is not fails the startup, naming it, in a
  service that uses it.

  | Property | Default | What it bounds |
  |---|---|---|
  | `paztport.read-timeout-ms` | `30000` | Each call through the `PooledTlsClient` (with `paztport.tls-bundle` set, every call on the shared `RestClient.Builder`, and its `builder()`'s), and each of the egress's calls to the partner: the whole exchange, from sending the request to the end of the response's body, on any JDK, so a peer that sends its headers and then stops part way through the body is cut off too. For that the pooled client reads each response whole, and holds it in memory, before the caller sees it, as the stamping interceptor already did: it suits the small bodies mesh calls carry, not large streamed downloads, and a call through its `builder()` can no longer stream its response. A call past it fails as a timeout: a `ResourceAccessException` from a `RestClient`, an `UncheckedIOException` from `BoundaryClient.post`. |
  | `paztport.event-timeout-ms` | `2000` | Each event to the responder, whole: connecting, sending and reading the answer to its end, on any JDK, with a TLS bundle or without. An event is sent on the request thread before the refusal is answered, so a slow or silent responder would otherwise hold every refusal for as long as it liked; this caps that at this long per refusal, after which the event is given up and logged and the refusal goes ahead. Forged requests sent fast enough can still keep request threads busy, each for up to this long. |

  Two more are fixed: the pooled client connects within 5 s, and the egress's
  handshake has 10 s, whatever `paztport.read-timeout-ms` is. Without
  `paztport.tls-bundle` the shared builder keeps the application's own request
  factory, and its timeouts are the application's to set.
- **The verified chain.** `PaztportContext.verifiedChain()` is the request's chain
  once it has passed the full live order at this hop, and is null otherwise: in `off`
  mode, after an audit-mode failure, at an origin, at a hop with no verifier, and
  outside a request scope. Only the inbound filter sets it, from the result that
  decides attestation. Nothing is signed at the boundary over anything else.
- **`PublicWrites`.** A bean with two methods. `decide(destinationOwner)` runs the
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
- **The egress.** Setting `paztport.boundary.url` makes the service the egress to
  another organisation, with a `BoundaryClient` whose `post(path, json)` is the one
  way out. It needs `paztport.boundary.partner` (the partner's entry service),
  `paztport.boundary.url` (`https`, a scheme and an authority, no path; any other
  scheme fails the startup, though the `BoundaryClient` constructor accepts one, for tests),
  `paztport.boundary.tls-bundle` (its own SSL bundle, apart from `paztport.tls-bundle`,
  so the partner's CA is trusted only for the partner),
  `paztport.boundary.partner-policy-key-path` (the partner's pinned policy key) and
  `paztport.boundary.blinding-key-path` (its boundary key, 32 bytes as base64url,
  which the keygen writes as `boundary.key`; any other length fails the startup), as
  well as its own stamp key, proofs, keyring, root and policy pin; the context
  fails naming what is missing. The boundary key never leaves the organisation and
  belongs to this one egress service: the salts it derives do not name the egress,
  so it must not be shared with another service. Replicas of the egress share it.
  The first call opens a session and every call after it shares it. `post` throws `IllegalStateException` before anything, the handshake
  included, is sent when `verifiedChain()` is null. In an attested session it sends
  the influence blinded: one entry per class and owner, `src` `boundary:<this service>`,
  `h` a salted commitment to that group's originals (see
  [blinded influence](../spec/sessions-and-influence.md#blinded-influence)). It signs
  one boundary stamp over that list and sends the proof for `<this service>/<partner>`;
  in an unsafe one it sends only `X-Path-Session`. A `BoundaryListener` bean, if there
  is one, gets `sent(rid, partner, originals, sent)` in each attested call, after the
  session opens and before the request goes; if it throws, the request is not sent
  and `post` throws. Keep the originals it is given: `opening(rid, cls, owner,
  originals)` gives what to reveal to open the entry sent for that group, its salt
  derived again from the key. Nothing about the originals is logged. A reply
  that fails the client's check, an HTTP or I/O error (a `404` too) or no answer in
  10 s, the handshake's timeout, is followed by a handshake with no root, and the
  session is unsafe. That is the **fallback session**: the egress took it because
  it got no answer it could check, not because the partner said unsafe, so it is
  kept for at most 30 s from when it was opened (or less, if no call uses it for the
  idle period below). In it calls carry only `X-Path-Session`, as in any unsafe
  session. A passing failure (a partner restarting, a network blip) therefore does
  not leave the egress unsafe for the life of the process: the first call after the
  30 s tries the full handshake again. A genuine unsafe reply to the full handshake
  (the partner has not pinned this organisation) is the partner's answer, not a
  fallback, and is kept like an attested session. Each call has the read
  timeout, `paztport.read-timeout-ms` (below); one past it throws
  `UncheckedIOException` and keeps the session, as any failed call does, and is not
  retried. A `403 SESSION_UNKNOWN` clears the session, so the next call opens a
  new one; the refused call is not retried. A `403 POLICY_EXPIRED` clears it too: once
  the egress's own root or keyring passes its `notAfter` while it runs, the partner
  refuses every call in the attested session with it, and the next call's handshake
  gives an unsafe session. The egress logs one warning naming which of its own files has
  expired; renew them and restart it. Since a refused call is not retried, the
  egress also drops a session no call has used for `paztport.boundary.session-idle-ms`
  (default `600000`, 10 minutes), before the partner forgets it, and the next call
  opens a new one. Keep it below the partner's `session-idle-ms`. Every partner
  reply becomes one `local-untrusted` entry, and the request's own response is labelled
  `local-untrusted`, so a handler that relays the reply passes it on as untrusted. A path that would change the host or not be sent as given is refused before
  any I/O. The constructor refuses a root or keyring that does not verify under the
  service's own policy key.
- **Partner mode.** `paztport.partner.enabled=true` makes the service a partner's
  entry. It answers `POST /paztport/session` and registers `PartnerFilter` in place
  of `InboundFilter`: no modes, no responder events, no attested responses. It
  cannot be combined with `paztport.verify=true`. It needs `paztport.service-name`,
  `paztport.keyring-path`, `paztport.root-path`, `paztport.policy-key-path` and
  `paztport.key-path`, the entry service's own key, which signs its session replies,
  plus:

  | Property | Meaning |
  |---|---|
  | `paztport.partner.reply-cert-path` | `reply-cert.json`: the policy key's [reply certificate](../spec/wire.md#the-reply-certificate) for the key at `paztport.key-path`. Required. |
  | `paztport.partner.client-policy-key-paths` | The `policy.pub` of each organisation whose sessions may be attested. Required. |
  | `paztport.partner.client-origins` | The service names allowed to start a chain in a client's attested session. Required. |
  | `paztport.partner.unsafe-disabled` | Operations an unsafe session may not perform, as `METHOD /pattern`; the reply's `disabled`. |
  | `paztport.partner.max-sessions-per-peer` | How many sessions one client certificate (issuer and common name) may hold; its least recently used is evicted when it opens one more. Default `16`. |
  | `paztport.partner.session-idle-ms` | How long a session no call has used is kept, in milliseconds. Default `900000` (15 minutes). |

  **Lifetimes.** Every service that loads `paztport.keyring-path` and `paztport.root-path`
  (the mesh verifier, the egress `BoundaryClient`, the partner) refuses to start if
  either is in the old form or past its `notAfter`, with a message naming the property and
  saying to re-sign with the policy tool (`PAZTPORT_RENEW=true` renews without rebuilding),
  and logs one warning naming the file and its `notAfter` when 42 hours (a quarter of the
  default week) or less remain. A partner whose own root or keyring expires *while
  running* does not stop, since that would cut off callers it serves without attestation
  too: it opens only unsafe sessions, as it would for any unattested caller, and logs the
  reason once. Renew the files and restart it.

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
  One nonce cache is shared across sessions. A call with no `X-Path-Session` is
  unsafe; one naming no live session opened by the same issuer and common name
  (another peer's, an evicted or an expired one; issuers are told apart by their
  distinguished name, not by the CA's key) is `403 SESSION_UNKNOWN`. In an attested
  session the chain is verified by that session's own verifier, and the handler gets
  the verified influence and chain. The client's boundary chain is also the handler's
  `inboundChain()`, so a partner entry should not call into its own mesh from a
  partner request: its stamps would append to the client's chain.
  `PartnerGate`, a handler interceptor, refuses with `403 UNSAFE_SESSION` any request
  outside an attested session that matches an `unsafe-disabled` entry, by the
  handler Spring dispatched to, so `/refund;x=1` is `POST /refund`; a `HEAD` is
  refused where the matching `GET` is. The handshake endpoint and the
  [unverified paths](#paztport-spring) are not filtered, so a handler there runs
  with no influence and counts as unsafe.
- **Trace lines.** Besides the request and response lines, each value passed through
  `LogSafe`:
  - `PAZTPORT_TRACE session partner=<svc> check=<ReplyCheck>|- status=attested|unsafe`,
    at the egress after a handshake; `check` is `-` when the first handshake got no reply.
  - `PAZTPORT_TRACE boundary rid=<rid> receiver=<partner> session=attested|unsafe status=<http> classes=<a,b>|-`,
    at the egress after a call; the classes are those actually sent, so `-` when unsafe.
  - `PAZTPORT_TRACE session peer=<svc> status=attested|unsafe`, at the partner.
  - `PAZTPORT_TRACE request … session=attested|unsafe`, at the partner: the request
    line plus the session's status; one with no session header carries `reason=-`
    and is not verified, and a `SESSION_UNKNOWN` refusal carries `session=unknown`.
  - `PAZTPORT_TRACE decision rid=<rid>|- receiver=<svc> rule=public-write|trusted-record|unsafe-session reason=<code> ✓|✗ classes=<a,b>|-`,
    from `PublicWrites` and from `PartnerGate`; it never names an owner.
- **Modes and events.** `/admin/mode`, the events sent to a responder, one
  `PAZTPORT_TRACE` log line per request verified, including one verified only to
  decide attestation, and per response received (with `reason=-` where no verifier
  is configured to check it), and an optional
  `ReceivedRequestListener` hook that lets an application observe each request the
  filter receives. The SDK captures nothing itself: the mesh demo's request
  capture, for its replay scenario, is a listener on that hook.

## tools/keygen

One-shot job, `keygen [outDir] [service...] [--tls-only name...] [--org name]`:

- a per-service Ed25519 stamp key (`<svc>.key`) and a policy key (`policy.key`);
- `keyring.json`, signed by the policy key in the new form, valid for `PAZTPORT_POLICY_DAYS` days (default 7),
  and `policy.pub`, the pin;
- one CA per run, named by `--org` (default `shop`), whose key is written alone to
  `ca/ca.key`, outside `tls/`, so it sits apart from the certificates and keys that
  services mount (each service mounts only its own files, one by one);
- `tls/ca.crt`, and `tls/<name>.crt` and `.key` for every service and every
  TLS-only name (default `operator` and `responder`), which get a certificate but
  no stamp key, so they never enter the keyring. Certificates are ECDSA P-256 with
  `CN` and a DNS `SAN` of the name, subject and authority key identifiers, and are
  valid as both server and client;
- `boundary.key`, the egress's boundary key (32 random bytes as base64url), written
  only when it does not exist: every other key is new on each run, but a new
  boundary key would make the influence entries sent under the old one unopenable.
  An existing one that is not 32 bytes is refused, naming the file, and nothing is
  written. It is for the mesh's one egress service and its replicas.

Private keys and the boundary key are written owner-read/write only.

## tools/policy-tool

One-shot job, `policy-tool [--renew] [paths.yaml] [keysDir] [outDir]` (defaults `policy/paths.yaml`,
`out/keys`, `out/policy`). It reads `keysDir/policy.key` and `keysDir/keyring.json`, and signs the root and the
keyring in the new form, both valid for `PAZTPORT_POLICY_DAYS` days (default 7). It has two modes:

- **Rebuild**, the default: `paths.yaml` → salted tree → signed `outDir/root.json` plus one proof bundle per
  service (depth `PAZTPORT_PROOF_DEPTH`, default 8), and `keyring.json` re-signed beside it. The tree is new, so
  the `rootId` and every bundle change, and every service holding a root or proofs must reload them together.
  Rebuild when the routes change.
- **Renew**, with `--renew` or `PAZTPORT_RENEW=true` (so the same command line serves both): `outDir/root.json`
  and `keyring.json` signed again with a new `notAfter`, keeping the root's `root` and `rootId`, so the proof
  bundles stay valid and are not touched, and holders can pick up the renewed files one at a time. The new
  `notAfter` is the run's time plus `PAZTPORT_POLICY_DAYS`, so a renewal can shorten a longer existing window.
  `paths.yaml` is not read. Renewal is the routine operation, run well before `notAfter`; old-form and expired
  files are renewed into the new form all the same.

Either mode first checks that the keyring verifies under the policy key it names, in either form and expired or
not, and that that key is the one in `policy.key`; renewing also checks the root verifies under it. Any of these
failing is refused, exit 2, with nothing written. The keyring is written in place (truncated and rewritten, never
renamed over), so it can be a single file mounted writable into the tool. It is written first, so a keyring
the tool cannot write stops the run with `policy-tool: cannot write <file>: <reason>`, the file system's reason
(`Read-only file system`, `Permission denied`, `No space left on device`), and nothing written. I/O errors like
that one exit 1, not 2. Writing in place is not atomic: a crash or a full disk part-way through leaves the
keyring empty or truncated, which the next run refuses, and since the tool only re-signs a keyring, recovering
means new keys from the keygen. A rebuild vouches that the routes in
`paths.yaml` are the ones allowed now; a renewal, that the existing tree's routes all still are, since
narrowing a policy is a rebuild. Re-signing the keyring vouches that each listed key is still its service's
current key: the tool can check only that this policy key signed the keyring before, so retiring a key, which
needs a new keyring rather than a renewed one, is the policy owner's to ensure.

When `PAZTPORT_REPLY_CERT_SVC` names a service, either mode also writes `outDir/reply-cert.json`, a
[reply certificate](../spec/wire.md#the-reply-certificate) for that service's key in the keyring, valid for
`PAZTPORT_REPLY_CERT_DAYS` days (default 7), set apart from the policy's lifetime. It refuses, writing nothing,
a service the keyring has no key for. The tool prints only file names, their `notAfter` and the certificate's
service.
