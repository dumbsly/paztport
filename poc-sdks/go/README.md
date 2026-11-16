# Go SDK

One Go module, `github.com/dumbsly/paztport/poc-sdks/go`, for Go 1.27 or newer.
It depends on nothing beyond Go's standard library: it reads and writes JSON with
its own strict reader and writer, and every cryptographic primitive is Go's.

It implements protocol version 4 as the [spec](../spec/README.md) defines it,
all but the MCP profile: stamps, chains and extension blocks, policy material,
the live and offline verifiers, influence as an extension and the owner-aware
rule, sessions, responder events, and version 4 over HTTP in `paztporthttp`, its
receiver, caller, partner and egress. It replays `spec/vectors/v4.json` but for
the [MCP profile](../spec/README.md#the-mcp-profile)'s sections,
`influence.response`, and the `influence.request` cases whose `served` is not
empty; `json.json` but for `jcs` and its MCP bindings; and `http-v4.json`,
`events.json` and `ed25519.json` in full. The SDK leaves out:

- **The MCP profile**, local steps included.
- **Any integration.** It sends nothing, logs nothing, publishes no events and
  imports no HTTP library. It takes a request or a response as the strings and
  bytes a server, client or gateway already has, and hands back answers, headers
  and verdicts. The adapter for a server or a gateway is the embedder's.
- **Confirming the operation over HTTP.** The SDK reads operation tables
  (`policy.ReadOperationTable`), but the receiver does not work out from its
  routing which operation a request invokes. Confirming it is the embedder's.
- **Tools.** It has no keygen or policy tool: it generates no keys, builds no
  route tree and writes no files. The Java and TypeScript SDKs' keygens and policy
  tools write the keys, keyrings, roots, proof bundles and reply certificates it
  reads, and the Java keygen the boundary key.

```bash
go test ./...   # every package; the vectors are read from ../spec/vectors
```

`./run test` runs gofmt, `go vet` and this suite after the Java and TypeScript
ones. The fuzz targets' seeds run as part of the suite, and
`go test -fuzz=<target> ./<package>` fuzzes one. One test reads what the Java
keygen writes: the keyring, the policy key pair and the boundary key.
`PAZTPORT_JAVA_KEYRING` names the keyring, and the other three files are read
from beside it; `./run test` generates them and sets it, so there the test runs
or fails. Without it the test looks in the Java demo's `out/keys` and skips
unless all four files are there.

Nothing is published, so a module that uses this one from a checkout of the
repository points the import path at the directory:

```
require github.com/dumbsly/paztport/poc-sdks/go v0.0.0

replace github.com/dumbsly/paztport/poc-sdks/go => ../path/to/poc-sdks/go
```

## Packages

- `keys`: Ed25519 keys as the spec encodes them, key files and pins.
- `policy`: the signed keyring, signed root and reply certificate, routes, the
  salted Merkle tree and proof bundles, and their files; and operation tables
  (`OperationTable`, read with `ReadOperationTable` or `LoadOperationTable`),
  which map a request to its operation with `Match` and to a keyed operation's
  key value with `KeyValue`.
- `stamp`: version 4 stamps and chains, the extension blocks that travel beside a
  chain (`Block`, `Blocks`, `EmptyBlock`: an item is its JCS text, and a stamp's `ext`
  commits to its block), the prompt and response bindings, and the `Stamper` that
  starts, extends and answers chains and stamps the boundary call.
- `influence`: the first extension, a set of functions over what the verifier hands
  on, which no core package imports: entries and content labels (`ParseEntry`,
  `ParseLabel`), the request and response blocks, `ReadRequest` and `Decide`, the
  every-stamp and owner-aware rules (`GuardedWriteRefused`, `ShapedOnlyByTrusted`),
  `ResponseEntries`, `Items`, and blinded boundary influence and its openings. A test in
  `internal/guard` keeps `stamp`, `verify`, `offline` and `session` from importing it.
- `verify`: the live verifier, its checks 0 to 12 in the spec's order, with the
  extension checks 9a to 9c and the peer before the nonce; `Extensions`, which says
  what a verifier acts on and allows (the zero value acts on nothing); the `HandOver`
  of verified, or unverified, items per stamp; `ServedUnverified` for a request served
  without verifying; `NonceKey`; and the nonce cache.
- `session`: the handshake's request and reply, the reply's `extensions`, the
  server's status and the client's check of a reply (`ExtensionRequired`), the
  client's `Requirement` and `CallsAfter`, and the session id.
- `offline`: a record set verified again later, its recorded calls (`Call` takes
  an `ItemCheck` for the extension's items) and the recorded handshakes that opened
  their sessions, whose `CallConfig` gives the settings a call is checked under.
- `event`: responder events, their signed envelope, and the `Responder`'s checks.
- `reason`: the reason codes.
- `paztporthttp`: version 4 over HTTP at a service, with the `Receiver`, the
  `Caller`, peers from client certificates, and a partner's `Sessions` and
  handshake endpoint.
- `paztporthttp/wire`: the headers, the request binding, the result hash, the
  nonce keys and the caller's check of a response.
- `paztporthttp/boundary`: the egress, which opens a session with a partner and
  sends each call across with its boundary stamp and one block. The block names
  `influence`, with the request's influence blinded, only where the egress acts
  on it and every stamp of the internal chain names it, and names nothing
  otherwise.
- `internal/`: the JSON reader and writer, base64url, the checks the verifiers
  share, exact time arithmetic, string checks, and, for tests only, the vector
  reader and an import guard.

## What the embedder does

The packages decide; the code that embeds them carries out what they decide:

- **Sends the bytes.** It sends each `paztporthttp.Answer`, header list and
  `boundary.Step` exactly as given, an `Answer` with a body with `Content-Type:
  application/json` and no parameters (an empty body carries no Content-Type),
  and passes the authenticated peer:
  `paztporthttp.PeerFromCertificate` reads one from a client certificate under
  mutual TLS. Before it sets each header it is given, replacing and never appending,
  it removes every header of the request that `wire.IsPaztport` names, all values
  (a gateway's processor also removes them from the response it passes back).
- **States its extension settings once.** `Receiver.Extensions`,
  `Caller.Extensions` and `SessionsConfig.Extensions` hold the extensions the
  service acts on and the names it carries (`verify.Extensions`, whose zero value
  acts on nothing). Beside a `Verifier` the settings are the verifier's, and the
  field must be the zero value or equal to them, or `Accept` or `Stamp` panics.
  A partner has no verifier of its own, so each attested session's verifier is
  built with `SessionsConfig.Extensions`.
- **Sends the receiver's refusals.** `Receiver.Accept` returns an `Accepted`
  whose `Refusal`, when there is one, is sent in place of the handler's answer:
  `403` with the code where verification refuses under `enforce`;
  `400 {"reason":"EXTENSION_MISMATCH"}` where a service other than an origin
  would serve a request it did not verify (under `audit` after a failure or
  with a nonce cache that cannot answer, with Paztport off, with no mode or no
  verifier) and its blocks fail check 9a; and, at a service that acts
  on `influence`, `400 {"reason":"INFLUENCE_MISMATCH"}` for a request handed an
  item that does not read as an entry, verified or not, in every mode.
- **Carries what a request hands on.** A request the receiver serves gives the
  handler `Accepted.Inbound`, its chain and blocks, and `Accepted.HandOver`, the
  items it hands the extensions the service acts on: verified where
  `Accepted.Verified`, otherwise not verified, for a request served unverified
  whose blocks passed check 9a, and nil where nothing is handed on, such as at
  an origin or where the chain did not read. Each of the handler's calls is
  `Caller.Stamp(method, target, receiver, body, inbound, added)`, with `inbound`
  that `Inbound` and `added` what the service added itself for the request, the
  responses to its own calls among them and never what it was handed. The call
  sends the blocks received unchanged, then its own, which names `influence`
  with `added` where the service acts on it, and requires of the receiver what
  `Caller.Requires` holds for its service.
- **Handles a nonce cache that cannot answer.** When the `verify.NonceCache`
  returns an error, the request is undecided and `Accepted.CacheErr` holds the
  error, for the adapter's own log. Under `enforce` the `Refusal` is
  `paztporthttp.Unavailable()` (503, no body); under `audit`, and with no mode,
  the request is served unverified and unattested, with its chain and blocks once
  check 9a has held on them.
- **Names and confirms operations.** An embedder that names operations
  supplies `svc#operation` as the receiver itself, in the `Receiver`'s `Name`,
  and confirms the operation on its own side. The `Receiver`, given its own
  table in `Operations`, reads the key value of the operation `Name` names from
  the request's target, and refuses `BINDING_MISMATCH` a keyed operation's
  request that gives none. The `Caller`, given the receivers' tables in
  `Operations`, names the operation and its key value from the target in
  `Stamp`; without a table for a receiver it names the service. An embedder may
  still pass `svc#operation` with no table held; that call reads no key value,
  so for a keyed operation the caller's response key is the unkeyed one and its
  own check refuses the second item's response `REPLAY`; hold the receiver's
  table to call a keyed operation per item. The verifier accepts `svc#operation`
  in a stamp's `rcv`. A `Receivers` map names services only, and a response's
  `src` is the service.
- **Offers the delivery key.** `Accepted.Delivery()` gives the `Delivery`
  (`RID`, `Svc`, `Rcv`, `Key`, `Bind`) of a request whose chain was verified at
  this hop, and false otherwise. `Rcv` names the operation when the last stamp
  does, and `Key` is the key value of a keyed operation, "" when there is none.
  A duplicate delivery, such as a client's retry to another replica, is the
  application's to handle by idempotency keyed on it: the same key and `Bind` is
  the same request sent again by that signer, and the same key with another
  `Bind` is a different request under a reused key, to refuse.
- **Attests and checks answers.** It sends the `X-Path-Response` header that
  `Accepted.Attest(status, body, labels)` gives for the handler's complete
  answer, whose block carries the labels where the service acts on `influence`.
  As a caller, it reads each response whole and passes it to `Caller.Check`
  before anything reads it, and adds `Received.Entries`, what
  `influence.ResponseEntries` gives for the response, to what the service added
  for the request, a refused response's included. `Received.Refused` is true
  where the response failed check 9c (`EXTENSION_REQUIRED`): the responder's
  handler has run, so the embedder fails the call, hands the response to nothing
  and does not retry it.
  The caller's verifier can keep its nonce cache in memory: only the replica that
  sent a call can check its answer, so there is nothing to share. `Check` returns
  the cache's error when it cannot answer.
- **Applies the rules to its writes.** A handler decides a write to a public
  destination with `Accepted.PublicWrite(read, destinationOwner)`, or at a
  partner `PartnerAccepted.PublicWrite`, which answers `reason.OK` or
  `reason.InfluenceDenied`. A stamp handed on that does not name `influence`
  denies it whatever the entries say (the every-stamp rule); otherwise the
  owner-aware rule decides over the entries handed on and `read`, what the
  service has read for the request since it was accepted, with the destination's
  owner taken from its own records. It writes a trusted record only when
  `Accepted.TrustedRecord(read)`, or at a partner `PartnerAccepted.TrustedRecord`,
  allows it. At a service whose settings do not act on `influence` every write
  is denied and no record allowed: a write-guarding service deployed without the
  extension is the mistake the rules exist to catch.
- **Raises its server's header limit if it must.** A call whose blocks would
  pass the wire limit, 256 KiB, is refused by `Caller.Stamp` before anything is
  signed, and an answer whose `X-Path-Response` would pass it is left
  unattested; nothing is dropped to make room. A server's own header limit,
  often 8 to 16 KiB, is reached long before that, so a deployment whose
  influence grows past it raises it.
- **Refuses switched-off endpoints.** At a partner, `Sessions.Accept` does not
  refuse the endpoints switched off for unsafe sessions, since only the framework
  knows which handler a request reaches. For a call served and not attested, a
  call with no session header included, the adapter sends
  `paztporthttp.UnsafeRefusal()` before the handler runs when
  `UnsafeEndpoints(SessionsConfig.UnsafeDisabled).Refuses` the method and the
  handler's path pattern.
- **Bounds bodies, and fails closed.** A receiver binds the body whole. An adapter
  that cannot hold a body whole refuses the request itself rather than pass on
  part of it; a handshake endpoint need read at most one byte past the wire limit,
  262 144 bytes.
- **Logs.** A `verify.Result` names a suspect for the operator's logs, never for
  the caller; a refusal's body carries none.
- **Publishes events.** `event.SignEnvelope` signs an event, and the embedder
  POSTs the envelope's `Wire()` bytes to its responder's `/events` path.
- **Sets the egress's settings and requirement.** `boundary.Config.Extensions`
  are the egress's own settings, read from no `Accepted`: its boundary block
  names `influence` only where they act on it and every stamp of the internal
  chain verified there names it. `Config.Requirement` is what it requires of the
  partner. Where the session open with the partner does not meet it,
  `Egress.Begin`, or `Exchange.Answer` after the handshake, returns
  `boundary.ErrRequirementUnmet`: no call was sent, so the embedder fails the
  request, and the call is not retried in that session.
- **Keeps the egress's originals.** Before it sends a call whose boundary block
  names `influence`, it keeps the `Step`'s `Originals` and `Sent` under the
  request's rid and the partner's entry service, and does not send the call if
  it cannot. No other step carries them.
- **Sets what the spec leaves to it**: a partner's `SessionsConfig.MaxPerPeer` and
  `IdleMs`, and an egress's `Config.IdleMs`, which have no default.
