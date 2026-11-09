# Go SDK

One Go module, `github.com/dumbsly/paztport/poc-sdks/go`, for Go 1.27 or newer.
It depends on nothing beyond Go's standard library: it reads and writes JSON with
its own strict reader and writer, and every cryptographic primitive is Go's.

It implements protocol v3 as the [spec](../spec/README.md) defines it, all but the
MCP profile: stamps and chains, policy material, the live and offline verifiers, influence and
the owner-aware rule, sessions, responder events, and v3 over HTTP at a receiver,
a caller, a partner and an egress. It replays `spec/vectors/v3.json` and
`json.json` but their sections that belong to the
[MCP profile](../spec/README.md#the-mcp-profile), `http-v3.json` but its
`operations` section, and `events.json` in full. It leaves out:

- **The MCP profile**, local steps included.
- **Any integration.** It sends nothing, logs nothing, publishes no events and
  imports no HTTP library. It takes a request or a response as the strings and
  bytes a server, client or gateway already has, and hands back answers, headers
  and verdicts. The adapter for a server or a gateway is the embedder's.
- **Operations over HTTP.** The receiver neither works out nor confirms the
  operation a request invokes: it has no operation table. An embedder that names
  operations supplies `svc#operation` as the receiver itself, in the `Receiver`'s
  `Name`, and confirms the operation on its own side. The verifier accepts that
  form in a stamp's `rcv`, and the stamper and the caller can address it.
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
  salted Merkle tree and proof bundles, and their files.
- `stamp`: stamps and chains, the prompt and response bindings, and the `Stamper`
  that starts, extends and answers chains and stamps the boundary call.
- `influence`: influence entries and content labels, the commitment, the
  owner-aware rule, `ShapedOnlyByTrusted`, and blinded boundary influence and its
  openings.
- `verify`: the live verifier, its checks 0 to 12 in the spec's order, and the
  nonce cache.
- `session`: the handshake's request and reply, the server's status and the
  client's check of a reply, and the session id.
- `offline`: a record set verified again later, its recorded calls and the
  recorded handshakes that opened their sessions.
- `event`: responder events, their signed envelope, and the `Responder`'s checks.
- `reason`: the reason codes.
- `paztporthttp`: v3 over HTTP at a service: the `Receiver`, the `Caller`, peers
  from client certificates, and a partner's `Sessions` and handshake endpoint.
- `paztporthttp/wire`: the headers, the request binding, the result hash and the
  caller's check of a response.
- `paztporthttp/boundary`: the egress, which opens a session with a partner and
  sends each call across with its boundary stamp and blinded influence.
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
- **Handles a nonce cache that cannot answer.** `Receiver.Accept` returns an
  `Accepted` only. When the `verify.NonceCache` returns an error, the request is
  undecided and `Accepted.CacheErr` holds the error, for the adapter's own log.
  Under `enforce` the adapter sends `paztporthttp.Unavailable()` (503, no body);
  under `audit`, and with no mode, it serves the request unverified and
  unattested, with the chain and the influence as received.
- **Offers the delivery key.** `Accepted.Delivery()` gives the `Delivery` (`RID`,
  `Svc`, `Rcv`, `Bind`) of a request whose chain was verified at this hop, and false
  otherwise. A duplicate delivery, such as a proxy's retry to another replica,
  is the application's to handle by idempotency keyed on it: the same key and
  `Bind` is the same request sent again by that signer, and the same key with
  another `Bind` is a different request under a reused key, to refuse.
- **Attests and checks answers.** It sends the `X-Path-Response` header that
  `Accepted.Attest` gives for the handler's complete answer. As a caller, it reads
  each response whole and passes it to `Caller.Check` before anything reads it.
  The caller's verifier can keep its nonce cache in memory: only the replica that
  sent a call can check its answer, so there is nothing to share. `Check` returns
  the cache's error when it cannot answer.
- **Applies the rules to its writes.** A handler's write to a public
  destination is decided by `influence.PublicWriteRefused`, over the handler's
  influence and everything it has read since, with the destination's owner
  taken from its own records. It writes a trusted record only when
  `Accepted.TrustedRecord`, or at a partner `PartnerAccepted.TrustedRecord`,
  allows it.
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
- **Keeps the egress's originals.** Before it sends an attested call, it keeps the
  `Step`'s `Originals` and `Sent` under the request's rid and the partner's entry
  service, and does not send the call if it cannot.
- **Sets what the spec leaves to it**: a partner's `SessionsConfig.MaxPerPeer` and
  `IdleMs`, and an egress's `Config.IdleMs`, which have no default.
