# Java SDK

A Maven build (`paztport-sdk-parent`, JDK 21 or newer) of three libraries and two
one-shot tools. Every cryptographic primitive comes from the standard JDK; `keygen`
uses Bouncy Castle only to build its X.509 certificates, which the JDK signs.

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
- **Verifying.** `VerifierV3` runs the twelve checks of the live order.
  `VerifierConfigV3.pinned` checks the keyring and the root against the pinned
  policy key, and refuses to build a config if either fails. `OfflineVerifier` re-checks a
  recorded chain, all v3, or all v2 as legacy.
- **Stamping.** `StamperV3` stamps a hop's outbound call, starting a chain only at
  an origin, and stamps a response as one more stamp on the request chain, back to
  the caller.
- **Bindings, influence and labels.** `Bindings` (the prompt and response
  bindings, which refuse a lone surrogate), `Influence`, `InfluenceRule` (the one
  owner-aware rule) and `ContentLabel`.
- **Sessions.** `Sessions`: the handshake as messages, with no transport.
- **Encodings and keys.** `Base64Url` (the TypeScript SDK's decode rule exactly),
  `Jcs`, `KeyringFile` (the signed `keyring.json`), `KeyFiles`, `SignedRoot`, the
  Merkle tree and `PolicyBuilder`, `Routes`, and `EventVerifier` for events sent to
  a responder.
- **v1**, kept for `v1.json` only: `StampV1`, `PathChainV1`, `VerifierV1` and the
  rest carry a `V1` suffix.

## paztport-http

v3 over HTTP, with no web framework. `PaztportHeaders` names the four headers:
`X-Path-Chain`, `X-Path-Proof`, `X-Path-Influence` and the response's
`X-Path-Response`. `RequestBinding` computes `bind` over the method, the raw path
plus `?` and the raw query when there is one, and the body. `HttpV3` encodes and
decodes the headers, builds a request's verify input (nonce key
`<rid>|<last svc>|req`), computes a response's result hash over its status and
body, and checks a response's attestation against the chain the caller sent
(nonce key `<rid>|<target>|resp`). A service therefore calls a given receiver at
most once per request tree. `HttpVerifyRequestsV1` is the v1 equivalent, kept for
`v1.json`.

## paztport-spring

Glue, configured through `paztport.*` properties.

- **The inbound filter** caches the body, opens a `PaztportContext` scope for the
  request, and keeps the received chain and influence there for the outbound
  calls. Where `paztport.verify=true` it verifies the request in the current mode;
  such a service also needs a keyring, a root and the policy pin
  (`paztport.policy-key-path`), or it refuses to start. Influence it can't read is
  answered `400 {"reason":"INFLUENCE_MISMATCH"}` in every mode, unless verification
  refused the request first.
- **Response attestation.** A service with a stamp key attests each response whose
  request chain parsed as v3 and verified there, or was not checked there: one
  stamp over the status, the body and the labels its handler added with
  `PaztportContext.label`, sent as `X-Path-Response`. Refusals and audit-mode
  failures are not attested. The stamp covers the whole body, so the body is held
  until the handler returns. An async response is not attested: its body is sent
  whole when the async work completes, with no `X-Path-Response`.
- **The outbound interceptor** stamps every `RestClient` call through `StamperV3`,
  attaches the proof and the influence so far, and reads each response whole.
  Wherever there is a keyring, a root and the policy pin, it checks the response's
  attestation: verified labels become influence entries, and any other response
  becomes one `local-untrusted` entry (`src` `http:<target>`, `h` the result
  hash).
- **The context scope.** Influence is recorded only inside a `PaztportContext`
  scope. The filter opens one per request; background work, such as a scheduled
  job, can open its own around one unit of work. Outside one, calls are still
  stamped and responses still checked, but nothing is carried.
- **Mutual TLS.** `paztport.tls-bundle` names the Spring Boot SSL bundle the
  service presents on its calls and its events. On a request that came with a
  client certificate, `PeerIdentity` makes the verifier's peer: the subject's
  common name when there is exactly one, else `""`, at the TCP address the
  connection came from. Responses are checked with no peer.
- **Modes and events.** `/admin/mode`, the events sent to a responder, one
  `PAZTPORT_TRACE` log line per request or response verified, and an optional
  `ReceivedRequestListener` hook that lets an application observe each request the
  filter receives. The SDK captures nothing itself: the mesh demo's request
  capture, for its replay scenario, is a listener on that hook.

## tools/keygen

One-shot job, `keygen [outDir] [service...] [--tls-only name...] [--org name]`:

- a per-service Ed25519 stamp key (`<svc>.key`) and a policy key (`policy.key`);
- `keyring.json`, signed by the policy key, and `policy.pub`, the pin;
- one CA per run, named by `--org` (default `shop`), whose key is written alone to
  `ca/ca.key`, so it is never in `tls/`, the directory services mount from;
- `tls/ca.crt`, and `tls/<name>.crt` and `.key` for every service and every
  TLS-only name (default `operator` and `responder`), which get a certificate but
  no stamp key, so they never enter the keyring. Certificates are ECDSA P-256 with
  `CN` and a DNS `SAN` of the name, subject and authority key identifiers, and are
  valid as both server and client.

Private keys are written owner-read/write only.

## tools/policy-tool

One-shot job: `paths.yaml` → salted tree → signed `root.json` plus one proof
bundle per service.
