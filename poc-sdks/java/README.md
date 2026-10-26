# Java SDK

A Maven build (`paztport-sdk-parent`, JDK 21 or newer) of three libraries and two
one-shot tools. Every cryptographic primitive comes from the standard JDK.

```bash
mvn -q install   # build, test, and install into the local Maven repository
```

The Java demo ([poc-demos/java-mesh](../../poc-demos/java-mesh/README.md)) depends
on the installed artifacts, so install the SDK before building it.
`./run java-mesh` and `./run test` do this for you.

## paztport-core

The library: stamps, chain, salted Merkle tree, verifier. Small enough to read in
one sitting. It also owns policy building (`PolicyBuilder`), outbound stamping
(`OutboundStamper`), the check on events sent to a responder (`EventVerifier`),
route strings (`Routes`) and key loading (`KeyFiles`). It never touches TLS or
HTTP: the transport extension hands the verifier the binding of the request
received and the receiving service's name.

## paztport-http

The HTTP binding. `RequestBinding` computes `bind`, the base64url SHA-256 of
`METHOD \n PATH \n BODY`; `PaztportHeaders` names the two wire headers; and
`HttpVerifyRequests` turns an HTTP request into the transport-neutral
`VerifyRequest` the core verifier takes.

## paztport-spring

Glue: an inbound servlet filter (verify, and keep the received chain for the
outbound calls) and an outbound `RestClient` interceptor (stamp through
`OutboundStamper`, attach proof). It also holds the modes, the `/admin/mode`
endpoint, the events sent to a responder, and an optional
`ReceivedRequestListener` hook that lets an application observe each request the
filter receives. The SDK captures nothing itself: the mesh demo's request capture,
for its replay scenario, is a listener on that hook. It is configured through
`paztport.*` properties.

## tools/keygen

One-shot job: a per-service Ed25519 keypair, a policy keypair, and the public
`keyring.json`.

## tools/policy-tool

One-shot job: `paths.yaml` → salted tree → signed `root.json` plus one proof
bundle per service.
