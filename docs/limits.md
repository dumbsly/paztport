# Known limits

This is the register of what Paztport does not do on its own. It lists what a
deployment must supply for Paztport to hold, what any design of this kind cannot
do, and what this proof of concept leaves out.

## Using it soundly

What Paztport needs from a deployment, and what it deliberately doesn't cover yet.

- **The peer check needs mutual TLS in the service's own process.** A verifier checks
  that the last signer is the transport's authenticated sender (`PEER_MISMATCH`)
  only when it is given one. The Java mesh gives it one: every hop is mutual TLS, and
  `payment` takes the service named in the client certificate as the sender
  ([check 12](../poc-demos/java-mesh/README.md#the-verification-pipeline)). Each
  service that checks a peer terminates TLS in its own process, and the SDK reads
  the peer from the certificate verified there, first-hand. Behind a sidecar mesh
  (Istio's or Linkerd's per-pod proxy), mutual TLS ends at the sidecar and the
  application sees only a local connection, so the peer would be a header the
  sidecar asserts. That is a different trust model, in which the application must be
  reachable only through its sidecar, and the SDKs don't support it today. The
  agents demo runs over stdio, which has no TLS, so there the check is skipped and
  the last signer is known only by its signature
  ([the peer check](../poc-sdks/spec/verification.md#receivers-the-peer-and-attribution)).
- **Who a rejection can blame depends on the peer.** Without one, the instance in a
  stamp is reported by the service that signed it. The responder refuses a container
  that doesn't run the named service, but a compromised service can still name any
  replica of itself. With a peer, a rejection names the sender's own TCP address
  instead, which the responder resolves to a container on the mesh network, so a
  replica can only be blamed for what it sent. That rests on the address being the
  sender's: behind a proxy or NAT it would name the proxy. A certificate is per
  service, not per container, so blaming one container needs per-instance
  certificates; without them the responder still checks that the container runs the
  named service
  ([attribution](../poc-sdks/spec/verification.md#receivers-the-peer-and-attribution)).
- **Key custody is the cluster's.** A Paztport key kept in a Kubernetes Secret is as
  safe as any credential there: anyone who can read that namespace's Secrets, or
  create pods in it (directly or through a Deployment or Job), holds it, as they
  would a database password. Give keys the cluster's usual hardening:
  least-privilege RBAC on reading Secrets and on creating workloads, no
  service-account token in pods that don't call the API, encryption at rest, and
  admission control over what may run. What a stolen key can and cannot do is in "A
  service is whoever holds its keys" below.
- **Without a peer, a captured request can be sent again.** A stamp is good only for
  its receiver and its request. Where the transport supplies a peer, as the Java mesh
  does with mutual TLS, it is good only on the last signer's own connections: a
  captured request can't be sent again from anywhere else, whatever cache a receiver
  keeps. Without a peer (the agents demo over stdio, or any deployment without
  in-process mutual TLS), anyone holding a captured request can resend it to the
  same receiver within the call window (5 s by default); only the cache of the
  replica that saw the first sending refuses it, and over HTTP another replica can
  serve it.
- **Duplicate delivery is the application's.** The SDKs' caches are in memory, so a
  service run as several replicas, or restarted, can serve a request its signer
  sends twice, as a proxy that retries does. That is duplicate delivery, and the
  receiving application handles it as it handles any retried request, by idempotency
  keyed on the delivery: the verified chain's `rid`, its last signer and the receiver
  its last stamp names (with the operation, when it names one, and the key value of a
  keyed operation) name it, and that stamp's `bind` says which request it was. The
  Java and Go in-mesh receivers hand the application that key
  (`RequestContext.delivery()` and `Accepted.delivery()` in Java,
  `Accepted.Delivery()` in Go)
  ([replicas and duplicates](../poc-sdks/spec/verification.md#freshness-and-replay)).
- **A shared nonce cache is the deployment's to bring.** A service that must also
  hold a compromised caller to each key once per request tree, whatever its replica
  count, can pass its own expiring shared cache to the nonce-cache interface that the
  Java and Go SDKs expose; neither SDK ships one. A cache that cannot answer gives no
  verdict: `enforce` refuses the request 503 and `audit` serves it and records the
  failure ([verification.md](../poc-sdks/spec/verification.md#freshness-and-replay)).
  The TypeScript SDK takes no shared cache because it has none to share: its caches
  are per session, and a session lives on one replica.
- **Revocation takes up to a lifetime.** A keyring or root presented when a
  session opens with a partner (the handshake) stays usable by someone replaying it
  until its `notAfter`, so a leaked service key, or a route removed from a policy,
  can be used until the keyring or root that names it expires: 7 days by default.
  A deployment can shorten that by refusing any keyring or root whose `notAfter` is
  earlier than the latest it has seen per policy key, but that holds only while
  every issue's `notAfter` is later than the one before, since a renewal can write
  an earlier one; nothing signed says which issue is newer (a version number would
  make it exact, but the format carries none). Re-pinning a new policy key ends it
  at once. Choosing the lifetime and running the renewals are the deployment's job.
- **Async is out of scope.** Queues, caches, and scheduled jobs break the
  linear-chain model (see the async direction in
  [where this could go](directions.md)).
- **The rule judges whose data shaped a write, not who may receive it.** A
  hijacked request that read no private data passes the rule whatever destination
  it names. In the demo, who may receive a refund is the PSP's own payer check
  (only a card held by whoever paid for the order, else `NOT_PAYER`), and the PSP
  registers a card's owner only from a charge the shop vouched for and no untrusted
  content shaped. A service whose destinations are not its own records needs a
  check of its own.
- **The rule judges only the influence the request carries.** `PublicWrites` sees
  that influence only where the request's chain passed the live order at that hop.
  Where it did not, because Paztport is off on the hop, the chain failed in audit
  mode or the call came in an unsafe partner session, the influence may be
  incomplete or empty, and the rule passes what it cannot see. A partner must
  therefore list its public writes in `paztport.partner.unsafe-disabled`.

## Limits of the concept

What any design of this kind meets, and what this one has not yet tackled.

**Inherent**

- **Position, not trust.** A compromised hop on a valid route can still misuse
  that route (see the Java demo's
  [threat model](../poc-demos/java-mesh/README.md#threat-model)).
- **A service is whoever holds its keys.** Those are its stamping key and the TLS
  key the peer check reads, and a pod that can read or mount them is that service:
  its stamps verify. Paztport attests the path, not that each hop is a legitimate
  deployment. That proof belongs to the workload-identity layer: attestation that
  issues identities only to approved workloads (SPIFFE/SPIRE, for one), signed
  images checked at admission, and admission rules on who may run a service's pods.
  Because the peer check binds each stamp to its TLS peer, once TLS identity is
  attested a copy holding a stolen stamping key is refused at the next hop with a
  peer; offline verification has no peer to check.
- **Influence is only as complete as the instrumented path.** Content that reaches a
  component outside an attested hop (a cache, a side channel, training data, a
  person pasting text) is invisible to the rule.
- **The rule counts presence, not effect.** It can't tell whether third-party text
  actually changed what a model did, so it refuses conservatively, preferring a
  false refusal to a missed one. It doesn't refuse on third-party text alone: it
  refuses when untrusted content and private data not owned by the destination are
  both in the influence. Untrusted content can still steer a customer's own data to
  that customer.
- **The proof hides the policy, not the request's route.** The stamps name the
  route to whoever verifies them, and a route's proof is the same on every
  request, so a partner can count and cluster requests by route. It sees one
  route, `<egress>/<partner entry>`, never the internal one. Hiding a request's
  own route from its verifier is not what the proof is for.
- **A binding binds the value read, not its text.** Paztport's own objects are
  read from their bytes, but a tool's arguments and result are the transport's
  content: its JSON parser reads them, and they are hashed as RFC 8785 JCS, which
  treats every number as the 64-bit float that parser reads. So
  `9007199254740993` and `9007199254740992` share one binding, though a tool that
  reads integers exactly sees two (see
  [Hashed content](../poc-sdks/spec/wire.md#hashed-content)).
- **What a partner must learn.** To apply the owner-aware rule, a partner must
  learn each influence entry's class and owner, and match those against the
  destination's owner, which it takes from its own records. Those owners are
  private to the sender. The sources behind each class and owner cross only as
  blinded commitments that the sender can open.

**Not yet tackled**

- **Partner replies are not attested.** The egress records each reply from the
  partner as `local-untrusted`, and labels its own response the same, so whatever
  relays the reply passes it on as untrusted. A response stamp under the partner's
  keyring, which the egress already holds from the session reply, would attest it;
  that is a spec addition.

## Limits of this proof of concept

Engineering shortcuts of this repository, not of the design.

- **Keys and certificates are files, with no workload attestation.** In the Java
  demo they are files mounted into each service from `out/keys`; in the Envoy
  Gateway demo they are Kubernetes Secrets. Anyone who can read them, or start a
  pod that mounts them, can act as that service (see "A service is whoever holds
  its keys" above).
- **The responder mounts the Docker socket**, which is host-level control.
  Acceptable for a local demo only; never do this in a real deployment.
- **The responder's keyring is unpinned.** It checks event signatures against
  `keyring.json` as mounted, without verifying the keyring against the policy pin
  or checking its `notAfter`, both of which the mesh services do. Anyone who could
  replace that file could name their own event signer.
- **The nonce cache is in memory, per replica,** and forgets a key after the nonce
  TTL (15 s by default, never under twice the call window). It has no size cap, so
  a flood within that time grows it. A shared, expiring store is optional hardening
  against a compromised caller; duplicate delivery is the receiving application's to
  handle (see "Duplicate delivery is the application's" above).
- **The Spring starter's mode switch is guarded by a token alone.** On a service
  that verifies requests, the starter registers `/admin/mode`, which switches the
  verifier between `audit` and `enforce` or turns Paztport off on the hop, only where
  `paztport.admin-token` is set, and answers only a request whose `X-Admin-Token`
  matches it (the demo makes a token for each run, as `PAZTPORT_ADMIN_TOKEN`). The
  starter verifies every path, this one included, unless `paztport.unverified-paths`
  lists it ([unverified paths](../poc-sdks/java/README.md#unverified-paths)); the demo
  lists `/admin` on each service that has the switch. A real deployment keeps
  management on a port of its own, out of its callers' reach, as Boot's
  `management.server.port` does for actuator; the switch is served on the
  application port, so a deployment that cannot keep it from callers sets no token.
- **The demo includes a replay harness.** The Java demo's `payment` can retain its
  last request (`/debug/last-request`, only when `PAZTPORT_CAPTURE=true`) so the
  demo can replay and mutate a genuinely valid request. The harness lives in the
  demo and reaches requests through the Spring SDK's `ReceivedRequestListener`
  hook. It simulates an on-the-wire capture and isn't part of the attestation
  model.
- **The demo's evidence stores are stand-ins.** The shop's store of what each
  blinded entry sent to the PSP stood for, and the PSP's record of what each call
  carried, are in memory and exist only when `PAZTPORT_OPENINGS=true`.
- **The demo's support desk is a stand-in.** The bearer tokens, the seeded orders
  and the mailer's directory are fixtures, and `assistant` is scripted, with no
  model.

