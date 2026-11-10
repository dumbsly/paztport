# Paztport

**A passport for requests.** The "zt" stands for zero trust.

Most security asks one question at the door: *who are you?* Paztport asks a
second question: ***how did you get here?***

That second question matters once an attacker has taken over one part of a
system. A request from that part carries its valid credentials, so a service that
asks only *who are you?* (the payment service, the customer database, the admin
panel) does what it's told.

## The idea in plain terms

Think about how a passport works. Every border you cross stamps it, and customs at
your destination looks at the stamps, not just at your face. Paztport gives every
request inside a system the same kind of passport:

- **Every step stamps it** with a signature nobody else can forge. Skip a step or
  fake one, and the stamps stop lining up.
- **The destination checks the whole itinerary**, not just the last hop. A payment
  request is accepted only if it arrived by a route on the approved list.
- **The approved list stays sealed.** Each service holds a single fingerprint of
  it, so it can check a route without anyone ever seeing the full map of how the
  system fits together. That includes a partner, and an attacker who gets inside.

When a request turns up with the wrong history, it's refused. That holds even when
its credentials are valid and its contents look perfectly normal. The machine that
sent it can then be moved into isolation and replaced with a clean copy,
automatically, within seconds: in the demo, a responder does exactly that, acting on
the signed events the rejection produces.

## Why it matters

- **It catches the attacks that look normal.** Paztport rejects a request from a
  hijacked internal service because of where it came from.
- **It shrinks what a break-in is worth.** A compromised component can only do
  what its legitimate position in the system allows. An attacker who takes over
  the search service gets the search service, not the payment system behind it.
- **It keeps your blueprint private.** Paztport checks routes without ever
  publishing them. The same design is meant to let two organisations trust each
  other's calls without swapping architecture diagrams.
- **It makes an automatic response possible and keeps the evidence.** The signed
  events name the offending machine, so a responder can act on them. The demo's
  responder isolates the machine rather than deleting it, so investigators get a
  live specimen while a clean replacement keeps the service running. If the same
  service keeps tripping, it stops and calls a human rather than risk tearing down
  healthy machines after a bad deploy.
- **It covers an AI agent's tool calls.** The
  [agents demo](poc-demos/agents-mcp/README.md) stamps an agent's MCP calls, and
  the server refuses the write a planted prompt injection asks for, by the
  owner-aware rule ([§3](#3-operations-influence-and-sessions));
  [§6](#6-where-this-could-go) says what is still open.
- **It's cheap.** Checking a request is a few Ed25519 verifications and SHA-256
  hashes; the demos measure what that costs
  ([Java mesh](poc-demos/java-mesh/README.md#measurements),
  [Envoy Gateway](poc-demos/envoy-gateway/README.md#measurements)).
- **It's open.** There's no vendor and no lock-in. It's Apache-2.0 code built on
  standard primitives, Ed25519 and SHA-256.

It's also honest about its limits. Paztport doesn't make a compromised machine
trustworthy; it limits how far a compromise can travel. The full list is in
[Known limits](#5-known-limits).

## What's in this repository

A working proof of concept of **path attestation**. A request has to prove the
route it took through a system, and the destination accepts it only if that route
is one the system allows. The allowed routes are committed to a salted Merkle tree,
so a service checks a request against one signed root hash. It never holds, and
never reveals, the full map of valid paths.

It works end to end. In the [Java mesh demo](poc-demos/java-mesh/README.md), a
request with a perfectly valid body, sent by a service that is legitimately on the
network, is **rejected purely because of where it came from**, and the offending
container is **quarantined and replaced automatically**. All the scenarios and a
circuit-breaker check pass (`demo.sh` reports 26 checks), and the overhead has been
measured.

The demo also tells a story across two organisations. A customer's support ticket
passes through a ticket service, which labels the text as third-party, to an
assistant, which is a **scripted stand-in for a hijacked model, with no model in
it**. It reads the customer's private order and tries a refund (at a payment
provider that is a second organisation, reached through a boundary attestation)
and an email. An honest ticket is refunded and emailed. A malicious ticket asks
for Alice's data to go to Mallory, and is refused at the mailer and at the
provider from the influence the requests carry, though every hop was a legitimate
position on an allowed route. See
[the support-assistant storyline](poc-demos/java-mesh/README.md#the-support-assistant-storyline).

The [Envoy Gateway proof of concept](poc-demos/envoy-gateway/README.md) puts Paztport
at a Kubernetes edge, on a local kind cluster. A Go `ext_proc` processor, installed
by its own Helm chart, stamps each request entering an Envoy Gateway as the origin
service `edge`, and the Java mesh's `orders` and `payment` verify it. Its checks show
that a chain a client sends is replaced at the edge, not believed, that a request
sent around the edge is refused, and that a stamp taken from the processor is refused
from any connection but Envoy's. Its README also records what one full measurement
run showed: the processor's cost under load, how the edge fails and recovers, and
rotating the edge's key.

The [agents demo](poc-demos/agents-mcp/README.md) carries the same chains over MCP,
with the TypeScript SDK. An extension to the pi coding agent intercepts each tool
call the agent makes to a mock GitHub MCP server and stamps it, verifies each
response, and tracks the influence of what the agent has read. One issue on a
public repository carries a prompt injection that asks the agent to copy private
notes into a public pull request, and with Paztport on, the server refuses that
write by the owner-aware rule ([§3](#3-operations-influence-and-sessions)). The
model runs locally through Ollama, and an eval runs the agent many times in each
setting, with Paztport on and off and with and without the planted issue, and scores
each run from the server's outcome log.

The idea is offered freely. The code is Apache-2.0, and every cryptographic
primitive comes from each language's standard library (the JDK, Node's
`node:crypto`, Go's `crypto` packages), so anyone can lift it into their own stack.

---

## Contents

1. [The problem: a caller's identity covers one hop](#1-the-problem-a-callers-identity-covers-one-hop)
2. [Two proofs that bind together](#2-two-proofs-that-bind-together)
3. [Operations, influence and sessions](#3-operations-influence-and-sessions)
4. [Security principles](#4-security-principles)
5. [Known limits](#5-known-limits)
6. [Where this could go](#6-where-this-could-go)
7. [Running it](#7-running-it)
8. [Repository layout](#8-repository-layout)
9. [Where to go next](#9-where-to-go-next)

---

## 1. The problem: a caller's identity covers one hop

Service C can verify that service B called it. mTLS and SPIFFE identities make that
*last hop* trustworthy and say nothing about the hops before it, so C doesn't learn
who called B.

An attacker who compromises B, or tricks it, inherits every privilege B has
downstream. A B tricked into using its privileges for someone else is what Norm
Hardy called a **confused deputy** ("The Confused Deputy (or why capabilities might
have been invented)", ACM SIGOPS Operating Systems Review 22(4), 1988). Either way,
the malicious request looks identical to a legitimate one: same headers, same body
shape, same authenticated caller.

What differs is the request's **history**. An illicit route leaves a fingerprint
even when the request itself is clean. Paztport turns that history into a
credential, and makes it unforgeable.

## 2. Two proofs that bind together

A request is accepted only if it proves **two** things: that it really travelled
the route it claims (*proof of travel*), and that the route is one the system
allows (*proof of legitimacy*). Either proof alone is breakable. Together they
aren't.

### 2.1 Proof of travel: the stamp chain

Each hop appends a **stamp** to the `X-Path-Chain` header. A stamp is signed by
the hop's own Ed25519 key, and it signs over the previous stamp's signature:

```mermaid
flowchart LR
    s0["s0 · gateway<br/>prev = (empty)<br/>sig₀ = Sign(k_gateway, …)"]
    s1["s1 · orders<br/>prev = sig₀<br/>sig₁ = Sign(k_orders, …)"]
    s2["s2 · next hop<br/>prev = sig₁<br/>sig₂ = Sign(k_next, …)"]
    s0 -->|"prev links to sig₀"| s1
    s1 -->|"prev links to sig₁"| s2
```

| Field | Meaning |
|---|---|
| `v` | Version, always `3`. |
| `svc` | Service name. The route is rebuilt from these and the `rcv` fields. |
| `inst` | Instance (container hostname), so a response targets one replica, not a whole service. |
| `rid` | Request ID, minted by the origin and carried unchanged. |
| `ts` | When this stamp was signed. The last stamp must be within 5 s of the receiver's clock; the origin within a run window (30 min by default; 30 s for the six services a ticket crosses in the Java mesh). |
| `sess` | The session id, or empty for a chain with no session. |
| `rcv` | The receiver this stamp was signed for: the next stamp's `svc`, or the chain's receiver. Over HTTP it may also name an operation, `service#operation`. |
| `bind` | The binding of what *this hop sent*. Over HTTP, `SHA-256(METHOD \n PATH \n BODY)` (`PATH` with its query). |
| `infl` | The influence commitment, empty for no influence. |
| `prev` | The previous stamp's `sig`; empty at the origin. |
| `sig` | Ed25519 signature over the canonical bytes `3\|svc\|inst\|rid\|ts\|sess\|rcv\|bind\|infl\|prev`. |

Why it's built this way:

- **Chaining through `prev = sig`** makes the chain tamper-evident. Remove,
  reorder, or insert a stamp and some `prev` stops matching, or some signature
  stops verifying.
- **Ed25519 rather than an HMAC** means verifiers need only *public* keys. No
  shared secret is ever distributed, and a compromised verifier can't forge stamps.
- **The receiver binding**, `rcv`, makes each stamp good only for the hop it was
  handed to: the next service, or the chain's receiver. A chain forwarded unchanged
  to any other service fails `BINDING_MISMATCH` before its route is looked at. Over
  HTTP `rcv` can also name the operation the call invokes there (§3).
- **The request binding** ties the chain to the actual payload. The receiver
  recomputes `bind` from the request it got and compares it to the **last** stamp.
  A chain copied from a real request and spliced onto a malicious body no longer
  matches.
- **Receiver binding, request binding and, with mTLS, the peer check** stop anyone
  but the signer using a stamp; a nonce cache refuses the signer's second sending on
  the replica that saw the first, and forgets a key after 15 s, at least twice the
  5 s window.

The Java and Go SDKs sign them over HTTP (the Java mesh, the Envoy Gateway edge), and
the TypeScript SDK over MCP (the agents demo).

Who a rejection names depends on the transport. When it authenticates the sender, as
mTLS does in the Java mesh, the verifier checks that the sender is the last signer
and names that authenticated sender in every result but a `POLICY_EXPIRED`, which
names no one, since it is the verifier's own material running out. Without one, only
an allowed request or a `PATH_NOT_ALLOWED` names a suspect, the last signer: by then
the signatures, receivers and binding have held, so that service's key really signed
this request for this receiver. Every other result, a forwarded chain's included,
names no one.

### 2.2 Proof of legitimacy: the salted Merkle tree

The allowed routes are hashed into a Merkle tree. A service pins only the
**root**, one 32-byte hash that stands for the entire policy, signed by a policy
key. A request carries an `X-Path-Proof`: the sibling hashes from its route's leaf
up to the root.

```mermaid
graph BT
    L0["leaf: gateway/orders/payment<br/>H(0x00 ‖ salt ‖ path)"]
    L1["leaf: gateway/orders"]
    L2["leaf: gateway/search"]
    L3["padding"]
    L4["padding"]
    L5["padding"]
    L6["padding"]
    L7["padding"]
    N01["H(0x01 ‖ L0 ‖ L1)"]
    N23["H(0x01 ‖ L2 ‖ L3)"]
    N45["H(0x01 ‖ L4 ‖ L5)"]
    N67["H(0x01 ‖ L6 ‖ L7)"]
    N03["H(0x01 ‖ N01 ‖ N23)"]
    N47["H(0x01 ‖ N45 ‖ N67)"]
    ROOT["signed root"]

    L0 --> N01
    L1 --> N01
    L2 --> N23
    L3 --> N23
    L4 --> N45
    L5 --> N45
    L6 --> N67
    L7 --> N67
    N01 --> N03
    N23 --> N03
    N45 --> N47
    N67 --> N47
    N03 --> ROOT
    N47 --> ROOT

    classDef target fill:#f6c177,stroke:#b4637a,color:#1f1d2e,stroke-width:2px
    classDef sibling fill:#9ccfd8,stroke:#31748f,color:#1f1d2e,stroke-width:2px
    classDef pad fill:#e6e6e6,stroke:#999999,color:#555555,stroke-dasharray: 3 3
    classDef root fill:#c4a7e7,stroke:#907aa9,color:#1f1d2e,stroke-width:2px
    class L0 target
    class L1,N23,N47 sibling
    class L3,L4,L5,L6,L7 pad
    class ROOT root
```

*Illustrative depth-3 tree, whose routes name services alone; a route can also name
the operation each hop asks for (§3). The proof for the orange leaf is the three
blue siblings; the verifier recomputes upward and compares against the pinned root.
The real tree is padded to depth 8.*

The details carry real weight:

- **Leaf** = `SHA-256(0x00 ‖ salt ‖ "gateway/orders/payment")`.
  **Node** = `SHA-256(0x01 ‖ left ‖ right)`. The `0x00` / `0x01` domain-separation
  prefixes are mandatory. Without them, a 64-byte internal node could be passed off
  as a leaf: the classic Merkle second-preimage attack.
- **Every leaf has a secret 128-bit salt.** A route space is small enough to
  enumerate, so an unsalted `gateway/orders/payment` could be confirmed by hashing
  guesses. With salts, sibling hashes and the root reveal nothing an observer can
  test guesses against. No leaf goes unsalted (§4).
- **Proofs are padded to a fixed depth** (8 levels, 256 leaf slots). Each route
  goes in a random slot, and unused slots are filled with random 32-byte values
  that look like any other hash. Proof length and position therefore leak nothing
  about how many routes exist or where in the policy one sits.
- **The root is signed** by the policy key over its `rootId`, the root and a
  validity window, `notAfter`. A widened policy can't be swapped in without that
  key, and a verifier stops relying on the root once its window has passed. The
  `rootId` is a random label for each build (`v` + 12 random hex chars), not
  derived from the policy, so two builds of one policy share neither a root nor an
  id. The window is 7 days by default. Renewing signs the same tree again under
  the same `rootId` with a new `notAfter`, so proof bundles stay valid. The
  policy key also signs the keyring, which names every service's key, the same way,
  with its own window.

The proof hides the policy, not the request's own route (see §5.2, Inherent).

### 2.3 Why you need both

- **Stamps alone** prove the travel but not its legitimacy. The verifier would
  need the full list of allowed routes, which reveals the map and has to be
  distributed everywhere. Without a policy check, any well-signed chain from a valid
  origin would pass.
- **Merkle proofs alone** prove that *some* route is allowed, not that *this
  request* took it. An attacker could claim a perfectly valid route and attach a
  proof for it.

The binding between the two is one rule: **the verifier rebuilds the route from the
authenticated fields in the stamps, never from any claimed field:** the origin's
`svc`, then the receiver each stamp names in `rcv`. It checks *that* route against
the root, and checks that the last `rcv` names itself. You can't claim a
route you didn't travel, and you can't travel a route that isn't in the tree.

The exact format is in the [protocol spec](poc-sdks/spec/README.md), and
[poc-sdks](poc-sdks/README.md#on-the-wire) has a summary.

## 3. Operations, influence and sessions

The stamps and the tree prove which services a request passed through, and that the
route is allowed. Four more ideas carry the rest of the protocol: which handler each
hop was asked to run, what content shaped a request, whether an answer can be
believed, and how far one organisation trusts another's calls. The known limits rely
on all four, and each links to the spec section that states it in full.

**Operations.** Over HTTP a service may name its operations, so that a policy can
allow a route through one of its handlers and not through another. An operation is
one handler, the code a request runs, and the service lists them in a table,
`ops-<svc>.json`, by method, path template and, optionally, a query condition. A
caller that holds the table names the operation in its stamp's `rcv` as
`service#operation`, so the route records what was asked for: the Java mesh allows
`gateway/orders#createOrder/payment#pay`. The receiver never takes its operation from
the request. It works out from its own routing the handler that will run and checks
the chain against that at check 4, so a chain that names another operation fails
`BINDING_MISMATCH`. The signed root covers each table as one more route,
`<svc>/ops:<hash>`, so tables are pinned with the policy. A call's nonce key names
its caller and the operation, so a caller calls each operation at most once per
request tree.

An operation that acts on one item of many can declare a key in its
table entry: a `{}` path segment or a query parameter, whose value is at most 128
characters long by default and never more than 1024. The receiver reads the key value
from its own route match and the caller from the target it sends; both nonce keys
and the delivery key (§5.1) gain the value, so a keyed operation is called at most
once per request tree for each item. A call to a keyed operation with no key value
fails `BINDING_MISMATCH` and spends nothing, and the Java policy tool lists each
keyed operation when it builds a policy. The MCP profile has no operations, since a
tool call's receiver already names one tool
([operations](poc-sdks/spec/wire.md#operations),
[nonce keys](poc-sdks/spec/verification.md#freshness-and-replay)).

**Influence.** Influence is a record of what content the context held when an action
was decided: a ticket's text, a customer's order, a tool's result. It travels with
each call (`X-Path-Influence` over HTTP), and the call's last stamp commits to it in
`infl`, so a hop can't drop an entry without breaking the stamp. Each entry has a
class: `third-party` for content from outside the trust boundary, which may carry
instructions; `private` for data that must not reach a public destination unless it
belongs to the destination's owner; `public` for what is already public; and
`local-untrusted` for content nothing vouches for, such as a response that was not
attested. An entry may also name an owner, an opaque id of whose data it is, which
the service that served the data takes from its own records, never from the content
([influence](poc-sdks/spec/sessions-and-influence.md#influence)).

**The owner-aware rule.** A write to a public destination is refused when its
influence holds both untrusted content (`third-party` or `local-untrusted`) and
`private` data that is not the destination owner's, an unknown owner on either side
counting as someone else's. So untrusted content can still steer a customer's own
data to that customer, but never someone else's data, or data whose owner nobody
knows. The service applying the rule takes the destination's owner from its own
records, never from the request
([the owner-aware rule](poc-sdks/spec/sessions-and-influence.md#the-owner-aware-rule)).

**Response attestation.** An answer carries a stamp of its own. Over HTTP the
answering service sends `X-Path-Response`: the labels of what it answered, each a
class and, where it has one, an owner from its own records, and one more stamp on
the request's chain, signed for the caller over the status, the body and the labels.
A service attests only when the request's chain passed the live order at that
service; and where it confirms its operation a second time as the handler is about
to run, as the Spring starter does when the chain named one and it recorded the
operation on the request's own dispatch, only an answer whose handler it confirmed.
A chain that names no operation is still attested, and so is a forward the starter
verifies afresh ([Java README](poc-sdks/java/README.md#response-attestation)). So no
origin attests, nor a hop where Paztport is off, and neither a refusal nor a request
that failed in audit mode is attested. The caller adds the labels to its influence
only when the whole response verifies, and counts any other response as one
`local-untrusted` entry, never dropped. An MCP server attests a tool's result the
same way, only for a call that verified
([who attests](poc-sdks/spec/verification.md#http-requests-and-responses),
[content labels](poc-sdks/spec/sessions-and-influence.md#content-labels)).

**Sessions between organisations.** Inside one organisation's mesh every service pins
one policy in advance; across a boundary, the two sides open a session first. Each
sends its signed root, its policy key, its keyring and a fresh nonce, the partner
signs its reply, and every stamp in the session carries the session id in `sess`,
so a chain made for one session fails in any other. The partner has pinned the
sender's policy key out of band, and opens an **attested** session only when both
roots are present and verify, the sender's policy key is one it pinned and has signed
the sender's keyring, and every root and keyring is current; otherwise the session
is **unsafe**. The sender's egress verifies the internal chain and, in an attested
session, sends one boundary stamp of its own in its place, with the influence
blinded to one entry for each class and owner; the partner verifies that stamp and
applies the owner-aware rule, and the internal route never crosses. An unsafe
session is graded trust, not a refusal: the egress sends no stamp and no influence,
and the partner verifies nothing, refuses the endpoints it lists as disabled
(`UNSAFE_SESSION`) and serves the rest. Either way the partner does not attest its
replies (§5.2), so the sender counts each one `local-untrusted`. The agents demo's
client opens the same kind of session with each MCP server, and in an unsafe one
counts every result `local-untrusted`
([status](poc-sdks/spec/sessions-and-influence.md#status),
[between organisations](poc-sdks/spec/sessions-and-influence.md#between-organisations)).

## 4. Security principles

**Every route leaf carries a secret, random 128-bit salt, and no unsalted leaf
exists.** So a route can't be confirmed by hashing guesses: guessing a salted leaf
means brute-forcing its salt, roughly `2¹²⁸` work. There's no unsalted leaf code
path anywhere in the codebase, tests included.

Signatures are Ed25519 and hashes are SHA-256, relied on for their standard
properties:

- Stamps are **Ed25519** signatures, whose security rests on discrete log on
  Curve25519.
- Integrity (binding, replay, Merkle) rests on SHA-256's preimage and collision
  resistance.

Against a quantum attacker, Grover gives only a quadratic speedup against preimage
search, while Shor breaks Ed25519 outright, which is why the post-quantum plan (§6)
keeps the Merkle tree and swaps only the signatures.

The other principles:

- **Fail closed.** Any parse error, missing header, unknown key, or expired stamp
  is a rejection. Stripping the header must never become an escape hatch.
- **One byte form, read strictly.** Every Paztport object travels as its canonical
  JSON bytes (RFC 8785), or their base64url, and each SDK reads it from those
  bytes with its own strict reader, never through the transport's JSON parser. So
  every implementation accepts and refuses the same bytes, and one signed object
  has one form ([JSON](poc-sdks/spec/wire.md#json)).
- **Only entry points start chains.** The first stamp must come from a key only
  real ingress holds. A compromised internal service can't forge the gateway's
  signature.
- **Never trust a claimed field.** The route is always rebuilt from authenticated
  stamps.
- **Log identities and verdicts, never secrets.** Service IDs, request IDs, and
  reason codes appear in logs. Private keys, salts, and proof bundles never do.

## 5. Known limits

The limits come in three parts: what a deployment must supply for Paztport to
hold, what any design of this kind cannot do, and the shortcuts this repository
takes.

### 5.1 Using it soundly

What Paztport needs from a deployment, and what it deliberately doesn't cover yet.

- **The peer check needs mutual TLS in the service's own process.** A verifier checks
  that the last signer is the transport's authenticated sender (`PEER_MISMATCH`)
  only when it is given one. The Java mesh gives it one: every hop is mutual TLS, and
  `payment` takes the service named in the client certificate as the sender
  ([check 12](poc-demos/java-mesh/README.md#the-verification-pipeline)). Each
  service that checks a peer terminates TLS in its own process, and the SDK reads
  the peer from the certificate verified there, first-hand. Behind a sidecar mesh
  (Istio's or Linkerd's per-pod proxy), mutual TLS ends at the sidecar and the
  application sees only a local connection, so the peer would be a header the
  sidecar asserts. That is a different trust model, in which the application must be
  reachable only through its sidecar, and the SDKs don't support it today. The
  agents demo runs over stdio, which has no TLS, so there the check is skipped and
  the last signer is known only by its signature
  ([the peer check](poc-sdks/spec/verification.md#receivers-the-peer-and-attribution)).
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
  ([attribution](poc-sdks/spec/verification.md#receivers-the-peer-and-attribution)).
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
  same receiver within the 5 s window; only the cache of the replica that saw the
  first sending refuses it, and over HTTP another replica can serve it.
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
  ([replicas and duplicates](poc-sdks/spec/verification.md#freshness-and-replay)).
- **A shared nonce cache is the deployment's to bring.** A service that must also
  hold a compromised caller to each key once per request tree, whatever its replica
  count, can pass its own expiring shared cache to the nonce-cache interface that the
  Java and Go SDKs expose; neither SDK ships one. A cache that cannot answer gives no
  verdict: `enforce` refuses the request 503 and `audit` serves it and records the
  failure ([verification.md](poc-sdks/spec/verification.md#freshness-and-replay)).
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
  [section 6](#6-where-this-could-go)).
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

### 5.2 Limits of the concept

What any design of this kind meets, and what this one has not yet tackled.

**Inherent**

- **Position, not trust.** A compromised hop on a valid route can still misuse
  that route (see the Java demo's
  [threat model](poc-demos/java-mesh/README.md#threat-model)).
- **A service is whoever holds its keys.** Those are its stamping key and the TLS
  key the peer check reads, and a pod that can read or mount them is that service:
  its stamps verify. Paztport attests the path, not that each hop is a legitimate
  deployment. That proof belongs to the workload-identity layer: attestation that
  issues identities only to approved workloads (SPIFFE/SPIRE, for one), signed
  images checked at admission, and admission rules on who may run a service's pods.
  Because the peer check binds each stamp to its TLS peer, once TLS identity
  is attested a copy holding a stolen stamping key is refused at the next hop with a
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
  [Hashed content](poc-sdks/spec/wire.md#hashed-content)).
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

### 5.3 Limits of this proof of concept

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
- **The nonce cache is in memory, per replica,** and forgets a key after 15 s, at
  least twice the 5 s window. It has no size cap, so a flood within that time grows
  it. A shared, expiring store is optional hardening against a compromised
  caller; duplicate delivery is the receiving application's to handle (see
  "Duplicate delivery is the application's" above).
- **The Spring starter's mode switch is guarded by a token alone.** On a service
  that verifies requests, the starter registers `/admin/mode`, which switches the
  verifier between `audit` and `enforce` or turns Paztport off on the hop, only where
  `paztport.admin-token` is set, and answers only a request whose `X-Admin-Token`
  matches it (the demo makes a token for each run, as `PAZTPORT_ADMIN_TOKEN`). The
  starter verifies every path, this one included, unless `paztport.unverified-paths`
  lists it ([unverified paths](poc-sdks/java/README.md#unverified-paths)); the demo
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

## 6. Where this could go

These are design directions, except where a bullet says what is built.

- **Post-quantum.** Keep the Merkle tree and swap Ed25519 stamps for hash-based
  signatures. SLH-DSA (FIPS 205) is stateless, but at ~8–50 KB per signature, one
  stamp as `X-Path-Chain` encodes it is larger than Tomcat's default 8 KB header
  limit with any parameter set, and two stamps with the smallest are larger than
  Node's default 16 KiB; those limits can be raised. XMSS and LMS are smaller but
  stateful, and reusing a key is catastrophic. Signing isn't behind a swap
  interface yet. Making it swappable would take a `StampSigner` / `StampVerifier`
  interface, an algorithm tag in `keyring.json` and alongside each `sig`, and, for
  XMSS or LMS, a signer with persisted key state. The interface is cheap; managing
  stateful keys and living with the header sizes is the real work.
- **AI agents and MCP.** For an agent, a path is a sequence of steps
  (`user → orchestrator → subagent → tool`, or
  `read_inbox → summarize → send_email`), and the agent *runtime*, not the model,
  holds the keys and stamps each step. A sensitive MCP server can require a chain
  proving a call began in a user session and went only through approved agents,
  without the client revealing its agent architecture. The MCP chain, the session
  handshake, influence tracking and response attestation are built in the
  TypeScript SDK and [the agents demo](poc-demos/agents-mcp/README.md), against a
  mock MCP server. Still open: running it in a production agent runtime.
- **Async boundaries.** Treat a queue like another organisation: attest and
  summarise at enqueue, carry a compact signed commitment plus the broker's message
  ID, and let the message ID replace the timestamp as the anti-replay key. Fan-in
  (joins) is the open frontier and likely needs its own commitment structure.
- **Scale.** A forest of sub-roots partitioned by destination keeps every proof at
  `log(subtree)` no matter how large the global path space gets. It also shrinks the
  blast radius of a policy change to one domain.
- **Interrupted work and race conditions.** A quarantined node can't be trusted to
  hand off its own work. The trusted party is the origin, which can mint a
  retry (the same `rid` and an `attempt` counter, which would need a new field in
  the signed bytes and the nonce key) that a replayer can't forge. The same
  verifiable `rid` could own leases on declared intent keys, giving path-scoped
  concurrency control at the attested boundary.
- **Cross-organisation trust.** Publish signed roots, never trees. An egress
  gateway verifies the internal chain and emits one boundary attestation. The
  boundary attestation is implemented in the Java demo (see
  [the storyline](poc-demos/java-mesh/README.md#the-support-assistant-storyline)).
  What is still a direction is the rest: an append-only log of roots (in the style
  of Certificate Transparency) lets partners detect an unexpected new root without
  seeing the policy behind it.

## 7. Running it

**Prerequisites:** JDK 25 or newer and Maven for the Java side, Docker with Compose
for the mesh demo, Node 22.19 or newer with npm for the TypeScript side, Go 1.27 or
newer for the Go SDK, staticcheck 2026.2.2 or newer for `./run test`'s checks of the
Envoy Gateway processor, and unzip for its jar check; for the Envoy Gateway proof of
concept, Maven running on Java 25 or newer (as `mvn -v` reports it), Docker, Go, kind
0.33, kubectl 1.36 and Helm 4.3 or newer, and python3 for its measurements. macOS and Linux; on Windows use WSL.

```bash
./run test        # the name and link checks, the TypeScript type checks, gofmt, go vet and staticcheck, every suite, a check of the built jars and of the processor's third-party list; no Docker and no model
./run java-mesh   # build the Java SDK and the mesh demo, then run every scenario
./run envoy-gateway  # the edge processor on Envoy Gateway in a local kind cluster, and its checks; the cluster stays up
./run envoy-gateway measure  # the measurement suites, on a cluster of their own; needs python3
./run agents-mcp  # install the TypeScript SDK and the agents demo, set up demo keys, start the demo page
./run bench       # time the primitives a verifying hop pays for (JMH, a few minutes); not part of test
```

`./run` with no argument prints its usage. A missing prerequisite stops it with one
line naming what is missing, before anything is built. Each folder still builds on
its own; its README has the commands.

## 8. Repository layout

```
paztport/
├── LICENSE, NOTICE           Apache-2.0, copyright
├── LICENSING.md              what each jar and image carries, and why
├── THIRD-PARTY.txt           runtime dependencies and their licences (generated)
├── licenses/                 licence texts the bundling jars carry, and the licence plugin's shared settings
├── run                       front door: java-mesh, envoy-gateway, agents-mcp, test, bench
├── poc-sdks/
│   ├── spec/                 the protocol spec, and vectors/: v3.json, which every SDK replays (Java and Go all of it but the MCP profile); http-v3.json, Java's and Go's; events.json, all three's; json.json, TypeScript's but its http bindings, Java's and Go's but the MCP profile's sections
│   ├── scripts/              name check, link check, jar check, tests for ./run, THIRD-PARTY.txt regeneration
│   ├── java/                 core, http, spring (paztport-core, paztport-http, paztport-spring), tools/keygen, tools/policy-tool, tools/bench
│   ├── typescript/           core, mcp (@paztport/core, @paztport/mcp), policy-tool
│   └── go/                   one module: the protocol's packages, and paztporthttp with wire and boundary
└── poc-demos/
    ├── java-mesh/            services/ (gateway, orders, payment, search, tickets, assistant, mailer), psp, responder; Compose, demo.sh, measure.sh, load.js, policy/ (paths.yaml, ops-*.json), psp-policy/
    ├── envoy-gateway/        the edge at Envoy Gateway: the Go ext_proc processor, its Helm chart, a kind cluster and its checks
    └── agents-mcp/           agent/MCP demo
        ├── mock-github-mcp/  mock GitHub MCP server (+ docs server), stdio, demo agent target
        ├── pi-extension/     pi extension: stamps MCP calls, verifies responses, tracks influence
        ├── policies/         the client and server route policies that setup-demo signs
        ├── scripts/          setup-demo: throwaway demo keys and policies
        ├── eval/             runs the agent many times per setting, scores from the outcome log, verify
        ├── demo-ui/          local web page: one run at a time, evidence per call, results folders
        └── scenarios/        scenario folders: repositories, planted text, scoring data
```

## 9. Where to go next

- [poc-sdks](poc-sdks/README.md): the SDKs and a summary of the on-the-wire format.
  - [poc-sdks/java](poc-sdks/java/README.md) and
    [poc-sdks/typescript](poc-sdks/typescript/README.md): one section per package.
  - [poc-sdks/go](poc-sdks/go/README.md): the Go module's packages, and what the code
    that embeds it does.
  - [poc-sdks/spec](poc-sdks/spec/README.md): the protocol spec and the shared conformance
    vectors.
- [poc-demos](poc-demos/README.md): the demos.
  - [poc-demos/java-mesh](poc-demos/java-mesh/README.md): the mesh walkthrough, threat
    model, scenarios, responder, measurements and configuration.
  - [poc-demos/envoy-gateway](poc-demos/envoy-gateway/README.md): the edge processor at
    an Envoy Gateway, its chart, and the checks on a local kind cluster.
  - [poc-demos/agents-mcp](poc-demos/agents-mcp/README.md): the agent and MCP demo.

## Licence and third-party software

Copyright 2026 The Paztport Authors. Licensed under Apache-2.0 (see
[LICENSE](LICENSE) and [NOTICE](NOTICE)). Its patent grant (section 3) licenses
each contributor's patent claims that their contribution infringes, to everyone who
uses the code, commercially included, and ends for anyone who sues over them. The
repository bundles no third-party code. [THIRD-PARTY.txt](THIRD-PARTY.txt) lists the
runtime dependencies and the licence each is used under, and
[LICENSING.md](LICENSING.md) says what each jar and image carries, and how to
regenerate the list.
