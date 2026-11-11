# Paztport

**A passport for requests.** The "zt" stands for zero trust.

Most security asks one question at the door: *who are you?* Paztport asks a
second question: ***how did you get here?***

That second question matters once an attacker has taken over one part of a
system. A request from that part carries its valid credentials, so a service that
asks only *who are you?* (the payment service, the customer database, the admin
panel) does what it's told.

This repository holds Paztport, a protocol for path attestation, written as a
[spec](poc-sdks/spec/README.md) (version 3); SDKs in Java and Go, which carry it
over HTTP, and in TypeScript, which carries it over MCP, the protocol AI agents
use to call tools; and three demos: a small
[mesh of Spring Boot services](poc-demos/java-mesh/README.md), Paztport at an
[Envoy Gateway](poc-demos/envoy-gateway/README.md) edge on a local Kubernetes
cluster, and an [AI agent's MCP calls](poc-demos/agents-mcp/README.md).
It is a proof of concept: nothing is published to a package registry, and nothing
has been audited. Claude, an AI model, wrote all of its code and documentation.

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
its credentials are valid and its contents look perfectly normal. The refusal can
also produce a signed event that, where the evidence allows, names the machine that
sent the request; the caller is never told. What happens next is your choice:
Paztport defines the event and when it may be acted on, not the response. In the
demo, a responder acts on it by moving the machine into isolation and replacing it
with a clean copy, automatically, within seconds.

## Concepts

<!--
Note for the author: this section is yours to write, in your own words. A
first-time reader reaches it straight after the plain-terms idea. The opening
names the technique, path attestation, without defining it, and the sections
below use these terms: origin, stamp, chain, receiver, proof, root, keyring, the
live order of checks, the `audit` and `enforce` modes, responder and event,
influence, and session. Until this section exists, each term gets a
one-clause definition where it is first used; those inline definitions will be
indexed here, with their lines, so you can find them and fold them in. Defined
once here, the terms let the rest of the README lean on them.
-->

## What it does

- It limits what a break-in is worth. A compromised component can do only what
  its legitimate position in the system allows: an attacker who takes over the
  search service gets the search service, not the payment system behind it.
  Paztport doesn't make the compromised machine trustworthy; it limits how far
  the compromise can travel. [Known limits](docs/limits.md) lists what it needs
  from a deployment and what it cannot do.
- It carries calls between organisations. The two sides first open a session,
  exchanging the signed fingerprints of their policies, each side's list of
  approved routes. In an attested session, which a partner opens only with a
  sender whose policy-signing key it pinned in advance, the sender's last internal
  service checks the request's stamps and sends one stamp of its own in their
  place, so the internal route stays inside.
  The Java and Go SDKs implement this over HTTP; in the Java mesh, a payment
  provider plays the second organisation
  ([between organisations](poc-sdks/spec/sessions-and-influence.md#between-organisations)).
- It covers an AI agent's tool calls. The
  [agents demo](poc-demos/agents-mcp/README.md) stamps each call an agent makes to
  an MCP server. A planted prompt injection asks the agent to copy private notes
  into a public pull request, and with Paztport on, the server refuses that write
  by the owner-aware rule: a write to a public destination is refused when the
  content behind it includes untrusted text together with private data not known
  to belong to the destination's owner
  ([the owner-aware rule](poc-sdks/spec/sessions-and-influence.md#the-owner-aware-rule)).
  [Where this could go](docs/directions.md) says what is still open.
- It is checked end to end. The Java mesh's `demo.sh` makes 26 checks, among them
  forged stamps, replays, altered bodies, expired requests, routes the policy does
  not list, `audit` mode (which records the verdict and lets a failing request
  through, where `enforce` refuses it), and the quarantine with its circuit
  breaker; a green run ends `26 passed, 0 failed`
  ([the scenarios](poc-demos/java-mesh/README.md#running-it)).
- Its cost is measured. Checking a request takes a few Ed25519 verifications and
  SHA-256 hashes. In the
  [Java mesh](poc-demos/java-mesh/README.md#measurements), `enforce` adds about
  1.9 ms at the median with one hop enforcing, most of it stock-JDK Ed25519. The
  [Envoy Gateway](poc-demos/envoy-gateway/README.md#measurements) processor adds
  0.35 ms at the median at 1000 requests a second.

The code is Apache-2.0. Every cryptographic primitive the SDKs use comes from each
language's standard library (the JDK, Node's `node:crypto`, Go's `crypto`
packages); the Java keygen tool also uses Bouncy Castle, to write X.509
certificates.

---

## Contents

- [The idea in plain terms](#the-idea-in-plain-terms)
- [Concepts](#concepts)
- [What it does](#what-it-does)
- [How it works](#how-it-works)
  - [The problem](#the-problem)
  - [Two proofs](#two-proofs)
  - [Beyond routes](#beyond-routes)
  - [Design rules](#design-rules)
- [What the demos show](#what-the-demos-show)
- [5. Known limits](#5-known-limits)
- [6. Where this could go](#6-where-this-could-go)
- [7. Running it](#7-running-it)
- [8. Repository layout](#8-repository-layout)
- [9. Where to go next](#9-where-to-go-next)

---

## How it works

### The problem

Service C can verify that service B called it: mTLS and SPIFFE identities make that
*last hop* trustworthy, and say nothing about the hops before it. So an attacker who
compromises B, or tricks it, inherits every privilege B has downstream. A B tricked
into using its privileges for someone else is what Norm Hardy called a **confused
deputy** ("The Confused Deputy (or why capabilities might have been invented)", ACM
SIGOPS Operating Systems Review 22(4), 1988). Either way, the malicious request
looks identical to a legitimate one: same headers, same body shape, same
authenticated caller.

An illicit route leaves a fingerprint in the request's **history** even when the
request itself is clean. Paztport turns that history into a credential, and makes
it unforgeable without a hop's own key.

### Two proofs

A request is accepted only if it proves **two** things: that it really travelled
the route it claims (*proof of travel*), and that the route is one the system
allows (*proof of legitimacy*). Either proof alone leaves a hole. Together, a
request can neither claim a route it did not travel nor travel a route the policy
does not list.

#### Proof of travel: the stamp chain

Each hop appends a **stamp** to the request's **chain**, the list of stamps the
request carries, starting from its **origin**, the chain's first signer (over HTTP,
the chain travels in the `X-Path-Chain` header). A stamp names its **receiver**,
the service the hop hands the request to, which verifies the chain it is handed.
A stamp is signed by the hop's own Ed25519 key, and it signs over the previous
stamp's signature:

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
| `inst` | The signer's instance, as the signer reports it (in the Java mesh, its container's hostname), so a **responder**, the service a verifier reports refusals to and which may act on them, can act on one replica, not a whole service. |
| `rid` | Request ID, minted by the origin and carried unchanged. |
| `ts` | When this stamp was signed. The last stamp must be within the call window (5 s by default) of the receiver's clock, and the origin's within the run window (30 min by default, for an agent run that reuses one origin; inside one mesh, where a request is a single call rather than a run, the origin may be held to the call window too). |
| `sess` | The id of the session the chain was stamped in, or empty for a chain with no session, as inside one mesh. |
| `rcv` | The receiver this stamp was signed for: the next stamp's `svc`, or the chain's receiver. Over HTTP it may also name an operation, `service#operation`. |
| `bind` | The binding of what *this hop sent*. Over HTTP, `SHA-256(METHOD \n PATH \n BODY)` (`PATH` with its query). |
| `infl` | The commitment to the request's **influence**, the record of what content the context held when the call was decided; empty for no influence. |
| `prev` | The previous stamp's `sig`; empty at the origin. |
| `sig` | Ed25519 signature over the canonical bytes `3\|svc\|inst\|rid\|ts\|sess\|rcv\|bind\|infl\|prev`. |

Why it's built this way:

- Chaining through `prev = sig` makes the chain tamper-evident. Remove, reorder, or
  insert a stamp and some `prev` stops matching, or some signature stops verifying.
- Ed25519 rather than an HMAC means verifiers need only *public* keys. No shared
  secret is ever distributed, and a compromised verifier can't forge stamps.
- The receiver binding, `rcv`, makes each stamp good only for the hop it was handed
  to: the next service, or the chain's receiver. A chain forwarded unchanged to any
  other service fails `BINDING_MISMATCH` before its route is looked at. Over HTTP
  `rcv` can also name the operation the call invokes there
  ([Operations](#operations)).
- The request binding ties the chain to the actual payload. The receiver recomputes
  `bind` from the request it got and compares it to the **last** stamp. A chain
  copied from a real request and spliced onto a malicious body no longer matches.
- Receiver binding, request binding and the peer check (with mTLS, the last signer
  must be the sender the transport authenticated) stop anyone but the signer using a
  stamp; a nonce cache refuses the signer's second sending on the replica that saw
  the first, and forgets a key after the nonce TTL (15 s by default, and never under
  twice the call window).

A verdict can name the sender it holds responsible, in the service's own logs and
in the signed **event** the service may send its responder, and who that can be
depends on whether the transport authenticated the sender
([Using it soundly](docs/limits.md#using-it-soundly)).

#### Proof of legitimacy: the salted Merkle tree

The allowed routes are hashed into a Merkle tree. A service pins only the
**root**, one 32-byte hash that stands for the entire policy, signed by the
**policy key**, the policy owner's signing key, which stays offline. A request
carries a **proof** of its route (over HTTP, the `X-Path-Proof` header): the
sibling hashes from its route's leaf up to the root.

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
the operation each hop asks for ([Operations](#operations)). The proof for the
orange leaf is the three blue siblings; the verifier recomputes upward and compares
against the pinned root.*

How the tree is built, and why:

- **Leaf** = `SHA-256(0x00 ‖ salt ‖ "gateway/orders/payment")`.
  **Node** = `SHA-256(0x01 ‖ left ‖ right)`. The `0x00` / `0x01` domain-separation
  prefixes are mandatory. Without them, a 64-byte internal node could be passed off
  as a leaf: the classic Merkle second-preimage attack.
- Every leaf has a secret 128-bit salt. A route space is small enough to enumerate,
  so an unsalted `gateway/orders/payment` could be confirmed by hashing guesses;
  confirming a salted one means brute-forcing its salt, roughly `2¹²⁸` work, and
  sibling hashes and the root reveal nothing an observer can test guesses against.
  The leaf hash takes the salt as an argument, so there is no leaf function without
  one; the policy tool, which builds and signs a policy, draws a random 16-byte salt
  for each leaf, and a proof on the wire must carry a 16-byte `leafSalt`.
- Proofs are padded to a fixed depth (8 levels and 256 leaf slots by default, set
  by `PAZTPORT_PROOF_DEPTH` in the Java policy tool). Each route goes in a random
  slot, and unused slots are filled with random 32-byte values that look like any
  other hash. Proof length and position therefore leak nothing about how many
  routes exist or where in the policy one sits.
- The root is signed by the policy key over its `rootId`, the root and a validity
  window, `notAfter`. A widened policy can't be swapped in without that key, and a
  verifier stops relying on the root once its window has passed. The `rootId` is a
  random label for each build (`v` + 12 random hex chars), not derived from the
  policy, so two builds of one policy share neither a root nor an id. The window is
  7 days by default. Renewing signs the same tree again under the same `rootId` with
  a new `notAfter`, so proof bundles, the files that hold each service's proofs,
  stay valid. The policy key also signs the **keyring**, which names every
  service's key, the same way, with its own window.

The proof hides the policy, not the request's own route (see
[Limits of the concept](docs/limits.md#limits-of-the-concept), Inherent).

#### Why you need both

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

A receiver makes these checks, with freshness, replay and the peer check among
them, in one fixed sequence, the **live order**, and the first that fails is the
result. The order is part of the protocol, so every implementation refuses the
same chain with the same code
([the live order](poc-sdks/spec/verification.md#the-live-order)).

The exact format is in the [protocol spec](poc-sdks/spec/README.md), and
[poc-sdks](poc-sdks/README.md#on-the-wire) has a summary.

### Beyond routes

The stamps and the tree prove which services a request passed through, and that its
route is allowed. Five more ideas carry the rest of the protocol: which handler each
hop was asked to run, what content shaped a request, which public writes that
content may make, whether an answer can be believed, and how far one side trusts
another's calls. Each ends in a link to the spec section that states it in full.

#### Operations

Over HTTP a service may name its operations, the handlers a request can run, so
that a policy can allow a route through one handler and not through another. The
service lists them in an operation table, by method, path template and, optionally,
a query condition, and the signed root covers each table, so tables are pinned with
the policy. A caller that holds the table names the operation in its stamp's `rcv`
as `service#operation`, so the route records what was asked for: the Java mesh
allows `gateway/orders#createOrder/payment#pay`. The receiver never takes its
operation from the request: it works out from its own routing which handler will
run, and a chain that names another fails `BINDING_MISMATCH`. A caller calls each
operation at most once per request tree, the calls made under one origin's request
ID; an operation that acts on one item of many can declare a key, the path segment
or query parameter that names the item, and is then called once per item. Over MCP
there are no operations, since a tool call's receiver already names one tool
([operations](poc-sdks/spec/wire.md#operations),
[nonce keys](poc-sdks/spec/verification.md#freshness-and-replay)).

#### Influence

Influence travels with each call (`X-Path-Influence` over HTTP), and the call's last
stamp commits to it in `infl`, so a hop can't drop an entry without breaking the
stamp. Its entries record content such as a ticket's text, a customer's order or a
tool's result, and each has a class: `third-party` for content from outside the
trust boundary, which may carry instructions; `private` for data that must not reach
a public destination unless it belongs to the destination's owner; `public` for
what is already public; and `local-untrusted` for content nothing vouches for, such
as a response that was not attested. An entry may also name an owner, an opaque id
of whose data it is, which the service that served the data takes from its own
records, never from the content
([influence](poc-sdks/spec/sessions-and-influence.md#influence)).

#### The owner-aware rule

A write to a public destination is refused when its influence holds both untrusted
content (`third-party` or `local-untrusted`) and `private` data that is not the
destination owner's, an unknown owner on either side counting as someone else's. So
untrusted content can still steer a customer's own data to that customer, but never
someone else's data, or data whose owner nobody knows. The service applying the rule
takes the destination's owner from its own records, never from the request
([the owner-aware rule](poc-sdks/spec/sessions-and-influence.md#the-owner-aware-rule)).

#### Response attestation

An answer carries a stamp of its own: one more stamp on the request's chain, signed
for the caller over the status, the body and the labels of what the service
answered, each label a class and, where the service has one, an owner from its own
records (over HTTP, the `X-Path-Response` header). A service attests only an answer
to a request whose chain passed the live order there, so no origin attests, nor a
hop where Paztport is off, and neither a refusal nor a request that failed in
`audit` mode is attested. A service that confirms its operation a second time, as
the handler is about to run, attests only an answer whose handler it confirmed. The
caller adds the labels to its influence only when the whole response verifies, and
counts any other response as one `local-untrusted` entry, never dropped. An MCP
server attests a tool's result the same way, only for a call that verified
([who attests](poc-sdks/spec/verification.md#http-requests-and-responses),
[content labels](poc-sdks/spec/sessions-and-influence.md#content-labels)).

#### Sessions

Inside one organisation's mesh every service pins one policy in advance; across a
trust boundary the two sides open a session first ([What it does](#what-it-does)
has the attested case between organisations). Each sends its signed root, policy
key, keyring and a fresh nonce, the other signs its reply, and every stamp in the
session carries the session id in `sess`, so a chain made for one session fails in
any other. In an attested session, the one stamp that crosses commits to the
request's influence blinded to one entry for each class and owner, which is all the
partner needs to apply the owner-aware rule. A session that is not attested is
unsafe: graded trust, not a refusal, in which the sender signs no stamp and sends
no influence, and the partner verifies nothing, refuses the endpoints it lists as
disabled (`UNSAFE_SESSION`) and serves the rest. Either way, a partner does not
attest its replies (see
[Limits of the concept](docs/limits.md#limits-of-the-concept)), so the sender counts
each one `local-untrusted`. Over MCP a client opens a session with a server before
its first call, and in an unsafe one counts every result `local-untrusted`
([status](poc-sdks/spec/sessions-and-influence.md#status),
[between organisations](poc-sdks/spec/sessions-and-influence.md#between-organisations)).

### Design rules

- Signatures and hashes are relied on for their standard properties: stamps are
  Ed25519 signatures, whose security rests on discrete log on Curve25519, and
  integrity (binding, replay, the tree) rests on SHA-256's preimage and collision
  resistance. Against a quantum attacker, Grover gives only a quadratic speedup
  against preimage search, while Shor breaks Ed25519 outright, which is why the
  post-quantum plan ([Where this could go](docs/directions.md)) keeps the Merkle
  tree and swaps only the signatures.
- Fail closed. Any parse error, missing header, unknown key, or expired stamp is a
  rejection; stripping the header must never become an escape hatch.
- One byte form, read strictly. Every Paztport object travels as its canonical JSON
  bytes (RFC 8785), or their base64url, and each SDK reads it from those bytes with
  its own strict reader, never through the transport's JSON parser. So every
  implementation accepts and refuses the same bytes, and one signed object has one
  form ([JSON](poc-sdks/spec/wire.md#json)).
- Only entry points start chains. An origin's key is held only by real ingress, so
  a compromised internal service can't start a chain or forge the gateway's
  signature.
- Never trust a claimed field. The route is rebuilt from authenticated stamps, a
  receiver's operation from its own routing, and a destination's owner from the
  deciding service's own records, never from anything the request says.
- Log identities and verdicts, never secrets. Service IDs, request IDs and reason
  codes appear in logs; private keys, salts and proof bundles never do.

## What the demos show

It works end to end. In the [Java mesh demo](poc-demos/java-mesh/README.md), a
request with a perfectly valid body, sent by a service that is legitimately on the
network, is **rejected purely because of where it came from**, and the offending
container is **quarantined and replaced automatically**. All the scenarios and a
circuit-breaker check pass (`demo.sh` reports 26 checks, among them forged,
replayed, expired and spliced requests, routes the policy does not list, audit
mode, and the quarantine with its circuit breaker), and
the overhead has been measured.

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
write by [the owner-aware rule](#the-owner-aware-rule). The
model runs locally through Ollama, and an eval runs the agent many times in each
setting, with Paztport on and off and with and without the planted issue, and scores
each run from the server's outcome log.

## 5. Known limits

What a deployment must supply, what any design of this kind cannot do, and what this
proof of concept leaves out are listed in [docs/limits.md](docs/limits.md).

## 6. Where this could go

The directions beyond this proof of concept are in [docs/directions.md](docs/directions.md).

## 7. Running it

**Prerequisites:** JDK 25 or newer and Maven for the Java side, Docker with Compose
for the mesh demo, Node 22.19 or newer with npm for the TypeScript side, Ollama,
running, with a model pulled (for example `ollama pull qwen3:4b`) for the agents
demo, Go 1.27 or newer for the Go SDK, staticcheck 2026.2.2 or newer for
`./run test`'s checks of the Envoy Gateway processor, and unzip for its jar check;
for the Envoy Gateway proof of concept, Maven running on Java 25 or newer (as
`mvn -v` reports it), Docker, Go, kind
0.33, kubectl 1.36 and Helm 4.3 or newer, and python3 for its measurements. macOS and Linux; on Windows use WSL.

```bash
./run test        # the name, link and Java import checks, the TypeScript type checks, gofmt, go vet and staticcheck, every suite, a check of the built jars and of the processor's third-party list; no Docker and no model
./run java-mesh   # build the Java SDK and the mesh demo, then run every scenario; the mesh stays up
./run envoy-gateway  # the edge processor on Envoy Gateway in a local kind cluster, and its checks; the cluster stays up
./run envoy-gateway measure  # the measurement suites, on a cluster of their own; needs python3
./run agents-mcp  # install the TypeScript SDK and the agents demo, set up demo keys, start the demo page
./run bench       # time the primitives a verifying hop pays for (JMH, a few minutes); not part of test
```

`./run` with no argument prints its usage. A missing prerequisite stops it with one
line naming what is missing, before anything is built; Ollama is the exception,
which `./run agents-mcp` only reports as reachable or not. Each folder still builds
on its own; its README has the commands.

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
│   ├── scripts/              name check, link check, import check, jar check, tests for ./run, THIRD-PARTY.txt regeneration
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
source tree contains no third-party code, but some built jars (the shaded tool jars
and the demo's Spring Boot jars) bundle libraries; [LICENSING.md](LICENSING.md)
says which. [THIRD-PARTY.txt](THIRD-PARTY.txt) lists the
runtime dependencies and the licence each is used under, and
[LICENSING.md](LICENSING.md) says what each jar and image carries, and how to
regenerate the list.
