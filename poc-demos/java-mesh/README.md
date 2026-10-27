# Java mesh demo

A small mesh of Spring Boot services that uses the Java SDK
([poc-sdks/java](../../poc-sdks/java/README.md)), with a responder that
quarantines offending containers. The idea and the concepts are in the
[root README](../../README.md).

Contents: [The system at a glance](#the-system-at-a-glance) · [A request, end to end](#a-request-end-to-end) · [Least knowledge](#least-knowledge-who-holds-what) · [The verification pipeline](#the-verification-pipeline) · [Response attestation](#response-attestation) · [Threat model](#threat-model) · [Response](#response-quarantine-not-deletion) · [Modes and rollout](#modes-and-rollout) · [What building it taught us](#what-building-it-taught-us) · [Measurements](#measurements) · [Running it](#running-it) · [Configuration](#configuration)

## The system at a glance

The demo is a small mesh of four services. `payment` is the sensitive endpoint
and verifies every request it gets. `search` is reachable on the network and can
call `payment`, but its only legitimate route is `gateway → search`, so in the demo
it plays the attacker. Every hop is mutual TLS, with one certificate per service
from one CA, and every caller checks the attested responses it gets back.

```mermaid
flowchart LR
    client(("client"))

    subgraph mesh["mesh network"]
        gateway["gateway<br/>(only allowed origin)"]
        orders["orders"]
        payment["payment<br/>(verifier)"]
        search["search<br/>(attacker in the demo)"]
        responder["responder<br/>(quarantine controller)"]
    end

    subgraph quarantine["quarantine network (internal, isolated)"]
        jailed["isolated suspect<br/>(kept running for forensics)"]
    end

    client --> gateway
    gateway --> orders
    orders --> payment
    gateway --> search
    search -. "illicit call" .-> payment
    payment -. "rejection events" .-> responder
    responder -. "Docker API: isolate + replace" .-> jailed
```

Allowed routes live in [`policy/paths.yaml`](policy/paths.yaml):

```yaml
paths:
  - [gateway, orders, payment]
  - [gateway, orders]
  - [gateway, search]
```

| Component | Role |
|---|---|
| `services/*` | Four tiny Spring Boot services. The business logic is deliberately trivial. |
| `responder` | Counts rejections and quarantines and replaces offending containers through the Docker API. |

The services use `paztport-spring`, and Compose runs the SDK's `keygen` and
`policy-tool` as one-shot jobs; [poc-sdks/java](../../poc-sdks/java/README.md)
describes them.

## A request, end to end

```mermaid
sequenceDiagram
    autonumber
    participant C as client
    participant G as gateway (origin)
    participant O as orders
    participant P as payment (verifier)

    C->>G: POST /checkout (mTLS)
    Note over G: mint rid<br/>s0 = Sign(k_gateway, …, rcv = orders, prev = empty)
    G->>O: POST /orders (mTLS)<br/>X-Path-Chain = [s0]<br/>X-Path-Proof = proof(gateway/orders)
    Note over O: s1 = Sign(k_orders, …, rcv = payment, prev = sig of s0)<br/>bind = hash of the /pay request it is about to send<br/>attach proof(gateway/orders/payment)
    O->>P: POST /pay (mTLS, orders' certificate)<br/>X-Path-Chain = [s0, s1]<br/>X-Path-Proof = proof(gateway/orders/payment)
    Note over P: the twelve checks: signatures, links and receivers,<br/>rid, freshness, binding, influence, nonce,<br/>the route gateway/orders/payment against the root,<br/>and the peer: the last signer is orders
    Note over P: r1 = Sign(k_payment, …, rcv = orders, prev = sig of s1)<br/>bind = the 200 and its body
    P-->>O: 200 PAID<br/>X-Path-Response = r1
    Note over O: check [s0, s1, r1] as receiver orders,<br/>with the proof it sent
    Note over O: r0 = Sign(k_orders, …, rcv = gateway, prev = sig of s0)
    O-->>G: 200<br/>X-Path-Response = r0
    Note over G: check [s0, r0] as receiver gateway
    G-->>C: 200
```

Application code never touches any of this. The Spring outbound interceptor
stamps every `RestClient` call through core's `StamperV3`. It takes the target
service from the request URI host (Compose service names double as hostnames),
takes the inbound chain and the influence so far from a request-scoped context,
and attaches the proof for `(chain so far) + target` if this hop holds one. The
inbound filter caches the body, records the received chain for later appends,
runs verification on verifying services, and attests the responses of every
service that holds a stamp key.

A response is attested by one more stamp on the chain the request arrived with,
naming the caller as its receiver and binding the status, the body and any content
labels. The caller runs the same live checks on it, all but the peer check,
against the chain and the proof it sent, so a response needs no proof of its own.
A response that is unattested or fails is still delivered, but counts as untrusted
influence on whatever the caller does next
([Response attestation](#response-attestation)).

## Least knowledge: who holds what

Each route's proof goes to exactly one place: that route's **second-to-last hop**,
because that hop attaches it when calling the last hop. Least knowledge is enforced
by *distribution*, not just by policy.

```mermaid
flowchart LR
    paths[/"policy/paths.yaml"/] --> pt["policy-tool"]
    kg["keygen"] --> polkey[("policy.key")]
    polkey --> pt
    kg --> keyring[("keyring.json<br/>signed, public keys only")]
    kg --> pin[("policy.pub<br/>the pin")]
    kg --> privkeys[("one stamp .key<br/>per service")]
    kg --> tls[("tls/: ca.crt, and a .crt and .key<br/>per service, operator, responder")]
    kg --> cakey[("ca/ca.key<br/>mounted into no service")]

    pt --> root[("root.json<br/>signed root")]
    pt --> bg[("proofs-gateway.json<br/>gateway/orders<br/>gateway/search")]
    pt --> bo[("proofs-orders.json<br/>gateway/orders/payment")]
    pt --> bs[("proofs-search.json<br/>(empty)")]

    root --> payment["payment"]
    keyring --> payment
    pin --> payment
    privkeys -->|"payment.key<br/>attests responses, signs events"| payment
    keyring --> responder["responder"]
    bg --> gateway["gateway"]
    bo --> orders["orders"]
    bs --> search["search"]
```

The diagram leaves out what every service shares: each gets its own certificate
and key and `ca.crt`, and the callers (`gateway`, `orders`, `search`) also get
`keyring.json`, `root.json` and `policy.pub`, to check the responses they get back.

| Component | Holds | Never holds |
|---|---|---|
| gateway / orders | Own stamp key; own proof bundle; the signed keyring, root and pin; own TLS certificate and key, and `ca.crt` | Other services' keys, the tree, any salts but its own proofs' |
| payment (verifier) | The signed keyring, root and pin, and a nonce cache; its own stamp key, which attests its responses and signs its events to the responder; own TLS certificate and key, and `ca.crt` | Any other private key, the tree, salts, proofs |
| search | Own stamp key; an **empty** bundle; the signed keyring, root and pin; own TLS certificate and key, and `ca.crt` | Any proof for a route ending at `payment`, because none exists |
| responder | The keyring, read as mounted, to check that events are signed by `payment`; own TLS certificate and key, and `ca.crt`; the Docker socket | Any stamp key, the pin, the root, the tree, salts, proofs |
| operator (`demo.sh`, `measure.sh`) | A TLS certificate and key, and `ca.crt` | Any stamp key: it is not in the keyring, so it can't start or extend a chain |
| policy-tool | `policy.key`, the full tree and every salt | Nothing is mounted *from* it into services |

Each of the four services verifies the keyring and the root against `policy.pub`,
held apart from the keyring it vouches for, and refuses to start if either fails.
The CA's key is written to its own directory, `out/keys/ca/`, so that
`out/keys/tls/` holds only what may be mounted, and it is mounted into no service.
In Compose every service's key-material mount is a single file; only the one-shot
`keygen` job mounts `out/keys` whole, because it writes there. Each service
container sees only the specific files its role needs, never a shared volume of
keys.

The heart of the demo is `search`'s empty bundle. `search` can reach `payment` on
the network and can sign stamps with its own key. It was never given a proof for a
route to `payment`, and it can't make one: the route `gateway/search/payment` isn't
a leaf, and collision resistance means no sibling set will walk a non-leaf up to
the root.

## The verification pipeline

`payment` runs the protocol's live order, twelve checks, and fails closed at the
first one that doesn't hold:

```mermaid
flowchart TD
    A["request arrives at payment<br/>over mutual TLS"] --> S1["1. chain header present and<br/>parses as v3 stamps?"]
    S1 -->|no| R1["403 CHAIN_MISSING"]
    S1 -->|yes| S2["2. does a signed field<br/>hold the delimiter?"]
    S2 -->|yes| R2["403 BAD_SIGNATURE"]
    S2 -->|no| S3["3. first stamp is an<br/>allowed origin (gateway)?"]
    S3 -->|no| R3["403 BAD_ORIGIN"]
    S3 -->|yes| S4["4. every signature verifies, every prev links,<br/>then each rcv names the next hop<br/>and the last names payment?"]
    S4 -->|bad signature| R4a["403 BAD_SIGNATURE"]
    S4 -->|bad link| R4b["403 BROKEN_LINK"]
    S4 -->|wrong receiver| R4c["403 BINDING_MISMATCH"]
    S4 -->|yes| S5["5. one shared rid?"]
    S5 -->|no| R5["403 RID_MISMATCH"]
    S5 -->|yes| S6["6. every stamp in the session<br/>(empty inside the mesh)?"]
    S6 -->|no| R6["403 SESSION_UNKNOWN"]
    S6 -->|yes| S7["7. last stamp and origin<br/>within 5 s of now?"]
    S7 -->|no| R7["403 EXPIRED"]
    S7 -->|yes| S8["8. last stamp's bind matches the received<br/>method, path and query, and body?"]
    S8 -->|no| R8["403 BINDING_MISMATCH"]
    S8 -->|yes| S9["9. influence parses and the<br/>last stamp commits to it?"]
    S9 -->|no| R9["403 INFLUENCE_MISMATCH"]
    S9 -->|yes| S10["10. rid, last svc<br/>never seen before?"]
    S10 -->|seen| R10["403 REPLAY"]
    S10 -->|new| S11["11. route rebuilt from stamps + payment<br/>walks the proof to the pinned root?"]
    S11 -->|no| R11["403 PATH_NOT_ALLOWED"]
    S11 -->|yes| S12["12. last signer is the service<br/>the client certificate names?"]
    S12 -->|no| R12["403 PEER_MISMATCH"]
    S12 -->|yes| OK["200: handled, response attested"]

    classDef reject fill:#eb6f92,stroke:#b4637a,color:#ffffff
    classDef pass fill:#3e8f6e,stroke:#2a6b52,color:#ffffff
    class R1,R2,R3,R4a,R4b,R4c,R5,R6,R7,R8,R9,R10,R11,R12 reject
    class OK pass
```

Notes on the ordering:

- The order is the protocol's ([verification.md](../../poc-sdks/spec/verification.md#the-live-order)).
  Cheap structural checks run first. The signatures run before anything trusts a
  field. Freshness and binding run before the replay cache is touched, which is why
  a body altered on a replayed request reports `BINDING_MISMATCH` and an aged one
  reports `EXPIRED`.
- **A wrong receiver is a binding failure.** Each stamp signs the hop it was
  handed to, so a chain forwarded unchanged to `payment` fails at check 4, before
  the route is looked at.
- A missing or unparseable **proof** gives `PATH_NOT_ALLOWED`, not `CHAIN_MISSING`:
  without a valid proof you can't show membership. `CHAIN_MISSING` is reserved for
  the chain.
- **Check 12 is the peer check.** `payment` requires a client certificate from the
  mesh CA, and takes the service it names (its common name, when it has exactly
  one) as the sender. The chain's last signer must be that service. It runs last,
  so every other check keeps its code.
- Every rejection returns a 403 with the reason code and publishes an event for
  the responder. Influence that can't be read is never dropped: where verification
  hasn't refused the request first, it is answered `400 INFLUENCE_MISMATCH`.
- **Every result names the peer.** The TLS layer authenticated the sender, so each
  result, `OK` included, names the service its certificate names
  (`suspectSvc`) at the address it connected from (`suspectInst`), whatever the
  chain says. A certificate is issued per service, not per container, so the
  responder still checks that the container at that address runs that service
  (see [Response](#response-quarantine-not-deletion)).
- One trace line per verification shows the verdict, for example after scenario 1:
  `PAZTPORT_TRACE request rid=… reason=OK receiver=payment ✓ peer=orders (mTLS) classes=-`.

## Response attestation

Every service holds a stamp key, so each attests what it answers whenever the
request came with a chain: `X-Path-Response` carries one stamp on that chain, back
to the caller, binding the status, the body and the content labels. `gateway` is
the origin, and the client's requests to it carry no chain, so its answers are not
attested. The caller checks
it against the chain and the proof it sent, with itself as the receiver and no
peer, since TLS hostname verification already authenticated the server it called.
`gateway`, `orders` and `search` each hold the keyring, the root and the pin, so
each checks every response it gets.

- A service attests only a request whose chain verified there, or that it did not
  check (`orders`, which doesn't verify, or `payment` in `off`). A refusal, or a
  request that failed in `audit`, is answered without an attestation: the stamp
  would vouch for a chain the service knows to be bad.
- A verified response's labels become influence on whatever the caller does next.
  Any other response, unattested, failing or a refusal, still reaches the caller,
  and adds one `local-untrusted` influence entry, so content nobody vouched for
  still counts. Every check logs a
  `PAZTPORT_TRACE response rid=… from=… reason=… receiver=…` line.
- The response's nonce key is `<rid>|<target>|resp`, and a request's is
  `<rid>|<last svc>|req`, so a service calls a given receiver at most once per
  request tree.

## Threat model

**The attacker** fully controls one service (`search` in the demo). That includes
its stamp key, its TLS certificate and key, its network position, and every header
it receives. The network lets it call `payment` directly; there is no
NetworkPolicy to hide behind. It does **not** have other services' private keys,
the policy key or the CA key. Its goal is to get `payment` to act on a request.

| Attack | What stops it | Demo scenario |
|---|---|---|
| Call `payment` with no attestation | Fail closed: missing chain is invalid, never "legacy traffic" | 2: `CHAIN_MISSING` |
| Forge a stamp claiming to be `gateway` | Verified against gateway's public key, which the attacker can't sign for | 3: `BAD_SIGNATURE` |
| Extend a real chain it legitimately received, with its own stamp, to `payment` | Route rebuilt from stamps (`gateway/search/payment`) is not a leaf | 4: `PATH_NOT_ALLOWED` |
| Forward that chain unchanged | `gateway`'s stamp names `search` as its receiver, not `payment` | `BINDING_MISMATCH` (the receiver rule the spec's `wrong receiver` vector pins) |
| Replay a captured valid request | Its nonce key, the `rid` and the last signer, already spent | 5: `REPLAY` |
| Keep a valid chain, swap the body | Last stamp's `bind` no longer matches | 6: `BINDING_MISMATCH` |
| Hold a chain and use it later | Stamps older than the freshness window | 7: `EXPIRED` |
| Send another service's fresh chain from its own connection | The last signer must be the service its client certificate names | `PEER_MISMATCH` (the SDK's mutual TLS test) |
| Keep attacking | Instance isolated and replaced after a threshold | 9: quarantine |

**Not defended by design:** a compromised hop that sits on a *valid* route can
still misuse that route. If `orders` were compromised, it could alter what it sends
to `payment`. It would sign the altered request itself, so the misuse is
attributable to it, but it isn't prevented. Attestation constrains **position**,
not **trustworthiness**. The practical result is that lateral movement becomes
*positional*: a compromised node can do only what its legitimate place in the
graph allows.

## Response: quarantine, not deletion

The chain shows exactly where a route stopped being valid, so the response can
target **one instance** rather than a whole service. Docker has no ReplicaSet, so
the `responder` plays that role through the Docker socket.

The decision logic is a small pure function, unit-tested without Docker:

```mermaid
flowchart TD
    E["rejection event<br/>reason, suspectSvc, suspectInst, rid, audit"] --> A{"audit event, or a policy refusal<br/>(INFLUENCE_DENIED, UNSAFE_SESSION)?"}
    A -->|yes| N1["ignore"]
    A -->|no| B{"suspect instance known?"}
    B -->|no| N2["ignore: can't attribute"]
    B -->|yes| C{"3+ events from this instance<br/>within 60 s?"}
    C -->|no| N3["record, wait"]
    C -->|yes| D{"service already quarantined<br/>max times in 10 min?"}
    D -->|yes| ESC["ESCALATE<br/>stop acting, page a human"]
    D -->|no| Q["QUARANTINE this instance"]

    classDef act fill:#f6c177,stroke:#b4637a,color:#1f1d2e
    classDef esc fill:#eb6f92,stroke:#b4637a,color:#ffffff
    class Q act
    class ESC esc
```

The action is then carried out asynchronously:

```mermaid
sequenceDiagram
    participant P as payment
    participant R as responder
    participant D as Docker API

    P->>R: 3rd PATH_NOT_ALLOWED from search at 172.23.0.2 (mTLS)
    R-->>P: decision QUARANTINE (returns immediately)
    Note over R: on a worker thread: find the container at 172.23.0.2<br/>on the mesh network, check it runs search,<br/>then wait a 750 ms grace period<br/>so the request that triggered this can finish
    R->>D: disconnect it from mesh
    R->>D: connect it to quarantine (kept running)
    R->>D: create a clone with the same image, env, labels,<br/>and volume binds, on mesh, under the alias "search"
    R->>D: start the replacement
    Note over D: gateway's https://search now resolves<br/>to the clean replacement
```

Why each piece is there:

- **Quarantine, don't delete.** The suspect moves to an isolated network and keeps
  running, so you keep a live specimen for forensics while a clean replacement
  serves traffic.
- **Attribute to the instance.** Under mutual TLS every result names the peer:
  the service its certificate names, at the address it connected from. The
  responder resolves that address to a container on the mesh network, so it
  isolates one replica, not every pod in the service. A certificate is issued per
  service, not per container, so the responder acts only when that container
  really runs the named service (its Compose service label). Replacements carry
  the same label. Counts are kept per service and instance, so one service's
  events can't build up a count against another's container. A suspect that is
  not an address, as from a verifier given no peer, is looked up as a container
  name; an event with no suspect takes the "ignore: can't attribute" branch.
- **Only attributable refusals count.** `INFLUENCE_DENIED` and `UNSAFE_SESSION`
  are policy refusals of a sound chain, which an honest service misled by its
  input can earn, so the responder never counts them.
- **Require a threshold** (3 in 60 s). One bad event doesn't trigger action, and
  audit-mode events never do.
- **Circuit breaker** (by default at most 2 quarantines per service per 10 min).
  If a deploy adds a legitimate route before the root is updated, every pod on it
  looks guilty. Past the limit the responder stops acting and logs `ESCALATE`.
  Repeated quarantines of one service are also the **reinfection signal**: if the
  replacement is flagged again, the image or an input is the problem, not the pod.
- **Only signed events count.** Anyone on the mesh can reach the responder, so
  `payment` signs each event with its own key (`PAZTPORT_EVENT_KEY_PATH`) inside an
  envelope, and the responder checks it against `keyring.json` with core's
  `EventVerifier`. It refuses, with a 403 and no decision, any event that is
  unsigned, from a signer other than the allowed ones (`payment` by default),
  badly signed, more than 30 s from the responder's clock, or whose `eventId` it
  has already seen. Events go over mutual TLS with `payment`'s certificate, and
  the responder requires one from the mesh CA, but the signature is still what
  counts. The responder reads `keyring.json` as mounted: it holds no pin to check
  it against.

## Modes and rollout

Each verifying service runs in one of three modes (`PAZTPORT_MODE`):

| Mode | Verifies | Rejects | Use |
|---|---|---|---|
| `off` | no | no | Latency baseline |
| `audit` | yes, logs events marked `audit=true` | no | Measure the false-positive rate on real traffic |
| `enforce` | yes | yes, with a 403 | Protection |

The mode governs `payment`'s check of requests only. Callers check every
response they get in every mode, and a response check never refuses anything: it
only decides whether the response counts as trusted.

`audit` is the on-ramp for an existing system. You run it against real traffic,
measure how often retries, health checks, and batch jobs trip it, fix the policy,
then flip individual endpoints to `enforce`. The responder ignores audit events, so
nothing gets quarantined while you're learning.

## What building it taught us

Some of the most useful results came from running the system live, not from the
unit tests. Each of these was root-caused before it was fixed:

- **The quarantine severed the request that triggered it.** The first responder
  acted synchronously inside the event POST. But the suspect was *part of the
  call chain* that produced the event (`demo → search → payment → responder`), so
  pulling it off the network mid-request meant `payment`'s 403 could never be
  delivered back. The triggering call hung. Fix: decide synchronously, act
  asynchronously after a short grace period. The general lesson: **a response
  system must never sit inside the path of the thing it's responding to.**
- **Fresh salts mean fresh root bytes, so every holder reloads together.** The
  `rootId` stays stable for a given policy, but each `policy-tool` run draws new
  salts and the root bytes change. If you restart only the verifier, the callers
  still hold proofs for the old tree and every legitimate request fails. Policy
  rollout has to be atomic across every holder. That's a miniature of the "policy
  drift" problem real deployments will face.
- **Control-plane endpoints must bypass the data-plane check.** The inbound filter
  first verified *every* path, including the admin and debug endpoints, and
  rejected them for lacking a chain. Attestation applies to the attested data path,
  not to the control plane.
- **An SSL bundle changed the HTTP client.** Giving `RestClient` an SSL bundle
  switched it to `HttpURLConnection`, which hands over an error response's body
  only once the status has been read, and otherwise throws. Every refusal seen
  through a stamping client became an exception until the interceptor read the
  status first. Only the live mesh showed it: scenario 4 answered 500 instead of
  mirroring `payment`'s 403.
- **Infrastructure the responder needs has to be created by the responder.**
  Compose doesn't create a network that no service joins, and a container created
  with networking disabled can't then join a network. Both were caught only by
  watching real Docker API errors.

## Measurements

Measured on a single host (Apple Silicon, Docker Desktop, the services on a JDK 21
runtime) with k6 driving the legitimate path (10 virtual users for 20 s, via
[measure.sh](measure.sh)), mutual TLS on every hop. `payment` is toggled between
`off` and `enforce` with everything else identical, so the difference is the cost
of `payment`'s request verification. No request failed in either run.

| | p50 | p99 | mean | max |
|---|---|---|---|---|
| `payment` in `off` (run first) | 12.55 ms | 35.43 ms | 14.13 ms | 56.78 ms |
| `payment` in `enforce` | 10.34 ms | 21.46 ms | 11.09 ms | 49.29 ms |

| Operation | Cost |
|---|---|
| Merkle proof verify (depth 8) | **1.6 µs** |
| SHA-256 (one stamp) | 0.09 µs |
| Ed25519 sign / verify (stock JDK) | ~222 / ~226 µs |
| Request headers at chain depth 2 | 924 B chain + 615 B proof = **1.5 KB** |

What the numbers say:

- **Verification's cost is below the run-to-run noise at this load.** `enforce`
  measured faster than `off`, which verification can't cause: `off` ran first, so
  it most likely carries the JVM's and the connections' warm-up. Read the two
  rows as the same, not as `enforce` being cheaper.
- **The proof of legitimacy is effectively free.** All the cost is in the
  signature chain, one Ed25519 verify per stamp.
- **Stock JDK Ed25519 is the slow part.** It runs about 5–10× slower than
  optimized native implementations, which do tens of microseconds. A hot-path
  deployment would swap the signature implementation; the Merkle machinery
  wouldn't change.
- **The chain grows by about 462 B per stamp, on average** (924 B over two). The proof is a fixed 615 B whatever
  the route length. `X-Path-Influence` is absent when there is no influence, as
  here. The response headers were not measured: `X-Path-Response` carries one
  stamp plus its labels.

Caveats:

- **Single host, loopback networking.** These numbers show feasibility. They
  aren't a production SLA.
- **`off` vs `enforce` isolates request verification, nothing else.** Both runs
  include mutual TLS on every hop, the stamps every caller signs, the response
  stamps `payment` and `orders` sign, and the response checks at `orders` and
  `gateway`. Only `payment` verifies requests in this topology, so a design that
  verifies at every hop multiplies that cost by the number of verifying hops.
- **The primitive costs are JIT-warmed micro-benchmarks from an earlier
  measurement**, made when the mesh still ran v1 over plain HTTP, and not repeated
  for this run. The primitives they time (the Merkle walk, SHA-256 and the JDK's
  Ed25519) are the same. Cold starts pay JIT and class-loading costs that aren't
  reflected here.
- **The false-positive rate isn't measured.** Retries, health checks, and batch
  jobs need real traffic in `audit` mode, and this local POC doesn't generate any.

## Running it

**Prerequisites:** JDK 21 or newer, Maven, Docker with Compose.

`./run java-mesh` from the repository root does the build and runs `demo.sh`.
By hand, from this folder:

```bash
(cd ../../poc-sdks/java && mvn -q install -DskipTests)  # the SDK jars and the tool jars
mvn -q package -DskipTests              # build every module
docker compose build keygen policy-tool # package the freshly built jars
docker compose run --rm keygen          # stamp keys, signed keyring, policy pin, CA and certificates
docker compose run --rm policy-tool     # signed root + per-service proof bundles
export PAZTPORT_ADMIN_TOKEN=$(openssl rand -hex 16)   # token for /admin/mode
docker compose up -d --build            # the mesh + responder
./demo.sh                               # run every scenario, print pass/fail
docker compose up -d --force-recreate payment   # back to your token (see below)
./measure.sh                            # optional: off vs enforce latency + header sizes
```

`measure.sh` switches `payment` between `off` and `enforce` through `/admin/mode`,
so it needs the token `payment` was started with, and it stops with an error if a
switch is refused. `demo.sh` generates its own token on every run and leaves
`payment` running with it, so after `demo.sh` recreate `payment` from a shell that
has your `PAZTPORT_ADMIN_TOKEN` (or re-run `docker compose up -d`) before `measure.sh`.

`docker compose run` reuses an existing image and never rebuilds it. If you
change and rebuild the Java code, run `docker compose build keygen policy-tool`
again before generating keys or policy. Otherwise the old jars run, and you get
output in the old format, for example private keys that aren't owner-only.
`up --build` rebuilds the mesh services itself. Private key files, the TLS keys
and the CA's included, are written owner-read/write only (`0600`). `demo.sh`
regenerates the keys when `policy.pub` or `tls/ca.crt` is missing, so keys from
before mutual TLS are replaced.

Every hop is mutual TLS, so every call is `https` and presents a certificate from
the mesh CA. `demo.sh` and `measure.sh` make their calls from throwaway containers
on the mesh network that present the `operator` certificate, mounted file by file;
the containers run as root to read the owner-only key. k6 can't be given a private
CA, so `load.js` skips checking the gateway's certificate, while the gateway still
checks the operator's. A client on the host needs the same: the `operator`
certificate and key, `ca.crt`, and `gateway` as the host name, since that is the
name in the gateway's certificate.

`demo.sh` is idempotent. It cleans up any replacement containers, restores the
original policy, rebuilds the root, resets the mode to `enforce`, and runs these,
printing `payment`'s trace line for scenario 1:

| # | Scenario | Expected |
|---|---|---|
| 1 | client → gateway → orders → payment | 200 |
| 2 | search calls payment with no headers | 403 `CHAIN_MISSING` |
| 3 | search forges a stamp claiming to be gateway | 403 `BAD_SIGNATURE` |
| 4 | search extends a real `gateway→search` chain to payment with its own stamp | 403 `PATH_NOT_ALLOWED` |
| 5 | a captured valid request is replayed | 403 `REPLAY` |
| 6 | valid chain, body altered after the last stamp | 403 `BINDING_MISMATCH` |
| 7 | a chain older than the max age | 403 `EXPIRED` |
| 8 | scenarios 2–4 in `audit` mode | 200, events logged, no quarantine |
| 9 | three illicit calls from search in `enforce` | search isolated; a fresh search serves `gateway→search` |
| 9b | another round past the per-service limit | responder logs `ESCALATE` |
| 10 | add `[gateway, search, payment]`, rebuild root | scenario 4 now returns 200: policy drives behaviour |

The attacks run inside the mesh, from `search`'s `/attack/*` endpoints (enabled
only when `ATTACK_MODE=true`), so every one reaches `payment` over `search`'s own
TLS connection, presenting `search`'s certificate. Only the gateway port is
exposed to the host.

## Configuration

| Variable | Default | Used by |
|---|---|---|
| `PAZTPORT_MODE` | `enforce` | `payment` (`off`, `audit`, `enforce`) |
| `PAZTPORT_MAX_AGE_MS` | `5000` | `payment`: both freshness windows, the last stamp's and the origin's. The callers' response checks use the same property, `paztport.max-age-ms`, with the same default |
| `PAZTPORT_ORIGINS` | `gateway` | `payment`. The callers' response checks use the same property, `paztport.origins`, with the same default |
| `PAZTPORT_PROOF_DEPTH` | `8` | policy-tool |
| `ATTACK_MODE` | `false` | search |
| `PAZTPORT_ADMIN_TOKEN` | empty, so `/admin/mode` refuses every request | `payment` (the demo generates one per run) |
| `PAZTPORT_CAPTURE` | `false`; `true` for `payment` in Compose | `payment` (the replay harness) |
| `RESPONDER_URL` | empty, so events are only logged | `payment` (the demo sets `https://responder:8080` for scenario 9) |
| `PAZTPORT_EVENT_KEY_PATH` | `/config/keys/payment.key` in Compose; required when `RESPONDER_URL` is set | `payment` |
| `PAZTPORT_KEY_PATH` | `/config/keys/<svc>.key` in `gateway`'s and `orders`' `application.yml`; Compose sets it for `payment` and `search` | the four services; `payment`'s attests its responses |
| `PAZTPORT_PROOFS_PATH` | `/config/policy/proofs-<svc>.json` in `gateway`'s and `orders`' `application.yml`; Compose sets it for `search` | `gateway`, `orders`, `search` |
| `PAZTPORT_KEYRING_PATH` | `/config/keys/keyring.json` in every `application.yml` but `search`'s; Compose sets it for `search` | the four services (requests at `payment`, responses at the callers), responder (event signatures) |
| `PAZTPORT_ROOT_PATH` | `/config/policy/root.json` in every service's `application.yml` but `search`'s; Compose sets it for `search` | the four services |
| `PAZTPORT_POLICY_KEY_PATH` | `/config/keys/policy.pub` in `gateway`'s and `orders`' `application.yml`; Compose sets it for `payment` and `search` | the four services: the pin the keyring and the root must verify under |
| `RESPONDER_ALLOWED_SIGNERS` | `payment` | responder |
| `QUARANTINE_THRESHOLD` | `3` | responder |
| `QUARANTINE_MAX_PER_SVC` | `2` | responder (the demo uses `1` so `ESCALATE` comes sooner) |

The TLS files are not variables: each service's `application.yml` names its
certificate, its key and `ca.crt` under `/config/tls/` as the Spring Boot SSL bundle
`mesh`, which it serves with (`client-auth: need`) and presents on its calls
(`paztport.tls-bundle: mesh`). The origin's window can be set apart from the last
stamp's with the property `paztport.run-max-age-ms`; unset, both are
`PAZTPORT_MAX_AGE_MS`.
