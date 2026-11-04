# Envoy Gateway proof of concept

Paztport at an [Envoy Gateway](https://gateway.envoyproxy.io) edge on a local [kind](https://kind.sigs.k8s.io)
cluster. A Go `ext_proc` processor stamps each request as the origin service `edge`, and the
[java-mesh](../java-mesh/README.md) services `orders` and `payment` verify it. The idea and the concepts are in the
[root README](../../README.md).

This is the proof of concept and its behavioural checks. The load, failure, route-change and rotation measurements,
and the full write-up, are not here yet.

## Running it

```bash
./run envoy-gateway
```

builds the Java SDK and `orders` and `payment`, makes new keys and a new signed policy into `out/` (replacing an
earlier run's, which expire), builds the three images and loads them into a kind cluster named
`paztport-envoy-gateway`, installs Envoy Gateway, the Gateway, the processor's chart, the backends and their routes,
and runs the checks. It takes a few minutes; nothing is pushed to any registry. The cluster stays up for inspection,
under the kubectl context `kind-paztport-envoy-gateway`:

```bash
poc-demos/envoy-gateway/envoy-gateway.sh check   # run the checks again
poc-demos/envoy-gateway/envoy-gateway.sh down    # delete the cluster
```

`./run envoy-gateway` and `envoy-gateway.sh up` refuse to run while the cluster exists, since it holds the keys it
was made with; `down` first makes it again. Every `kubectl` and `helm` call names the cluster's own context, so no
other cluster is touched.

## Prerequisites

`./run envoy-gateway` checks these first and stops with a `missing:` line for the first one that is not there:

| Tool | At least | Why |
|---|---|---|
| Java and Maven | 25 | build the SDK, and run the key and policy tools |
| Docker | 24 | build the images, and run the kind node |
| Go | the SDK's `go` line | build `edgecheck`, the checks' client (the processor's image builds in Docker) |
| kind | 0.33 | the local cluster |
| kubectl | 1.35 (supported range 1.35 to 1.37) | drive the cluster; Kubernetes supports kubectl within one minor version of the API server, and the node image is 1.36 |
| Helm | 4.2 | install Envoy Gateway and the processor's chart; the lowest Helm release whose [version-skew table](https://helm.sh/docs/topics/version_skew/) lists Kubernetes 1.36 |

macOS and Linux; on Windows use WSL.

## Layout

| Path | What it is |
|---|---|
| `paths.yaml` | the routes the policy allows: `edge → orders` and `edge → orders → payment` |
| `material.sh` | makes the keys and the signed policy into `out/`, standing in for CI |
| `out/` | what `material.sh` wrote; holds private keys and is not committed |
| `processor/` | the Go `ext_proc` processor: `internal/routes` names each request's receiver from its HTTPRoute, `internal/material` loads and checks the edge's keys and policy, `internal/edge` stamps each request or refuses it, `internal/server` serves it, and `cmd/processor` runs it |
| `processor/Dockerfile` | the processor's image: a static binary on distroless, as nonroot, with its licences in `/licenses/` |
| `processor/THIRD-PARTY.txt` | every module the processor's binary is built from, each with its licence, and every licence file within those modules over code the binary holds; `processor/third-party.sh` checks it and gathers the licence texts into the image |
| `processor/cmd/edgecheck` | a client the checks use for the two requests curl cannot make; not in the image |
| `envoy-gateway.sh` | `up`, `check` and `down`: the cluster, the checks, and its removal |
| `kind/` | the cluster (`cluster.yaml`), the Gateway as an existing cluster would have it (`gateway.yaml`), `orders` and `payment` (`backends.yaml`), their routes (`routes.yaml`), and the pod the checks send requests from (`checks.yaml`) |
| `chart/` | the Helm chart: everything Paztport adds to a cluster that already runs Envoy Gateway |

`material.sh` refuses to write over an existing `out/`; `--fresh` makes everything again. `PAZTPORT_POLICY_DAYS` sets
how long the keyring and the policy root last (default 7 days).

## The processor

The processor serves Envoy's `ext_proc` service over gRPC with mutual TLS, TLS 1.3 only. It requires a client
certificate that chains to the client CA, is no CA itself, names client authentication among its key usages, and
whose subject is the common name `edge` alone; any other client's connection is refused in the handshake, so nothing it sends reaches the processor. Metrics, readiness and liveness
are on a separate port, over plain HTTP, never on the gRPC port. It reads its configuration and every file once, at
start: new material, routes or certificates take a pod roll.

| Variable | Default | What it is |
|---|---|---|
| `PROCESSOR_LISTEN` | `:9002` | the gRPC port's address |
| `PROCESSOR_ADMIN_LISTEN` | `:9090` | the admin port's address: `/metrics`, `/readyz`, `/livez` |
| `PROCESSOR_TLS_CERT`, `PROCESSOR_TLS_KEY` | | the processor's server certificate and its key, in PEM |
| `PROCESSOR_CLIENT_CA` | | the CA the edge's client certificate must chain to, in PEM |
| `PROCESSOR_KEY` | | the edge's private key, `edge.key` |
| `PROCESSOR_PIN` | | the pinned policy key, `policy.pub` |
| `PROCESSOR_KEYRINGS`, `PROCESSOR_ROOTS` | | the keyring and root files, each a comma-separated list, so an old and a new one can overlap |
| `PROCESSOR_BUNDLE` | | the edge's proof bundle, `proofs-edge.json` |
| `PROCESSOR_ROUTES` | | the routes file: one `<namespace>/<httproute>=<receiver>` a line |
| `PROCESSOR_BODY_LIMIT` | | the most bytes of body the edge stamps, from 1 to 1 GiB; a longer body is refused with 413 |
| `POD_NAME` | | the instance the edge's stamps name, from the downward API |

Every variable without a default is required; the processor stops at start, with one log line naming the fault, on
a missing setting or on material that would not stamp what the routes promise. `/readyz` answers 503 once the
material has expired (the processor then refuses every request) and while it shuts down; `/livez` answers 200.

| Metric | Type | What it counts |
|---|---|---|
| `paztport_edge_requests_total{outcome}` | counter | each request the edge decided: `stamped`, `refused_route`, `refused_material`, `refused_body` or `refused_error` |
| `paztport_edge_stamp_seconds` | histogram | how long stamping each stamped request took |
| `paztport_edge_body_bytes` | histogram | the size of each decided request's body |
| `paztport_edge_material_seconds_left` | gauge | how long the material stays ready; below zero once it has expired |

The Go runtime's and the process's own metrics are there too. The processor logs JSON on standard output: one line a
request, with its `outcome`, the `rid` of its stamp when it was stamped, and Envoy's `x-request-id` as
`x_request_id`; Envoy Gateway's Envoy makes its own for every request, replacing any a client sends, so a client
cannot choose the one logged. It never logs a body, a Paztport header, any other header the client sent, or a key.

The image builds from the repository's root, locally, and is never pushed:

```bash
docker build -f poc-demos/envoy-gateway/processor/Dockerfile -t paztport-processor:dev .
```

## The cluster

Each version is pinned: kind 0.33 with the node image `kindest/node:v1.36.4` by digest, Envoy Gateway v1.9.2 from its
Helm chart (its controller's image by digest, and Gateway API v1.6.1, which the chart installs), Envoy
`distroless-v1.39.1` by digest (in the EnvoyProxy), and the checks' `curlimages/curl:8.22.0` by digest. kind's own
network plugin enforces NetworkPolicy, so no other is installed.

Envoy Gateway runs in `envoy-gateway-system`; everything else is in the namespace `paztport`. `kind/gateway.yaml` is
the part a cluster that already runs Envoy Gateway would have: the GatewayClass, the Gateway `edge` (one HTTP
listener), and the EnvoyProxy, which gives Envoy its upstream client certificate, the edge's (CN `edge`, from the
mesh CA). Envoy Gateway presents that one certificate on every upstream connection that has a BackendTLSPolicy, to
the processor and to `orders` alike. `kind/backends.yaml` runs java-mesh's `orders` (two replicas) and `payment` as
they are, verifying every request in enforce mode with `edge` as the one origin, each with its own keys and
certificate mounted at the paths java-mesh uses. `kind/routes.yaml` holds two HTTPRoutes to `orders`: `orders`,
which the processor maps to the receiver `orders`, and `orders-unmapped` (host `unmapped.example`), which the processor
is attached to but does not map. Retries on those routes are only for a connection that failed or a stream refused,
where `orders` never saw the request.

Every hop is mutual TLS on every path, so the backends' probes only open a TCP connection, and the checks read their
metrics with the operator's client certificate. Their Services are named exactly `orders`, `payment` and
`paztport-processor`: each certificate carries the one DNS name of its service. Three settings matter on the
backends:

- `SERVER_FORWARDHEADERSSTRATEGY=NONE`. On Kubernetes, Spring Boot otherwise trusts `X-Forwarded-For` from any private
  address, and the peer's instance that a refusal's event names would be whatever the client put there (check 10).
- `MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,prometheus`, for `/actuator/prometheus`.
- On `payment`, Actuator's SSL metrics are left out: they read every SSL bundle's files at start, and `payment` also
  defines one for the PSP, which this proof of concept leaves out.

## The chart

`chart/` attaches the processor to an existing Gateway's HTTPRoutes in the release's namespace. It makes the
processor's Deployment (with a PodDisruptionBudget, a HorizontalPodAutoscaler on CPU, which needs metrics-server
and otherwise keeps its minimum, resource requests and limits, and a `preStop` pause before the processor drains),
its Service, and:

- an EnvoyExtensionPolicy on the routes in `routes` and `extraRoutes`: `failOpen: false`, a `messageTimeout`
  (500 ms by default), request bodies `Buffered`, the `xds.route_metadata` attribute, response headers sent and
  response bodies not, and mode overrides allowed, so that the processor can ask for a request's trailers. It sets no
  header mutation rules;
- a BackendTLSPolicy, so that Envoy checks the processor's certificate against the mesh CA;
- a NetworkPolicy that admits the Gateway's Envoy pods, by Envoy Gateway's labels, and no other pod to the gRPC port.
  It needs a network plugin that enforces NetworkPolicy (kind's does; on EKS, the VPC CNI with network policy
  enabled). With merged gateways Envoy Gateway does not give Envoy's pods the owning-gateway labels, so the policy then
  admits nothing and the edge refuses every request. The admin port (`/metrics`, `/readyz` and `/livez`, read only) is
  open to every pod by default; in production set `adminFrom` to the Prometheus namespace;
- a ClientTrafficPolicy on the Gateway that sets the listener's buffer limit to `bodyLimit`, the processor's own body
  limit: Envoy Gateway v1.9 has no body limit per route, so the limit is the listener's, for every route on it. A
  Gateway can have one ClientTrafficPolicy only; when it has one, set `clientTrafficPolicy: false` and give that one
  the same `connection.bufferLimit`;
- the edge's key and the processor's TLS key as Secrets, and the public material, the routes and the mesh CA as
  ConfigMaps. Values may name existing Secrets and the CA's ConfigMap instead, for a cluster that manages them
  elsewhere; `envoy-gateway.sh` does, so that no private key goes through Helm's values. A checksum annotation rolls
  the pods when the chart's material or routes change, or, at a `helm install` or `helm upgrade`, when an existing
  Secret or ConfigMap the values name has changed; a change to one of those alone rolls nothing until then.

Envoy's own client certificate is not the chart's: it is the EnvoyProxy's `backendTLS.clientCertificateRef`, a
setting of the Gateway's, as `kind/gateway.yaml` shows. A route to a Paztport backend goes into the chart's values
(`routes`, or `extraRoutes` until it is mapped) before the route itself is applied, so that Envoy never serves it
without the processor; `envoy-gateway.sh` installs the chart, then applies `kind/routes.yaml`. `values.yaml`
describes each value; `ci/lint-values.yaml` holds placeholders for `helm lint` and `helm template`.

## The checks

`envoy-gateway.sh check` sends its requests from the pod `checks` in the namespace `paztport` (curl, holding the
operator's and `payment`'s client certificates), or, for the two requests curl cannot make, from `edgecheck` on this
machine through `kubectl port-forward`. Each check prints what it saw: status codes, the `rid`s, and the lines
`orders`, `payment` and the processor logged. It never prints a stamp.

| Check | What it shows |
|---|---|
| 1 | `POST /orders` through the Gateway is answered 200; the processor stamped it, and `orders` and then `payment` verified it: their trace lines carry the stamp's `rid` with `reason=OK`, `orders`' with `peer=edge (mTLS)` |
| 2 | the same request sent straight to `orders`, with the operator's certificate and no chain, is refused `403 CHAIN_MISSING` |
| 3 | a client that sends a real `X-Path-Chain` and `X-Path-Proof` (check 7's), and another `X-Path-` header, through the Gateway is answered 200, and the stamp `orders` verified has a `rid` of the edge's, not the one the client sent |
| 4 | the responses from the Gateway in checks 1 and 3 carry no `X-Path-` header, although `orders` attests each response with one |
| 5 | a request on `orders-unmapped` is refused by the processor with its own 403, and `orders` logs nothing |
| 6 | the pod `checks` cannot open a connection to the processor's gRPC port, though its admin port answers, and a client certificate for `orders` is refused in the processor's handshake |
| 7 | a stamp taken from the processor (with the edge's certificate, as Envoy) and sent to `orders` from a pod presenting `payment`'s certificate is refused `403 PEER_MISMATCH`: a stolen stamp is good only on Envoy's own connections |
| 8 | `orders`' and `payment`'s `/actuator/prometheus` count the requests they served as verified in enforce mode, and the processor's `/metrics` the requests it stamped |
| 9 | an HTTP/2 request of headers and trailers, with no body, is refused by the processor with its own 500, and never reaches `orders` |
| 10 | a refused request sent with `X-Forwarded-For: 203.0.113.9` has its event name the pod's own address as the peer's instance |
| 11 | a body one byte over the limit is refused with Envoy's own 413, which the processor passes on (counted `refused_body`), and never reaches `orders` |

Each check was seen to fail with the setting it guards taken away: the processor detached from the routes (1, 3, 5,
9; with it detached, a fresh stamp taken from the processor and sent through Envoy is served, since Envoy presents
the edge's certificate), `orders-unmapped` mapped (5), the NetworkPolicy deleted (6), mode overrides refused (9) or
response headers not sent (4), `PAZTPORT_VERIFY` unset on `orders` (2, 7, 10), the Prometheus endpoint not exposed
(8), `SERVER_FORWARDHEADERSSTRATEGY` unset, when the event names `203.0.113.9` (10), and a processor that answered
Envoy's 413 with its own 500 (11).

## What the cluster showed

- Envoy Gateway sends the route metadata as one line of protobuf text, ending in a space, with the policies attached
  to the route (here the BackendTrafficPolicy) listed before the route's own resources; the processor's parser takes
  it as it is (`processor/internal/routes/testdata/route-metadata.captured.txtpb`, with the policy's name masked).
- A body over the limit is refused with 413, and never reaches `orders`. Envoy answers it itself, before the
  processor has the body, and sends that reply's headers to the processor, which passes them on (and counts the
  request `refused_body`). Envoy sends the processor its own replies before the stamp in the same way when a filter
  ahead of `ext_proc` refuses a request; each is passed on, never replaced.
- Containment needs every route to a Paztport backend to pass the processor. Envoy presents the edge's certificate
  on every upstream with a BackendTLSPolicy, so on a route without the processor a stamp the client holds is accepted
  as the edge's (seen with the policy detached: a stamp taken from the processor was served). Each such route must be
  in `routes` or `extraRoutes` before it is attached to the Gateway. The chart's EnvoyExtensionPolicy must be the only
  one on it: Envoy Gateway attaches the oldest and marks others Conflicted, and a policy on a rule of the route
  overrides it. No route may point at the processor's Service. Whoever can attach routes to the Gateway is inside the
  edge's trust. `envoy-gateway.sh up` waits for the policy to be accepted.
- Envoy Gateway replaces a client's `x-request-id` with its own.
