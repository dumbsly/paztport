# Envoy Gateway proof of concept

Paztport at an [Envoy Gateway](https://gateway.envoyproxy.io) edge on a local [kind](https://kind.sigs.k8s.io)
cluster. A Go `ext_proc` processor stamps each request as the origin service `edge`, and the
[java-mesh](../java-mesh/README.md) services `orders` and `payment` verify it. The idea and the concepts are in the
[root README](../../README.md).

This is the proof of concept, its behavioural checks, and the harness for its measurements (see
[Measuring it](#measuring-it)). Most of the measurements, and their write-up, are not here yet.

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
was made with; run `down` first to make it again. Every `kubectl` and `helm` call names the cluster's own context, so no
other cluster is touched.

## Measuring it

```bash
./run envoy-gateway measure            # every suite
./run envoy-gateway measure load       # the suites named
./run envoy-gateway measure --keep     # and leave the cluster up afterwards
```

does the same builds, and makes new keys and a new policy, then runs `measure.sh` on a cluster of its own: it refuses
to run while `paztport-envoy-gateway` exists, makes it with `envoy-gateway.sh up`, and adds an upstream that does as
little as it can, `echo` (`processor/cmd/echo`, from the image `paztport-echo:dev`, the processor's `Dockerfile`'s
target `echo`), with two twin routes to it on the Gateway's one listener (`kind/measure.yaml`). The processor is
attached to `echo` (host `echo.example`), which its chart maps to the receiver `orders`, and never to `echo-plain`
(host `echo-plain.example`); one BackendTrafficPolicy gives both the same request buffer and retries as
`orders-routes`. So a run on each, alternated, measures what the processor adds to plain Envoy. `echo` counts the
requests it is sent per host, with and without an `X-Path-Chain` header, so a suite can show that no request on
`echo` reached it unstamped.

Each suite starts from the same baseline, and prints it: two processor replicas with the autoscaler off, `orders` and
`payment` in enforce mode with no environment variable `kind/backends.yaml` does not set, only the routes `orders`,
`orders-unmapped`, `echo` and `echo-plain` and their BackendTrafficPolicies, no delay added to any pod's network, the processor's EnvoyExtensionPolicy failing closed (`failOpen` false; the run stops if it is not), and every pod's keys and policy those in `out/` (the run stops if they are not). Load comes from k6
(`measure/k6/edge.js`, `grafana/k6:2.2.0` by digest) in a Job in the cluster, which counts every response by its
status, a reset or a timeout included, and, for every response that was not the status expected, counts it in the
second of the run it came back in and keeps the time of the first and the last (it also lists up to 20000 of them
with their times). A comparison
runs a discarded warm-up of each side, then rounds of one run each, the side that goes first alternating, and prints
every run, the median of each side's runs with their lowest and highest, and the difference.

| Suite | What it measures |
|---|---|
| `load` | the latency the processor adds: plain Envoy (`echo-plain`) against Envoy and the processor (`echo`) at the same offered rate, well below either one's ceiling (`LOAD_RATE_SMALL`, 1000 requests a second, with a 400-byte body; `LOAD_RATE_LARGE`, 500, with a 256 KiB one), each run saying whether k6 kept to that rate; first, from Envoy's own configuration (its admin `/config_dump`), that the twins share one listener's filter chain and differ only in the processor's filter being enabled on `echo`; last, that `echo` was sent no request unstamped and `echo-plain` none stamped |
| `ceiling` | what the processor sustains, against plain Envoy: with one, two and four processor replicas (`helm upgrade`, the autoscaler off), `CEILING_ROUNDS` (3) rounds of stages of rising offered rate on `echo` and the same stages on `echo-plain`, the one that leads alternating, each stage a run at its own constant rate with the small body, in a table of offered and achieved rate, p50, p99, dropped and statuses. A stage is sustained when no request was dropped, it achieved within 2% of its offered rate, and every response was a 200; k6 holds the offered rate x 0.1 s users, all started before the run, so a drop (marked in the table) means the system held the requests that long on average, not that k6 was short of users. Each round's highest sustained stage is printed, then their median with the lowest and highest, which is written to `ceiling-sustained` in the run's directory (`<route> <replicas> <median>` a line, under a comment saying so) for later suites to read; where `echo`'s median equals `echo-plain`'s, it says the ramps carry no information about the processor there. Then, on one replica, 1.5 and 2 times its median (saturation): statuses, the window of responses other than 200, what the processor decided, what Envoy counted of its streams to the processor, and its restarts; and memory: 1 MiB bodies (the body limit) from 10, 25, 50 and 100 users, with the processor's peak resident memory (read from its `/metrics` a little over a second apart) and its restarts and how it last ended, an OOM kill included. Last, as `load` does, that `echo` was sent no request unstamped |
| `edge` | the whole edge: `orders` and `payment` with Paztport installed (the route `orders`, stamped by the processor, both backends in enforce mode with the Spring starter) against the same images without it (the starter's auto-configuration excluded through `SPRING_AUTOCONFIGURE_EXCLUDE`, `orders` given Spring Boot's own mutual TLS client to `payment` through `SPRING_HTTP_CLIENTS_SSL_BUNDLE=mesh`, and the requests on `orders-plain`, a twin of `orders` the processor is not attached to, from `kind/orders-plain.yaml`), alternated at `EDGE_RATE` (500 requests a second), each switch a change to the Deployments' environment, a rollout and a discarded warm-up of `EDGE_WARMUP` (30s); first the exact list of what differs, and, from Envoy's routes, that the processor's filter is enabled on `orders` and not on `orders-plain`; then each run, the medians, spread and what Paztport adds. `orders-plain` exists only while this runs: it is deleted (on any exit too) and shown gone from the cluster and from Envoy's routes. Then the route `orders` past what it sustains (`EDGE_STAGES`), and one overload stage (`EDGE_OVERLOAD_RATE`, 3000) from as many k6 users as its pod holds, with what Envoy refused (its circuit breakers, for the processor's cluster and for the cluster of `orders`), what the processor decided, every reason other than OK that `orders` and `payment` counted, by name, their restarts, and, from the longest request, whether a stamp could have been older than `orders`' `maxAgeMs` at all |
| `failure` | the edge under steady load while the processor fails, five cases, each one k6 run at a constant offered rate with the fault 10 s into it: on `echo`, at `FAILURE_RATE` (unset: half the two-replica median the `ceiling` suite measured on `echo` in the same run, or else `FAILURE_DEFAULT_RATE`, 5000 requests a second), one processor container killed (SIGKILL, from the kind node), and the time until both replicas are ready again; one processor pod slowed by 600 ms with `tc netem` in its network namespace, first only the packets from its gRPC port for 60 s (its `/readyz` still answering, shown), then the whole pod, until readiness takes it out, and whether the errors stop; every processor replica gone (`replicas=0`) for 30 s, that every response meanwhile was refused with a 5xx, and the time to the first 200 once two are back; and `kubectl rollout restart` of the processor. Then on the route `orders`, at `FAILURE_ORDERS_RATE` (750), one `orders` container killed: the requests that failed, what Envoy retried (the routes retry a connection that failed, never a request `orders` may have received), and from `orders`' traces that it served each rid once. Each case prints its run, its responses other than 200 by status with the first and the last, a timeline of the fault's events beside them and each second's count, what each processor pod decided, what Envoy counted of its streams to the processor (its circuit breaker's own 500s apart), and that nothing reached `echo` unstamped. Every fault is undone on any exit |

`ROUNDS` (3), `DURATION` (20s), `WARMUP` (10s), `VUS` (10), `LOAD_RATE_SMALL` and `LOAD_RATE_LARGE` set the runs;
`CEILING_STAGES_1`, `CEILING_STAGES_2` and `CEILING_STAGES_4` (each a list of rates), `CEILING_ROUNDS` (3),
`SATURATION_DURATION` (60s) and `MEMORY_VUS` (`10 25 50 100`) set `ceiling`'s; `EDGE_RATE`, `EDGE_WARMUP`,
`EDGE_STAGES` and `EDGE_OVERLOAD_RATE` set `edge`'s; `FAILURE_RATE`, `FAILURE_DEFAULT_RATE` and `FAILURE_ORDERS_RATE` set `failure`'s. Everything printed, each run's
responses other than the expected, and the Envoy configuration read go to `out/measurements/<UTC time>/`. Every
number is indicative: one kind node on one machine runs Envoy, the processor, the backends and k6 alike, and each
run prints the machine's CPUs and memory. The cluster is deleted at the end, unless `--keep`. `./run envoy-gateway
measure` needs `python3` (3.9 or later) as well as the tools below.

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
| `processor/cmd/echo` | the measurements' upstream: answers 200 and counts each host's requests with and without a stamp; the image's target `echo` |
| `envoy-gateway.sh` | `up`, `check` and `down`: the cluster, the checks, and its removal |
| `measure.sh`, `measure/` | the measurements: `common.sh` (k6 runs, alternation, the baseline), a file for each group of suites, k6's script (`k6/edge.js`) and `summary.py` (medians, spread and error windows) |
| `lib.sh` | what `envoy-gateway.sh` and `measure.sh` share |
| `kind/` | the cluster (`cluster.yaml`), the Gateway as an existing cluster would have it (`gateway.yaml`), `orders` and `payment` (`backends.yaml`), their routes (`routes.yaml`), the pod the checks send requests from (`checks.yaml`), what the measurements add (`measure.yaml`), and the route the `edge` suite makes for its baseline and then deletes (`orders-plain.yaml`) |
| `chart/` | the Helm chart: everything Paztport adds to a cluster that already runs Envoy Gateway |

`material.sh` refuses to write over an existing `out/`; `--fresh` makes everything again. `PAZTPORT_POLICY_DAYS` sets
how long the keyring and the policy root last (default 7 days).

## The processor

The processor serves Envoy's `ext_proc` service over gRPC with mutual TLS, TLS 1.3 only. It requires a client
certificate that chains to the client CA, is no CA itself, names client authentication among its key usages, and
whose subject is the common name `edge` alone; any other client's connection is refused in the handshake, so
nothing it sends reaches the processor. Metrics, readiness and liveness are on a separate port, over plain HTTP,
never on the gRPC port. It reads its configuration and every file once, at start: new material, routes or
certificates take a pod roll.

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
is attached to but does not map, and their BackendTrafficPolicy `orders-routes`, as a cluster's operator would have
one. It retries only a connection that failed or a stream refused, where `orders` never saw the request, and it
carries the edge's body limit as the routes' request buffer limit (`requestBuffer.limit`): `envoy-gateway.sh` writes
into it the one number, `BODY_LIMIT`, that it also passes the chart as `bodyLimit`. Since Envoy Gateway attaches one
BackendTrafficPolicy to a route, the chart is installed with `backendTrafficPolicy=false`.

Every hop is mutual TLS on every path, so the backends' probes only open a TCP connection, and the checks read their
metrics with the operator's client certificate. Their Services are named exactly `orders`, `payment` and
`paztport-processor`: each certificate carries the one DNS name of its service. Three settings matter on the
backends:

- `SERVER_FORWARDHEADERSSTRATEGY=NONE`. On Kubernetes, Spring Boot otherwise trusts `X-Forwarded-For` from any private
  address, and the peer's instance that a refusal's event names would be whatever the client put there (check 10).
- `MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE=health,prometheus`, for `/actuator/prometheus`.
- On `payment`, Actuator's SSL metrics and SSL health check are left out: they read every SSL bundle's files (the
  metrics at start, the health check at each `/actuator/health`, which it would answer `DOWN`), and `payment` also
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
  enabled; on AKS, Azure Network Policy Manager, Cilium or Calico). With merged gateways Envoy Gateway gives Envoy's
  pods the GatewayClass's label (`gateway.envoyproxy.io/owning-gatewayclass`) and not the Gateway's, so the policy
  admits nothing and the edge refuses every request until `gateway.envoyPodLabels` names that label instead. The
  admin port (`/metrics`, `/readyz` and `/livez`, read only) is open to every pod by default; in production set
  `adminFrom` to the Prometheus namespace;
- a BackendTrafficPolicy on the same routes, and on no other, that sets their request buffer's limit
  (`requestBuffer.limit`) to `bodyLimit`, the processor's own body limit. Envoy buffers a request's whole body before
  the processor stamps it; the request buffer is a filter Envoy runs ahead of the processor's, and refuses a longer
  body with 413. Envoy Gateway attaches one BackendTrafficPolicy to a route: of two on the same route the older is
  attached, and the newer is not accepted for it (its `Accepted` condition is `False`, reason `Conflicted`). So when
  the routes already have one, set `backendTrafficPolicy: false` and give that one `requestBuffer.limit` equal to
  `bodyLimit`, as `kind/routes.yaml` does. A route with no request buffer has only its listener's buffer, 32 KiB
  unless a ClientTrafficPolicy raises it: a longer body is refused with 413, never passed on unstamped. The chart's
  policy sets `mergeType` from `backendTrafficPolicyMergeType`, `StrategicMerge` by default: it merges into a
  BackendTrafficPolicy on the routes' Gateway or listener, so the routes keep that policy's rate limits, timeouts,
  retries and circuit breakers and gain the request buffer, and Envoy Gateway marks that policy `Merged`. With the
  value empty, a route-level policy replaces the Gateway's on its routes, which then lose its settings, and Envoy
  Gateway marks the Gateway's policy `Overridden`;
- the edge's key and the processor's TLS key as Secrets, and the public material, the routes and the mesh CA as
  ConfigMaps. Values may name existing Secrets and the CA's ConfigMap instead, for a cluster that manages them
  elsewhere; `envoy-gateway.sh` does, so that no private key goes through Helm's values. A checksum annotation rolls
  the pods when the chart's material or routes change, or, at a `helm install` or `helm upgrade`, when an existing
  Secret or ConfigMap the values name has changed; a change to one of those alone rolls nothing until then. The
  processor reads its certificate once, at start, so a Secret that cert-manager renews must roll the pods before the
  old certificate expires, or every request is refused (500) from then: run `helm upgrade`, or give
  `podAnnotations` a reloader's annotation (Stakater Reloader's `reloader.stakater.com/auto: "true"`, for one).

Envoy's own client certificate is not the chart's: it is the EnvoyProxy's `backendTLS.clientCertificateRef`, a
setting of the Gateway's, as `kind/gateway.yaml` shows. Envoy Gateway v1.9.2 has that one upstream client
certificate for each Gateway, presented on every upstream connection with a BackendTLSPolicy: a Gateway that already
presents another one to its backends cannot present the edge's as well, and a backend that trusts the edge's
certificate trusts every route on that Gateway.

The chart's EnvoyExtensionPolicy targets the routes, and Envoy Gateway lets a policy on a route replace, for that
route, an EnvoyExtensionPolicy on its Gateway or listener: an operator's Gateway-wide Wasm, Lua, dynamic module or
ext_proc filter stops running on every Paztport route, and Envoy Gateway marks that Gateway-wide policy
`Overridden`. `mergeType` (`StrategicMerge` or `JSONMerge`) merges the chart's policy into such a policy instead,
keeping its Wasm, Lua and dynamic modules. A Gateway-wide ext_proc is still replaced on these routes: the merge
covers the whole policy, `extProc` is a list with no merge key, and the chart sets it. Operators should alert on an
EnvoyExtensionPolicy or a BackendTrafficPolicy with `Overridden` true, and check each policy on every ancestor (each
Gateway its routes attach to), not only the first. A policy that merges also lists, as one more ancestor, the
listener whose policy it merged into, with `Merged` true and no `Accepted` condition. Neither policy merges in this
demo, so `envoy-gateway.sh up` waits for the chart's policy, and for the routes' BackendTrafficPolicy, to be accepted
on every ancestor and overridden on none; a wait for a merging policy must accept `Merged` on that listener ancestor.

A route to a Paztport backend goes into the chart's values (`routes`, or `extraRoutes` until it is mapped) before
the route itself is applied, so that Envoy never serves it without the processor; `envoy-gateway.sh` installs the
chart, then applies `kind/routes.yaml`. Removal is the other way round: a Paztport route comes off the Gateway before
it leaves `routes`, and the chart is never uninstalled (`helm uninstall`) while such a route is attached.

`values.yaml` describes each value. `routes`, `gateway.name` and `image.tag` have no default, and the chart refuses to
install without them; `envoy-gateway.sh` passes them with `--set`. Pod placement (`nodeSelector`, `tolerations`,
`affinity`, `topologySpreadConstraints`, `priorityClassName`), `imagePullSecrets` and `podAnnotations` are set only
when given; with autoscaling off and one replica, the PodDisruptionBudget's `minAvailable: 1` blocks node drains.
`ci/lint-values.yaml` and `ci/placed-values.yaml` hold placeholders for `helm lint` and `helm template`: the first
with the chart's own BackendTrafficPolicy, the second without it and with every optional value set.

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
| 11 | a body one byte over the limit is refused with Envoy's own 413 by the routes' request buffer, whose limit is the processor's; the processor is sent only that reply, which it passes on, and decides nothing; the request never reaches `orders` |
| 12 | a body longer than the listener's own 32 KiB buffer, and no longer than the limit, is stamped and verified at `orders` (200): the request buffer's limit is in force on the route |

Each check was seen to fail with the setting it guards taken away: the processor detached from the routes (1, 3, 5,
9; with it detached, a fresh stamp taken from the processor and sent through Envoy is served, since Envoy presents
the edge's certificate), `orders-unmapped` mapped (5), the NetworkPolicy deleted (6), mode overrides refused (9) or
response headers not sent (4), `PAZTPORT_VERIFY` unset on `orders` (2, 7, 10), the Prometheus endpoint not exposed
(8), `SERVER_FORWARDHEADERSSTRATEGY` unset, when the event names `203.0.113.9` (10), a processor that answered
Envoy's 413 with its own 500 (11), and the request buffer taken off the routes' BackendTrafficPolicy (12, refused
413 by the listener's buffer; and 11, where the processor, awaiting the body, then counts the request
`refused_body`).

## What the cluster showed

- Envoy Gateway sends the route metadata as one line of protobuf text, ending in a space, with the policies attached
  to the route (here the BackendTrafficPolicy) listed before the route's own resources; the processor's parser takes
  it as it is (`processor/internal/routes/testdata/route-metadata.captured.txtpb`, as captured).
- A body over the limit is refused with 413, and never reaches `orders`. The route's request buffer, a filter Envoy
  Gateway places ahead of `ext_proc`, holds the request until its body is whole, and refuses it once the body passes
  the limit: Envoy then opens a stream to the processor with that reply's headers alone, which the processor passes
  on, deciding and counting nothing, since it never had the request. On a route with no request buffer, the
  listener's buffer refuses the body instead while the processor awaits it, and the processor counts the request
  `refused_body`. Envoy sends the processor its own replies before the stamp in the same way when any filter ahead
  of `ext_proc` refuses a request; each is passed on, never replaced.
- Containment needs every route to a Paztport backend to pass the processor. Envoy presents the edge's certificate
  on every upstream with a BackendTLSPolicy, so on a route without the processor a stamp the client holds is accepted
  as the edge's (seen with the policy detached: a stamp taken from the processor was served). Each such route must be
  in `routes` or `extraRoutes` before it is attached to the Gateway. The chart's EnvoyExtensionPolicy must be the only
  one on it: Envoy Gateway attaches the oldest and marks others Conflicted, and a policy on a rule of the route
  overrides it (see the chart, above, for one on the Gateway). No route may point at the processor's Service.
  Whoever can attach routes to the Gateway is inside the edge's trust. `envoy-gateway.sh up` waits for the policy to
  be accepted on every ancestor and overridden on none.
- Of two BackendTrafficPolicies on the same route, the newer is not accepted for it: with the chart's own made after
  `orders-routes`, the chart's reported `Accepted` `False`, reason `Conflicted` ("another BackendTrafficPolicy has
  already attached to it").
- `payment`'s `/actuator/health` answered `DOWN` (503) with Actuator's SSL health check on, since the PSP's bundle is
  not mounted, and `UP` with it off.
- Envoy Gateway replaces a client's `x-request-id` with its own.

## Dependency notes

- `golang.org/x/net` is at v0.61.0, which has two OSV advisories, both in `x/net/html`; the processor does not compile
  that package. Move to v0.62.0 on or after 2026-11-10, when it has been released two weeks.
- java-mesh's services run on `eclipse-temurin:25.0.4.1_1-jre`, pinned by digest in `../java-mesh/Dockerfile`,
  which predates the October 2026 Java critical patch update. Move to a 25.0.5 image once one has been pushed two
  weeks: `25.0.5_8-jre` was first pushed on 2026-10-29, so on or after 2026-11-12.
