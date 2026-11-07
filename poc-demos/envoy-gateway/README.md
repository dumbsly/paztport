# Envoy Gateway proof of concept

Paztport at an [Envoy Gateway](https://gateway.envoyproxy.io) edge on a local [kind](https://kind.sigs.k8s.io)
cluster. A Go `ext_proc` processor stamps each request as the origin service `edge`, and the
[java-mesh](../java-mesh/README.md) services `orders` and `payment` verify it. The idea and the concepts are in the
[root README](../../README.md).

This is the proof of concept, its behavioural checks, the harness for its measurements (see
[Measuring it](#measuring-it)), and what one full run of them showed: the answers first, then the
[findings](#findings), the [gotchas](#gotchas-and-how-each-is-handled), [how to operate it](#operating-it), its
[limits](#limits), and the [measurements](#measurements) themselves.

## What the measurements showed

The answers to the nine questions this proof of concept was built to ask, for someone deciding whether to put Paztport
at their edge. The numbers are from one full run of `./run envoy-gateway measure` on 2026-11-07 (its results directory
`20261107T141511Z`), on an Apple M5 Pro Mac (the model is the host's; the run prints only its Docker Desktop VM's 18
CPUs and 19.5 GiB of memory), and every one of them is indicative. One kind node runs Envoy, the processor, the backends
and k6 together, so a ceiling here is the node's as much as any one part's. The run used Envoy Gateway v1.10.0, Envoy
v1.40.2, Kubernetes 1.37.0 on the kind node, k6 2.3.0 and a Temurin 25.0.5_8 JRE for `orders` and `payment`. Where a
number comes from another run, for a case this one did not measure, its sentence says which run. Where a measurement
was repeated, its median comes first and the lowest and highest after it, in brackets; every other number is from a
single run. The tables are under [Measurements](#measurements).

1. **Load: does the edge become the bottleneck?** At 1000 requests a second the processor adds 0.35 ms at p50 and
   0.56 ms at p99. One replica on this node saturates between 8000 and 10000/s, its tail latency growing from 6000/s.
   Two replicas sustained what plain Envoy did, and four one step less. Why one replica saturates there is not
   measured: no suite read the processor's CPU.
   - At 1000 requests a second with a 400-byte body, the processor adds 0.35 ms at p50 (one round's +0.27 to +0.37)
     and 0.56 ms at p99 (+0.54 to +0.56) to plain Envoy on the same listener. With a 256 KiB body at 500/s it adds
     0.49 ms and 1.37 ms: the cost of buffering the body and sending it to the processor. Stamping itself (hashing
     the body and signing) took 27 µs at p50 and 96 µs at p99.
   - The whole edge, `orders` calling `payment` at 500/s, answers 3.19 ms later at p50 (+3.12 to +3.21) and 2.87 ms
     at p99 (+2.82 to +2.87) with Paztport installed than without. That is every hop's work: the edge stamping, both
     backends verifying, `orders` stamping its call and both attesting their responses.
   - One processor replica (one CPU) met the ramps' test for sustained up to 10000/s in all three rounds, but its p50
     rose from 0.84 ms at 6000/s to 1.35 ms at 7000/s, 6.60 ms at 8000/s and 24.79 ms at 10000/s (the first round;
     p99 25 ms already at 6000/s), while plain Envoy's stayed near 0.2 ms on the same stages. Past 10000/s, Envoy's
     circuit breaker on the processor's cluster shed load (below). The two sides' medians were equal at one replica
     (10000/s), so the ramps alone say nothing about the processor there; the latency does.
   - Two replicas sustained 14000/s (10000-14000), as plain Envoy did (14000/s, 10000-14000), so there too the ramps
     show no cost. At four, 14000/s (12000-14000) against plain Envoy's 16000/s (14000-16000): the processor cost a
     step, within spreads that meet at 14000/s.
   - The route `orders` with Paztport sustained 2000/s (one ramp); at 3000/s it achieved 2494.9/s, with p50 195 ms.
   - Past saturation the edge refuses cleanly (one run each): one replica offered 15000/s and 20000/s answered 172975
     and 438456 requests with Envoy's own 500, every one refused by Envoy's circuit breaker on the processor's
     cluster, and none reached `echo` unstamped (see [Findings](#findings)).
   - Memory, the question whether 256Mi is enough with the 1 MiB body limit (one run): one replica's peak resident
     memory was 66.6, 97.1, 130.7 and 219.1 MiB with 10, 25, 50 and 100 clients each sending 1 MiB bodies back to
     back, every response a 200 and no restart. It grows by about 1.7 MiB a body in flight, so by that rate 256Mi
     holds about 120 concurrent 1 MiB bodies a replica (an estimate: the steps end at 100). A route that expects
     more raises `resources.limits.memory` or lowers `bodyLimit`.
2. **Failure modes, replicas and load balancing.** At 7000/s on `echo` (half the two-replica median), with two
   replicas, one run a case:
   - one processor container killed: 2186 requests refused with 500, all within 0.44 s, both replicas ready again
     2.50 s after the kill, nothing unstamped;
   - a `kubectl rollout restart` of the processor: no error in 630001 requests;
   - one replica slowed by 600 ms on its gRPC port alone: it stayed ready (19 of 19 probes), Envoy's health check took
     it out 2.45 s later, and the errors stopped 2.83 s after the delay: 4081 504s at the `messageTimeout` and 8 500s
     from Envoy's circuit breaker (see [Findings](#findings));
   - the same replica then slowed as a whole pod: readiness took it out 1.69 s later; no request failed from Envoy's
     health check's reading on, nor after the pod was ready again, and its container was not restarted (a longer
     delay can restart it; see [Findings](#findings));
   - every replica gone for 30 s: every response a 5xx while none existed (209999), the first 200 to a probe 0.92 s
     after two replicas were asked for, and 4200 requests reached `echo` unstamped as they came back: Envoy
     Gateway's recovery leak (see [Findings](#findings)). With `routingType: Service`, 0;
   - one `orders` container killed at 1000/s: 15 requests answered 503 within 0.31 s, Envoy made 356 retries after 364
     failed connections, and `orders` served each of 89987 stamps once.

   Envoy balances across the processor's pods itself: 50.0% and 50.0% of 140001 requests. The chart runs two to
   four replicas (an autoscaler on CPU) with a PodDisruptionBudget of one.
3. **Set-up.** One Helm chart on a cluster that already runs Envoy Gateway, plus two things a Gateway's owner sets:
   the edge's client certificate in the EnvoyProxy, and a BackendTLSPolicy for each Paztport backend. `./run
   envoy-gateway` needs no step by hand. What is not like any other workload is in [The chart](#the-chart): Envoy
   Gateway attaches one BackendTrafficPolicy and one EnvoyExtensionPolicy to a route and overrides a Gateway-wide
   one; a route goes into the chart's values before it is applied; merged gateways need `gateway.envoyPodLabels`;
   and a renewed certificate needs a pod roll.
4. **Is a central Paztport server needed?** No. The policy is signed offline (here by `material.sh`, standing for
   CI with the policy key in an HSM) and shipped as Secrets and ConfigMaps; the processor and the backends read
   files at start and check every stamp locally. No suite needed a runtime service, and a route change is a signing
   event.
5. **Adding or changing a route,** under 1000/s on `orders`, one run a step:
   - a new URL on an existing service (a second HTTPRoute to `orders`): the processor's mapping changes and its pods
     roll, then the route is applied. No error in 90001 requests on `orders`, and none in 3801 on the new route;
   - a new service path, `edge/payment`, with `payment` exposed at the edge: a rebuilt policy, rolled out in three
     overlap steps, refused no request for its material. The same change the old way, every holder's root replaced
     at once, had `orders` refuse 3776 requests `PATH_NOT_ALLOWED`. The rollouts' own errors are counted apart (see
     [Measurements](#route)).
6. **Rollout safety.** In production every valid path is signed before release, and a service goes straight to
   `enforce`; `audit` is a tool for before production, for finding the paths a system takes. So the suite measured
   the production order, at 1000/s on a route of its own, one run a step: the processor's pods mapped the route, then
   the processor attached to it, then `orders` and then `payment` rolled straight into `enforce`.
   - Mapping rolled the processor's pods with no error in 90001 requests, and Envoy started no stream to the
     processor, since the route was not yet attached.
   - Attaching cost no error either: each of Envoy's 79820 streams to the processor was decided by its pods, which
     already mapped the route, and none was refused. Mapping and attaching in one release, as the earlier run
     `20261105T192122Z` did on Envoy Gateway v1.9.2, cost 2663 403s in 3.37 s (see [Findings](#findings)).
   - Rolling the backends into `enforce` cost 199 of 150001 requests, every one a 500, during and after the rollouts;
     none was refused `EXPIRED`, and no request reached a backend running Paztport without a stamp.
   - Then a request straight to `orders`, past the Gateway, was refused `403 CHAIN_MISSING`.
7. **Observability.** The processor's `/metrics` counts what it decided, how long stamping took, the bodies' sizes and
   how long its material has left (6.9 days in the run); the backends count each request by mode, outcome and
   reason. A scan of 29942 lines the processor logged found none of a body marker, a header marker, a stamp's
   `X-Path-` values, any `X-Path-` header name or the edge's key in five encodings. Envoy's 67777 lines (its access
   log included), `orders`' 565141 and `payment`'s 29961 held none of them either.
8. **Key custody, and who can reach the processor.** The edge's private key is a Secret only the processor mounts.
   The processor's gRPC port takes mutual TLS from a client certificate named `edge` and nothing else, and the
   NetworkPolicy admits only the Gateway's Envoy pods to it (check 6): the processor signs for whoever reaches it.
   Even so, a stamp taken from it is refused `PEER_MISMATCH` from any connection but Envoy's (check 7). Anyone who can
   read the Secret or mount it in a pod is the edge, as for any service ([limits of the
   concept](../../README.md#52-limits-of-the-concept)).

   The edge's key was rotated at 1000/s in three overlap steps, one run each, and no request was refused for the
   key. The first step, `orders` and `payment` rolled together onto both keyrings, cost 428 non-200s (189 500s and
   239 503s). The processor's step cost no error. The last, the two backends rolled together onto the new keyring
   alone, cost 5504 of 150000, with about 5 s in which every request failed: Envoy's circuit breaker on the
   processor's cluster refused 4439 of them, and `orders` refused 212 `EXPIRED` (`payment` 78). Both backend steps
   rolled the same two Deployments, and the run does not say why the last cost so much more. Read it as the cost of
   rolling the backends under load, not of the key; not measured (see [Measurements](#rotation)).
9. **Upgrades.** See [Why ext_proc now, and a dynamic module later](#why-ext_proc-now-and-a-dynamic-module-later).

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
poc-demos/envoy-gateway/measure.sh --reuse route   # again, on the cluster a --keep run left up
```

does the same builds, and makes new keys and a new policy, then runs `measure.sh` on a cluster of its own: it refuses to
run while `paztport-envoy-gateway` exists, makes it with `envoy-gateway.sh up`, and adds an upstream that does as little
as it can, `echo` (`processor/cmd/echo`, from the image `paztport-echo:dev`, the processor's `Dockerfile`'s target
`echo`), with two twin routes to it on the Gateway's one listener (`kind/measure.yaml`). The processor is attached to
`echo` (host `echo.example`), which its chart maps to the receiver `orders`, and never to `echo-plain` (host
`echo-plain.example`); one BackendTrafficPolicy gives both the same request buffer and retries as `orders-routes`. So a
run on each, alternated, measures what the processor adds to plain Envoy. `echo` counts the requests it is sent per
host, with and without an `X-Path-Chain` header, so a suite can show that no request on `echo` reached it unstamped.
`measure.sh --reuse` runs suites again on the cluster a `--keep` run left up, making nothing (it refuses unless that
cluster exists, and leaves it up), with a results directory of its own, so that one run's material never meets
another's, and starts `echo` again, so that its counts are that run's own (`./run envoy-gateway measure`, which makes a
cluster of its own, refuses `--reuse`); the policy tool the `route` and `rotation` suites run is on `PAZTPORT_JAVA`
(`./run` passes the JDK Maven uses), or `java` on the PATH.

Each suite starts from the same baseline, and prints it: two processor replicas with the autoscaler off, `orders` and
`payment` in enforce mode with no environment variable `kind/backends.yaml` does not set, only the routes `orders`,
`orders-unmapped`, `echo` and `echo-plain`, their BackendTrafficPolicies and the BackendTLSPolicies of `orders` and
the processor, no delay added to any pod's network, Envoy
routing to endpoints (a `routingType` a suite set is removed), the processor's EnvoyExtensionPolicy failing closed
(`failOpen` false; the run stops if it is not), and every pod's keys and policy those in `out/` (the run stops if they
are not). Load comes from k6 (`measure/k6/edge.js`, `grafana/k6:2.3.0` by digest) in a Job in the cluster, which counts
every response by its status, a reset or a timeout included, and, for every response that was not the status expected,
counts it in the second of the run it came back in and keeps the time of the first and the last (it also lists up to
20000 of them with their times). A comparison runs a discarded warm-up of each side, then rounds of one run each, the
side that goes first alternating, and prints every run, the median of each side's runs with their lowest and highest,
and the difference.

| Suite | What it measures |
|---|---|
| `load` | The latency the processor adds: plain Envoy (`echo-plain`) against Envoy and the processor (`echo`), alternated at the same offered rate, well below either one's ceiling (`LOAD_RATE_SMALL`, 1000/s with a 400-byte body; `LOAD_RATE_LARGE`, 500/s with a 256 KiB one), once Envoy's own configuration shows that the twins differ only in the processor's filter. See `measure/load.sh`. |
| `ceiling` | What one, two and four processor replicas sustain on `echo` against `echo-plain`, over `CEILING_ROUNDS` (3) ramps of constant-rate stages, a stage sustained when no request was dropped, it came within 2% of its rate and every response was a 200; then one replica past that (saturation), and its memory with 1 MiB bodies. See `measure/load.sh`. |
| `edge` | The whole edge, `orders` and `payment` with Paztport installed against the same images without it (the starter excluded, on the route `orders-plain`), alternated at `EDGE_RATE` (500/s), each switch a rollout; then the route `orders` ramped past what it sustains (`EDGE_STAGES`), and overloaded at `EDGE_OVERLOAD_RATE` (3000/s) from 6000 k6 users (the rate × 2 s) in a 4Gi pod. See `measure/load.sh`. |
| `failure` | The edge under steady load while the processor fails, one constant-rate run a case with the fault 10 s into it: on `echo` at `FAILURE_RATE`, a processor container killed, a replica slowed on its gRPC port and then as a whole pod, every replica gone (Envoy routing to the pods, then to the Service), and the processor rolled; then, on `orders` at `FAILURE_ORDERS_RATE`, an `orders` container killed. See `measure/failure.sh`. |
| `gotchas` | Two routes an operator could add that undo what the stamp is for: a `URLRewrite` applied after the processor stamped the path, refused `BINDING_MISMATCH`; and a retry on 5xx, with `payment` scaled to 0, which sends `orders` the same stamp again (the finding, per rid). See `measure/rollout.sh`. |
| `observe` | What the processor and the backends count of a steady run on `orders` at `CHANGE_RATE`; then a scan of every line the processor logged for a request's markers, a stamp's values and the edge's key, with what Envoy's and the backends' logs hold of them as findings. See `measure/rollout.sh`. |
| `rollout` | Paztport adopted under load in the order production takes, on a route of its own (`orders-adopt`): the processor mapped, then attached, then `orders` and `payment` rolled straight into enforce; then a request straight to `orders`, past the Gateway, refused `CHAIN_MISSING`. See `measure/rollout.sh`. |
| `route` | Route changes under steady load on `orders` at `CHANGE_RATE`: a new URL on `orders` (`orders-shop`), then a new service path, `edge/payment`, on a rebuilt policy, rolled out in three overlap steps and then the old way, side by side; each step's traces show whether any request reached a backend without a stamp. See `measure/change.sh`. |
| `rotation` | The edge's key rotated (`policy-tool --rotate edge`) under the same load, in three overlap steps; then a stamp under the new key accepted while the backends' keyring is still the old, and one under the old refused once it is unpinned. See `measure/change.sh`. |

Each suite undoes what it changed on any exit while the cluster is kept. `route` and `rotation` make their material
with the policy tool in the run's own `measurements/<UTC time>/material/<suite>/`, from a copy of `out/keys`' policy
key and keyring, show that `out/keys` and `out/policy` are unchanged, and remove the copy's private keys when they
end.

`ROUNDS` (3), `DURATION` (20s), `WARMUP` (10s), `LOAD_RATE_SMALL` and `LOAD_RATE_LARGE` set the runs;
`CEILING_STAGES_1`, `CEILING_STAGES_2` and `CEILING_STAGES_4` (each a list of rates), `CEILING_ROUNDS` (3),
`SATURATION_DURATION` (60s) and `MEMORY_VUS` (`10 25 50 100`) set `ceiling`'s; `EDGE_RATE`, `EDGE_WARMUP`, `EDGE_STAGES`
and `EDGE_OVERLOAD_RATE` set `edge`'s; `CHANGE_NEW_RATE` (50) is the rate on a route `route` and `rotation` add.
`FAILURE_RATE`, the rate on `echo` of `failure`, is unset by default: half the two-replica median `ceiling` measured on
`echo` in the same run, or else `FAILURE_DEFAULT_RATE` (5000). `FAILURE_ORDERS_RATE` and `CHANGE_RATE`, the rates on
`orders` of `failure` and of `route`, `rotation`, `rollout` and `observe`, are unset by default: half the highest stage
`edge` sustained on `orders` in the same run, or else `ORDERS_DEFAULT_RATE` (1000), a fallback measured on the author's
machine. Each suite prints which rate it used.

Everything printed, each run's responses other than the expected, and the Envoy configuration read go to
`measurements/<UTC time>/`, beside `out/` and not in it: `out/` is material, which each `./run envoy-gateway measure`
makes again (`material.sh --fresh`), while a run's results cannot be made again, so nothing deletes them but the private
keys of the material copies; they are not committed. Every number is indicative: one kind node on one machine runs
Envoy, the processor, the backends and k6 alike, and each run prints the machine's CPUs and memory. The cluster is
deleted at the end, unless `--keep`. `./run envoy-gateway measure` needs `python3` (3.9 or later) as well as the tools
below.

On macOS a run holds `caffeinate -i` so that the host does not sleep under it, and every k6 run is held to its time: its
summary must come within its length, k6's 15 s `gracefulStop` and 10 s more of its start, or the run fails, naming a
stalled or sleeping host. A run that must keep its rate is held to that as well, within 2% with no request dropped: the
alternated rounds of `load` and `edge`, the cases of `failure` and its runs on how the load spreads, the steps of
`route`, `rotation` and `rollout` and their new routes' runs, and `observe`'s steady run. A ceiling, saturation, ramp or
overload stage is not, since falling short of its rate is what it measures, nor is a discarded warm-up. Each suite ends
with one line on its runs' pace, and fails with it.

## Prerequisites

`./run envoy-gateway` checks these first and stops with a `missing:` line for the first one that is not there:

| Tool | At least | Why |
|---|---|---|
| Java and Maven | 25 | build the SDK, and run the key and policy tools |
| Docker | 24 | build the images, and run the kind node |
| Go | the SDK's `go` line | build `edgecheck`, the checks' client (the processor's image builds in Docker) |
| kind | 0.33 | the local cluster |
| kubectl | 1.36 (supported range 1.36 to 1.38) | drive the cluster; Kubernetes supports kubectl within one minor version of the API server, and the node image is 1.37 |
| Helm | 4.3 | install Envoy Gateway and the processor's chart; the lowest Helm release whose [version-skew table](https://helm.sh/docs/topics/version_skew/) lists Kubernetes 1.37 |

macOS and Linux; on Windows use WSL.

## Layout

| Path | What it is |
|---|---|
| `paths.yaml` | the routes the policy allows: `edge → orders` and `edge → orders → payment` |
| `material.sh` | makes the keys and the signed policy into `out/`, standing in for CI |
| `out/` | what `material.sh` wrote; holds private keys and is not committed |
| `measurements/` | each measurement run's results, one directory a run, kept from run to run; of the material `route` and `rotation` make, only the public files are kept, as their private keys are removed when the suite ends; not committed |
| `processor/` | the Go `ext_proc` processor: `internal/routes` names each request's receiver from its HTTPRoute, `internal/material` loads and checks the edge's keys and policy, `internal/edge` stamps each request or refuses it, `internal/server` serves it, and `cmd/processor` runs it |
| `processor/Dockerfile` | the processor's image: a static binary on distroless, as nonroot, with its licences in `/licenses/`; and `echo`'s, the standard library alone, with the repository's licence and Go's |
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
| `paztport_edge_requests_total{outcome}` | counter | each request, by how it ended: `stamped`, `refused_route`, `refused_material`, `refused_body`, `refused_error` or `abandoned` (its stream ended before the edge decided it: Envoy stopped waiting, or the client or the body never finished). `stamped` counts requests the edge stamped and answered, not requests delivered: Envoy may still give up before a late answer arrives, which its `message_timeouts` counts |
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

Each version is pinned: kind 0.33 with the node image `kindest/node:v1.37.0` by digest, Envoy Gateway v1.10.0 from its
Helm chart (its controller's image by digest, and Gateway API v1.6.1, which the chart installs), Envoy
`distroless-v1.40.2` by digest (in the EnvoyProxy), and the checks' `curlimages/curl:8.23.0` by digest. kind's own
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

- an EnvoyExtensionPolicy on the routes in `routes` not set `attach: false`, and those in `extraRoutes`:
  `failOpen: false`, a `messageTimeout` (500 ms by default), request bodies `Buffered`, the `xds.route_metadata`
  attribute, response headers sent and response bodies not, and mode overrides allowed, so that the processor can ask
  for a request's trailers. It sets no header mutation rules. It also has Envoy check each processor replica
  actively, with the standard gRPC health check on the gRPC port (the whole server, answering as `/readyz` does),
  over the same mutual TLS as the requests: Kubernetes readiness cannot see a replica that is slow only on Envoy's
  path to it, since the kubelet cannot present Envoy's certificate. The check's timeout follows `messageTimeout`, it
  runs every second, and two failures in a row leave the replica out of Envoy's endpoints (`healthCheck` in the
  values). If every replica fails, Envoy's panic threshold has it send to all of them again;
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
setting of the Gateway's, as `kind/gateway.yaml` shows. For the shape this proof of concept uses, a Service backendRef
with a BackendTLSPolicy, Envoy Gateway v1.10.0 has that one upstream client certificate for each Gateway, presented on
every upstream connection that has a BackendTLSPolicy: a Gateway that already presents another one to its backends
cannot present the edge's as well, and a backend that trusts the edge's certificate trusts every route on that Gateway.

For production, consider Envoy Gateway v1.10.0's `Backend` resource, which this proof of concept neither uses nor tests.
A Backend can name its own TLS client certificate (`spec.tls.clientCertificateRef`, a Secret in the Backend's namespace;
without one it falls back to the EnvoyProxy's), and its `type: KubernetesService`, new in v1.10.0, routes to a Service
in the same namespace. The certificate follows the Backend, not the route. A deployment could then present the edge's
certificate only where a backendRef names such a Backend: each Paztport route's, and the EnvoyExtensionPolicy's to the
processor (which takes a Backend too, with an IP or FQDN endpoint, and needs the edge's certificate). The chart would
own it, rather than the Gateway's EnvoyProxy, and take the edge's certificate from the same issuer as every service's,
each workload with its own identity: cert-manager writes it to a Secret that every Envoy replica presents, or, with
SPIRE, each replica fetches its own over SDS (Envoy Gateway's [Backend Mutual TLS with
SPIRE](https://gateway.envoyproxy.io/v1.10/tasks/security/backend-mtls-spire/) task, behind
`extensionApis.enableSDSSecretRef`). A SPIFFE identity names the Envoy pods' service account, so the backends' peer
check would have to map it to the edge's name. The Backend resource needs Envoy Gateway's `extensionApis.enableBackend`,
a setting of the Envoy Gateway controller, not of a Gateway, which the cluster's operator owns. Envoy Gateway's [Backend
task](https://gateway.envoyproxy.io/v1.10/tasks/traffic/backend/) warns that the Backend API can be misused to reach
destinations that are otherwise restricted, which is why it is off by default, and advises restricting access to it with
Kubernetes RBAC: read it before enabling the setting.

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

A route that Envoy already serves is adopted in two releases, not one. The first adds it to `routes` with
`attach: false`: the processor's routes file maps it and its pods roll, and the processor is not yet attached to the
route, so the route's requests are untouched. Once the new pods are ready, the second release removes the
`attach: false` line; that attaches the processor and rolls nothing. `attach: false` is only for a route Envoy serves
without the processor. A route not yet served goes in with `attach` true, as above, since with `attach: false` Envoy
would serve it without the processor once applied. On a route the processor is attached to, `attach: false` detaches it
in place, and Envoy then serves the route without the processor: the backends' own checks (a backend in `enforce`
refusing CHAIN_MISSING) are what is left. The reason for two releases is that attaching and mapping in one release
makes the old pods, which do not map the route, refuse its requests (403) until the new pods take its streams.

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
  it as it is (`processor/internal/routes/testdata/route-metadata.captured.txtpb`, as captured under Envoy Gateway
  v1.9.2; the processor reads v1.10.0's the same way).
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
  in `routes` with `attach` true, or in `extraRoutes`, before it is attached to the Gateway. The chart's
  EnvoyExtensionPolicy must be the only one on it: Envoy Gateway attaches the oldest and marks others Conflicted, and
  a policy on a rule of the route overrides it (see the chart, above, for one on the Gateway). No route may point at
  the processor's Service. Whoever can attach routes to the Gateway is inside the edge's trust. `envoy-gateway.sh up`
  waits for the policy to be accepted on every ancestor and overridden on none.
- Of two BackendTrafficPolicies on the same route, the newer is not accepted for it: with the chart's own made after
  `orders-routes`, the chart's reported `Accepted` `False`, reason `Conflicted` ("another BackendTrafficPolicy has
  already attached to it").
- `payment`'s `/actuator/health` answered `DOWN` (503) with Actuator's SSL health check on, since the PSP's bundle is
  not mounted, and `UP` with it off.
- Envoy Gateway replaces a client's `x-request-id` with its own.

## Findings

What the checks and the measurements found, beyond the numbers.

- **The peer check contains a stolen stamp.** A backend requires the mutual TLS peer to be the stamp's last signer,
  the edge. The processor holds the edge's signing key and Envoy holds the edge's TLS client key, in different pods,
  so a stamp taken from a compromised processor is useless without Envoy's key: check 7 sends one from a pod holding
  `payment`'s certificate, and `orders` refuses it `PEER_MISMATCH`.
- **Replay protection is per replica.** Each backend replica keeps its nonce cache in memory. Across replicas only the
  peer check confines a replay, to the edge's own connections, so a request the edge sends twice can be served twice. A
  route that retries on 5xx does exactly that. With `payment` scaled to 0, so that `orders` answers 500, each of 50
  requests on such a route was verified and served by one `orders` replica, retried and served again by the other, and
  refused `REPLAY` only on the third try, back at a replica that had seen the stamp (Envoy counted 100 retries). Every
  client got 403 in the end, but had `payment` been up, it would have been called twice for one order. Hence the rule:
  a Paztport route retries only what never reached the backend (`connect-failure`, `refused-stream`), as
  `orders-routes` does. On it, 50 such requests were each served once, Envoy retrying none, and with an `orders`
  container killed under load, Envoy made 356 retries after 364 failed connections, and every stamp was served once. A
  request the edge sends twice is duplicate delivery, which the backend's application handles by idempotency keyed on
  the delivery (the verified chain's `rid` and last signer, with the last stamp's `bind` to tell a different request
  under a reused key). A shared, expiring nonce store across replicas is optional hardening: it holds a compromised
  caller to one call per request tree whatever the replica count, but it does not make a retry safe, as the retry is
  then refused `REPLAY`.
- **No central server is needed:** see the fourth answer above.
- **Spring Boot trusts `X-Forwarded-For` on Kubernetes.** Boot turns on Tomcat's `RemoteIpValve` when it detects
  Kubernetes, so the peer's instance a refusal's event names would come from a header the client sent. The backends
  set `SERVER_FORWARDHEADERSSTRATEGY=NONE`, and check 10 shows why.
- **Containment:** every route to a Paztport backend must pass the processor; see
  [What the cluster showed](#what-the-cluster-showed).
- **Envoy Gateway leaks on recovery from no ready processor.** While the processor has no ready pod, Envoy Gateway marks
  its EnvoyExtensionPolicy `Accepted False`, turns the routes into a direct 500 and removes the `ext_proc` filter from
  the listener. Every request then is refused, so it fails closed while down. But when the processor comes back, Envoy
  Gateway restores the filter on a new listener, and the old one's filter chain drains: each kept-alive client
  connection can pass one more request on it, without the processor and so unstamped. That is a reading the count fits
  rather than something the run shows directly: 4200 requests reached `echo` unstamped, all after the processor was
  asked back, against k6's 4200 users, each with a connection of its own; none while the processor was going and none
  while it was gone. The backends in `enforce` refuse such a request (`CHAIN_MISSING`), so it never reaches the
  application; the count is taken on `echo` because `echo` verifies nothing. The mitigation is the EnvoyProxy's
  `spec.routingType: Service`: Envoy then routes to the processor's Service, Envoy Gateway keeps the policy accepted and
  the filter in place, and 0 reached `echo` unstamped. Envoy refused every request itself, failing closed: over the
  case, 172465 500s, most of them (`cluster_rq_pending_overflow` +167584) from its circuit breaker once 1024 waited on
  connections that could not open, and 66199 504s at the `messageTimeout`. It costs a slower recovery, the first 200 to
  a probe 2.51 s after two replicas were asked for against 0.92 s, and the last error 3.63 s after against 0.73 s, and
  Envoy no longer balances across the processor's pods itself: kube-proxy balances its few long-lived HTTP/2
  connections, which in the run split 58.3% and 41.7%, and nothing keeps them even. It is also Gateway-wide, for every
  route. The default, routing to endpoints, leaks; `failure` reports it as a FAIL, and the run exits 1 for it.
- **Envoy's circuit breaker on the processor's cluster sheds load.** The processor's cluster sets no limit of its own
  (only `max_retries`, in Envoy's configuration as the run read it), so Envoy's default of 1024 requests at a time
  applies, and the chart leaves it. Past it Envoy refuses with its own 500 (`cluster_rq_active_overflow`), failing
  closed. Measured: one replica offered 15000/s refused 172975 that way while stamping every request that came back 200;
  on `orders` at 3000/s Envoy refused 9598 of 60001 while the processors stamped only 50403 in 20 s, about 2500 a
  second, far under what two replicas sustained on `echo`; and three steps that rolled the backends under load counted
  4439 (rotation's last), 3818 (`route`'s last overlap step) and 1592 (its old way). A reading of the `orders` case, not
  measured: Envoy holds a request's stream to the processor open until the response's headers, since the filter is
  sent them, so a slow backend holds the processor's streams as well, and enough of them in flight fill the 1024 while
  the processor itself is idle. The run does not give the number in flight: at the accepted rate, the p50 of 350 ms
  gives about 880 and the p90 of 596 ms about 1500.
- **A replica slow on its gRPC port is invisible to readiness.** A replica slowed by 600 ms on port 9002 alone kept
  answering `/readyz` (19 of 19 probes) and stayed ready. Readiness cannot see such a replica: the gRPC port takes only
  mutual TLS with Envoy's certificate, which the kubelet cannot present, so its probe never goes through that port.
  Passive outlier detection would not either: Envoy feeds it from the router, TCP proxy, Redis and Thrift filters, and
  ext_proc is none of them. So the chart has Envoy health-check each replica over the gRPC port, which takes a slow
  one out of its endpoints; that needs Envoy Gateway v1.10, since v1.9's health checks offered no ALPN and grpc-go
  refuses a TLS client that offers no `h2`. Without the check, in the earlier run `20261105T192122Z` on Envoy Gateway
  v1.9.2, such a replica stayed in Envoy's endpoints and cost 96750 504s. With it, the check read the replica failing
  2.45 s after the delay, and the errors stopped 2.83 s after it: 4081 504s, exactly Envoy's `message_timeouts`
  (+4081), and 8 500s from its circuit breaker. The slowed pod counted 3782 requests `abandoned`, so of the 4081
  requests Envoy gave up on, the pod stamped and answered 299 (4081 less 3782), the answer reaching Envoy after it had
  stopped waiting. Slowed then as a whole pod, it was taken out by readiness 1.69 s later; no request failed from the
  health check's reading on, nor after the pod was ready again, and its container was not restarted.
- **A whole pod slowed for 20 s or more can be restarted, and the restart is not drained.** The liveness probe
  (`/livez`, every 10 s, with Kubernetes' defaults of a 1 s timeout and three failures) fails every probe while the
  whole pod is slowed, and three failures need at least 20 s of delay. In a shorter run of `failure` on the same
  versions, with the hold at 20 s, the whole-pod delay held about 22 s (readiness took the pod out 2.23 s after it,
  then 20 s), and the container was restarted (restarts 1 before the case, 2 after). It last ended `Completed` about
  5 s after the delay was removed, which is the chart's `preStopSleepSeconds: 5`. The pod was Ready again 1.15 s after
  the removal, and about 4 s later came a burst of 363 500s within one second, the last as the container ended
  (`cluster_cx_connect_fail` +328 over the case). The earlier full run, `20261105T192122Z` on Envoy Gateway v1.9.2,
  showed the same: the container restarted once, and 456 500s 3 to 4 s after the pod was ready again. A liveness
  restart is not drained: the pod stays Ready through the `preStop` sleep, Envoy keeps sending, and when the process
  exits the streams on its connections fail closed as 500s. The suite now holds the delay to readiness's few seconds
  plus 10 s, so that the case shows the delay alone. Left for later: a liveness probe that catches only a wedged
  process, and a drain on a container restart.
- **Attaching the processor to a route already being served, in one release, costs a window of 403s.** In the earlier
  run `20261105T192122Z`, on Envoy Gateway v1.9.2, the chart mapped a route and attached its policy together. Envoy
  enabled the filter on the route as the policy changed, before the new processor pods, whose routes map it, took all
  of its streams; until then the old pods refused the route as unmapped. At 1000/s that was 2663 403s over 3.37 s, and
  Envoy's 79793 streams to the processor were exactly the new pods' 77130 stamps and those 403s. It fails closed. The
  chart now maps first: `attach: false` maps the route, and a second release attaches it (see
  [The chart](#the-chart)). This run measured that order: mapping cost no error and started no stream to the
  processor, and attaching cost none, each of Envoy's 79820 streams decided by pods that already mapped the route.
- **Mid-rollout responses go unattested, by design.** While `orders` enforced and `payment` did not yet run
  Paztport, `orders` counted 4078 `response checked CHAIN_MISSING` and still served the requests. A response is
  content, never refused; an unattested one is recorded as untrusted influence, which counts against later calls.
  These are not requests that reached a backend unstamped: the step's traces held no request refused
  `CHAIN_MISSING`.
- **A chainless request cannot be served on a multi-hop path, in `off` or `audit`.** A service that is not an origin,
  given a request with no chain, refuses to stamp its own outbound call. So with no processor in front and the
  backends in `off`, `orders` answered 500 rather than calling `payment`; that was seen in an earlier attempt at the
  `edge` suite's baseline, not in this run, and `audit` takes the same path in the code. The path is a later
  design: a chain starts only at an ingress or at an approved trigger (a service and one of its triggers, such as a
  scheduled job), and `audit`, which belongs before production, starts a chain where it serves a chainless request
  instead of sending its calls unstamped. The `edge` and `rollout` suites therefore compare against the backends
  without Paztport installed, not against `off`.
- **Rolling a backend under load costs errors.** Every step that rolled `orders` or `payment` at 1000/s cost from 190 to
  5504 non-200 responses apart from refusals for material, whatever the change. Three of them cost 190, 199 and 428
  (`route`'s first overlap step, `rollout`'s `enforce` step and rotation's first), every error a 500 but rotation's 239
  503s, with no `EXPIRED` and none from Envoy's circuit breaker. The other three cost 4526 (`route`'s last overlap
  step), 1994 (its old way) and 5504 (rotation's last, with about 5 s in which every request failed). Most of their
  500s were Envoy's circuit breaker on the processor's cluster (+3818, +1592 and +4439), and `orders` refused `EXPIRED`
  where requests waited past its 5 s (420, 149 and 212). Rotation's first and last steps both rolled `orders` and
  `payment` together, and the run does not say why the last cost so much more. Every step that rolled only the
  processor, on routes it already mapped, cost none. Read as the cost of this demo's backends' rollouts, and not
  measured: `payment` runs one replica here, and neither backend has a `preStop` pause or a readiness check beyond a
  TCP connection. That is not compared against a better-tuned Deployment. The windows below count these apart from
  refusals for material.

## Gotchas, and how each is handled

| Gotcha | What happens | Handled by |
|---|---|---|
| A `URLRewrite` on a Paztport route | the processor stamps the path the client sent, Envoy rewrites it after, and `orders` refuses `BINDING_MISMATCH` (10 of 10 in the run) | not rewriting paths on Paztport routes; it fails closed |
| A retry on 5xx | one stamp served once per replica, then `REPLAY` | retries confined to what never reached the backend (above) |
| A body over the limit | Envoy's 413 from the route's request buffer, never reaching `orders` (check 11) | the chart's or the route's `requestBuffer.limit` equal to `bodyLimit` |
| A client's own `X-Path-` headers | replaced by the edge's (check 3); none in a response (check 4) | the processor |
| Headers and trailers with no body | refused by the processor (check 9) | mode overrides allowed on the filter |
| A pod that is not Envoy, or a certificate other than `edge`, at the processor | refused by the NetworkPolicy or the handshake (check 6) | the chart |
| A stolen stamp | `PEER_MISMATCH` (check 7) | the peer check |
| A second BackendTrafficPolicy or EnvoyExtensionPolicy on a route, or one on the Gateway | `Conflicted`, or the Gateway's `Overridden` | `backendTrafficPolicy: false`, `mergeType`, and alerts (see [The chart](#the-chart)) |
| Merged gateways | the NetworkPolicy admits nothing, and the edge refuses everything | `gateway.envoyPodLabels` |
| Every processor replica gone | refused while down; one request a kept-alive connection unstamped on recovery | backends in `enforce`; `routingType: Service`; the PodDisruptionBudget and two replicas |
| More than 1024 requests in flight | Envoy's own 500 | capacity; it fails closed |
| A processor replica slow on its gRPC port | 504s at the `messageTimeout` for its share until Envoy's health check takes it out (4081 in the run, stopping 2.83 s after the delay) | the chart's health check (see [The chart](#the-chart)); an operator's alert on 504s and `message_timeouts` for the gap (see **A slow processor replica** under [Operating it](#operating-it)) |
| `X-Forwarded-For` | Boot would take the peer's instance from it | `SERVER_FORWARDHEADERSSTRATEGY=NONE` |

## Operating it

- **Adopting a route.** Material first, so the backends hold a policy that allows the route's paths. Then map the route,
  then attach the processor to it: add it to the chart's `routes` with `attach: false` (the processor's pods roll),
  and once they have, remove the `attach: false` line (nothing rolls). At 1000/s in the run, neither release cost an
  error. Mapping and attaching in one release, on a route already being served, cost 3.37 s of 403s at 1000/s in the
  earlier run `20261105T192122Z`, on Envoy Gateway v1.9.2. Then roll the backends straight into `enforce`, caller
  first, since a callee in `enforce` refuses every call its caller does not stamp yet: 199 errors of 150001, and no
  request reached a backend running Paztport unstamped. `audit` belongs before production, to find the paths a system
  takes and to check a release's policy against them.
- **A new route.** Into the chart's `routes` (the processor's pods roll), then the route applied; off the Gateway
  before it leaves `routes`.
- **A new service path.** Rebuild and sign the policy, then three steps: the backends pin the old root and the new
  one (`PAZTPORT_OVERLAP_ROOTPATHS`), callee first; the processor takes the new root and bundle and the mapping,
  then the route is applied; the old root is unpinned everywhere.
- **The edge's key.** `policy-tool --rotate edge`, then three steps: the backends pin both keyrings
  (`PAZTPORT_OVERLAP_KEYRINGPATHS`); the processor takes the new key and keyring; the old keyring is unpinned.
  Remove the old keyring before its `notAfter`: a processor refuses to start on a keyring past it, so a new pod (an
  autoscaler's, or a restart) would crash-loop. That rests on the processor's start-up check, which its unit tests
  show; the suites do not.
- **Certificates.** The processor reads its certificate once, at start, and a certificate's expiry is not part of its
  readiness: a renewed Secret needs a roll (`helm upgrade`, or a reloader's annotation in `podAnnotations`).
- **Policy status.** A merging policy lists its listener as one more ancestor, with `Merged` and no `Accepted`;
  anything that waits for `Accepted` on every ancestor must allow for it. Alert on `Overridden` and `Conflicted`.
- **Readiness.** `/readyz`, `paztport_edge_material_seconds_left` and each request's check take the material's one
  `notAfter`, which can overstate how long the edge's stamps will be accepted. It fails closed: past it the processor
  refuses every request, and a stamp a receiver no longer accepts is refused there.
- **A slow processor replica.** Until Envoy's health check takes it out (about `unhealthyThreshold` times `interval`,
  plus the check's timeout; 2.45 s in the run), its share of requests ends in 504s at the `messageTimeout`: alert on
  the 504s, and on the counter under **What to watch**.
- **What to watch.** `paztport_edge_requests_total` by outcome, `paztport_edge_material_seconds_left`, and, from
  Envoy, the processor's cluster: `streams_failed`, `message_timeouts` and `cluster_rq_active_overflow`; and the
  backends' reasons other than `OK`.

## Limits

- **The policy key's pin is single.** Rotating the policy key itself is not covered.
- **No identity in headers.** Nothing in this proof of concept carries who the client is; origin claims, committed in
  the origin stamp, are the path.
- **Streaming routes lose protection.** The processor stamps a whole buffered body, up to `bodyLimit`, so a route
  that streams its request cannot pass it, and cannot be a Paztport route.
- **A compromised Envoy has the origin's full authority.** It holds the edge's TLS key and can have any request
  stamped.
- **Replay protection is per replica,** above: a retry to another replica is served twice.
- **Envoy Gateway's default routing leaks on recovery,** above, until Envoy Gateway changes or `routingType: Service`
  is set.
- **Attaching to a served route in one release costs 403s,** above, as the earlier run `20261105T192122Z` measured on
  Envoy Gateway v1.9.2: the chart's `attach: false` maps a route first, the order this run measured, without an error.
- **One upstream client certificate for each Gateway,** with a Service backendRef and a BackendTLSPolicy, in Envoy
  Gateway v1.10.0 (see [The chart](#the-chart), which also names the `Backend` resource as a production consideration).
- **One machine, one node.** The ceilings are this node's, with Envoy, the processor, the backends and k6 sharing
  it; one run is not a spread across machines.

## The path

- **Origin claims**: identity committed in the origin stamp.
- **Origin-minted retries**: the origin signs a retry (same `rid`, a new attempt), which a replayer cannot forge.
- **A shared, expiring nonce store** across a backend's replicas, as optional hardening against a compromised caller.
- **A verifying front** and **partner entry** at the edge, and **client stamps**, a client signing its own requests
  (the DPoP and passkey shape).
- **Chains that start only at an ingress or an approved trigger,** with `audit` stamping (above).
- **`routingType: Service`, or a fix in Envoy Gateway,** for the leak on recovery.

## Why ext_proc now, and a dynamic module later

`ext_proc` keeps the processor a separate gRPC service on Envoy's stable `ext_proc` v3 API. It is built on the Go
SDK, and Envoy, Envoy Gateway and the processor upgrade apart: an Envoy Gateway upgrade rebuilds nothing of
Paztport's. It scales, fails and rolls as its own Deployment (a processor roll cost no error in the run), and its
signing key lives apart from Envoy's TLS key, which is what the peer check rests on. It costs a round trip to the
processor and the body copied to it, 0.35 ms at p50 with a small body and 0.49 ms with 256 KiB, and the failure modes
of a separate service, above.

A dynamic module runs in Envoy's process, and Envoy Gateway can attach one through the same EnvoyExtensionPolicy. It
would drop the round trip and the separate Deployment's failure modes. But it builds against Envoy's own interface,
so it is rebuilt for each Envoy minor version, and every Envoy Gateway upgrade carries a rebuild; its SDKs are still
young; and the edge's signing key would sit in Envoy's process beside its TLS key, so a compromise of either would be
a compromise of both. It is the later step, once its SDK has matured.

## What is kind-specific

- **One node.** Envoy, the processor (one CPU a pod), the backends, `echo` and k6 (two CPUs) share one node's CPUs,
  so the ceilings are the node's. A real cluster spreads them over nodes.
- **Images** are built locally and loaded into kind (`imagePullPolicy: Never`); a cluster pulls them from a registry,
  with `imagePullSecrets` if it needs them.
- **NetworkPolicy** is enforced by kind's own network plugin; on EKS or AKS it needs one that enforces it (see
  [The chart](#the-chart)).
- **The Gateway** has one HTTP listener behind a ClusterIP Service, reached from inside the cluster. A real one has
  an HTTPS listener behind a load balancer; the processor sees the same requests either way.
- **Keys, certificates and the policy** are made on this machine by `material.sh`, from a local mesh CA; a real
  deployment signs the policy in CI with an HSM-held key and takes certificates from its own CA.
- **No metrics-server**, so the autoscaler holds its minimum; the measurements set replicas with `helm upgrade`.
- **The measuring instruments** (`echo`, k6 in a Job, `tc netem` and `crictl` from the node, the node's log files) are
  not part of what a cluster would run.

The chart has nothing kind-specific. What `envoy-gateway.sh` passes it (the routes, the Gateway's name, the image's
tag, and the names of existing Secrets and a ConfigMap) a cluster's own values would.

## The processor in Envoy configured directly

Without Envoy Gateway, an operator writes what it generates. A sketch, not run in this repository: the filters on
the listener, the processor's cluster, and a route that names itself in the metadata the processor reads, in the
shape Envoy Gateway writes (`processor/internal/routes`). The processor's routes file then maps it,
`paztport/orders=orders`.

```yaml
http_filters:
  - name: envoy.filters.http.buffer             # the whole body first; a longer one is refused 413
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer
      max_request_bytes: 1048576                # the processor's PROCESSOR_BODY_LIMIT
  - name: envoy.filters.http.ext_proc
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor
      grpc_service:
        envoy_grpc: {cluster_name: paztport-processor}
        timeout: 10s
      failure_mode_allow: false                 # fail closed
      message_timeout: 0.5s
      allow_mode_override: true                 # the processor asks for a request's trailers
      request_attributes: [xds.route_metadata]
      processing_mode:
        request_header_mode: SEND
        request_body_mode: BUFFERED
        request_trailer_mode: SKIP
        response_header_mode: SEND              # so that it can remove every X-Path- header
        response_trailer_mode: SKIP
  - name: envoy.filters.http.router
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.router.v3.Router

# a route to orders, in its virtual host
- match: {prefix: /orders}
  route: {cluster: orders}                      # its upstream TLS presents the edge's client certificate
  metadata:
    filter_metadata:
      envoy-gateway:
        resources: [{kind: HTTPRoute, namespace: paztport, name: orders}]

# the processor's cluster: HTTP/2, mutual TLS with the edge's certificate, the processor's name checked
- name: paztport-processor
  type: STRICT_DNS
  load_assignment:
    cluster_name: paztport-processor
    endpoints:
      - lb_endpoints:
          - endpoint: {address: {socket_address: {address: paztport-processor, port_value: 9002}}}
  typed_extension_protocol_options:
    envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
      "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
      explicit_http_config: {http2_protocol_options: {}}
  transport_socket:
    name: envoy.transport_sockets.tls
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext
      sni: paztport-processor
      common_tls_context:
        tls_params: {tls_minimum_protocol_version: TLSv1_3}
        tls_certificates:
          - certificate_chain: {filename: /etc/edge/tls.crt}
            private_key: {filename: /etc/edge/tls.key}
        validation_context:
          trusted_ca: {filename: /etc/mesh/ca.crt}
          match_typed_subject_alt_names: [{san_type: DNS, matcher: {exact: paztport-processor}}]
```

`STRICT_DNS` on `paztport-processor` gives Envoy whatever that name resolves to. For a ClusterIP Service that is
one address, and kube-proxy balances Envoy's few long-lived HTTP/2 connections, as with `routingType: Service`
above; a headless Service (`clusterIP: None`) gives Envoy every ready pod's address, and Envoy balances the requests
itself. The rules are those above: every route to a Paztport backend carries the filter and a mapped route's
metadata (a route the processor does not map is refused 403), only Envoy can reach the processor's port, and nothing
retries a request that reached a backend.

## Measurements

One full run, `./run envoy-gateway measure`, on 2026-11-07 from 14:15Z (results directory `20261107T141511Z`): an Apple
M5 Pro Mac (the model is the host's; the run prints only its Docker Desktop VM's 18 CPUs and 19.5 GiB of memory), one
kind node. Every number is indicative. The run used Envoy Gateway v1.10.0, Envoy v1.40.2, Kubernetes 1.37.0, k6 2.3.0
and a Temurin 25.0.5_8 JRE for `orders` and `payment`. A median is followed by the lowest and highest of its runs, in
brackets; a single run says so. macOS's idle sleep was held off for the run (`caffeinate -i`). Every k6 run kept to
its time, and every run that must keep its offered rate kept it: 293 pace lines, all passed (see
[Measuring it](#measuring-it)). The run exits 1 for one known line, `failure`'s "nothing reached echo unstamped" in the
case with every processor replica gone, and its suite-end total: the recovery leak in [Findings](#findings). Every
other line passed.

### `load`

Three alternated rounds of 20 s a side, after a discarded warm-up; every run at its offered rate, every response a
200, `echo` sent nothing unstamped.

| Body, rate | Plain Envoy p50 | p99 | With the processor p50 | p99 | Added p50 | Added p99 |
|---|---|---|---|---|---|---|
| 400 B, 1000/s | 0.22 ms (0.21-0.22) | 0.46 ms (0.46-0.46) | 0.57 ms (0.49-0.59) | 1.02 ms (1.00-1.02) | +0.35 ms (+0.27 to +0.37) | +0.56 ms (+0.54 to +0.56) |
| 256 KiB, 500/s | 0.30 ms (0.30-0.31) | 0.71 ms (0.70-0.77) | 0.79 ms (0.78-0.80) | 2.08 ms (2.06-2.15) | +0.49 ms (+0.48 to +0.49) | +1.37 ms (+1.35 to +1.38) |

### `ceiling`

The median over three rounds of each round's highest sustained stage (no request dropped, within 2% of the offered
rate, every response a 200), 400-byte bodies.

| Processor replicas | `echo` (with the processor) | `echo-plain` (plain Envoy) |
|---|---|---|
| 1 | 10000/s (10000-10000) | 10000/s (10000-12000) |
| 2 | 14000/s (10000-14000) | 14000/s (10000-14000) |
| 4 | 14000/s (12000-14000) | 16000/s (14000-16000) |

At one and two replicas the two routes have the same median, so there the ramps do not show what the processor costs
in throughput. On one replica, `echo`'s p50 at 7000, 8000 and 10000/s was 1.35, 6.60 and 24.79 ms in the first round;
plain Envoy's stayed near 0.2 ms.

| Past saturation, one replica, 60 s | Requests | 200 | Envoy's 500 (`cluster_rq_active_overflow`) | k6 dropped | Stamped | Unstamped at `echo` |
|---|---|---|---|---|---|---|
| 15000/s | 888710 | 715735 | 172975 (172975) | 11280 | 715735 | 0 |
| 20000/s | 1136372 | 697916 | 438456 (438456) | 63631 | 697916 | 0 |

| Memory, one replica, 1 MiB bodies, 20 s | 10 users | 25 | 50 | 100 |
|---|---|---|---|---|
| peak resident memory (limit 256Mi) | 66.6 MiB | 97.1 MiB | 130.7 MiB | 219.1 MiB |
| requests a second, every one a 200 | 865.87 | 943.14 | 978.16 | 1026.82 |

No restart at any step.

### `edge`

The whole edge at 500/s, 400-byte bodies, three alternated rounds; every run at its rate, every response a 200.

| | p50 | p99 |
|---|---|---|
| Without Paztport (`orders-plain`, the starter excluded) | 0.55 ms (0.54-0.55) | 3.18 ms (3.16-3.23) |
| With Paztport (`orders`, enforce) | 3.74 ms (3.66-3.76) | 6.05 ms (5.98-6.10) |
| Paztport adds | +3.19 ms (+3.12 to +3.21) | +2.87 ms (+2.82 to +2.87) |

The route `orders` with Paztport, one ramp: sustained 2000/s (p50 5.50 ms, p99 12.67 ms); at 3000/s, 2494.9/s
achieved, p50 195.40 ms, 9836 dropped. Overloaded at 3000/s from 6000 users for 20 s: 60001 requests, 50403 200s,
9598 Envoy's 500 (`cluster_rq_active_overflow` on the processor's cluster, 9598), the processor stamping exactly the
50403, both backends counting only `OK`; the longest request took 1322.79 ms, under `orders`' 5 s `maxAgeMs`, so the
age check was not reached.

### `failure`

On `echo` at 7000/s (half the two-replica median above), on `orders` at 1000/s (half its sustained stage); one run
each.

| Case | Requests | Not 200 | Window | Recovery | Unstamped at `echo` |
|---|---|---|---|---|---|
| one processor container killed | 420001 | 2186 (500) | 0.443 s | both ready 2.50 s after the kill | 0 |
| one replica slowed 600 ms, port 9002 for 60 s, then the pod until readiness takes it out and 10 s more; Envoy health-checks the processor | 840003 | 4089 (504: 4081, 500: 8) | 2.327 s | ready throughout the port-only delay (19 of 19 probes); Envoy's health check read it failing 2.45 s after the port delay, the errors stopping 2.83 s after it, and none from that reading on, through the whole-pod delay or after the pod was ready again; out of readiness 1.69 s after the whole pod was slowed; no restart | 0 |
| every replica gone 30 s, routing to endpoints | 630001 | 224040 (500) | 32.006 s | first 200 to a probe 0.92 s after the upgrade to two | 4200, all after the upgrade to two |
| every replica gone 30 s, `routingType: Service` | 630002 | 238664 (500: 172465, 504: 66199) | 35.387 s | first 200 to a probe 2.51 s after the upgrade to two | 0 |
| the processor rolled (`kubectl rollout restart`) | 630001 | 0 | | two new replicas ready 1.75 s after the restart | 0 |
| one `orders` container killed, the route `orders` | 90001 | 15 (503) | 0.305 s | both ready 3.70 s after; 356 retries after 364 failed connections; each of 89987 stamps served once | |

In the slowed case, the 504s are Envoy's `message_timeouts` (+4081), and the 500s its circuit breaker on the
processor's cluster (`cluster_rq_active_overflow` +8). The slowed pod counted `abandoned` +3782, so 299 of the requests
Envoy gave up on (4081 less 3782) the pod stamped and answered, the answer reaching Envoy after it had stopped waiting.

The processor's share of 140001 requests at 7000/s: 50.0% and 50.0% routing to endpoints, 58.3% and 41.7% routing to
the Service.

### `gotchas`

| Case | Requests, one at a time | Answered | What `orders` did |
|---|---|---|---|
| `orders-rewrite`, `/api/orders` rewritten to `/orders` | 10 | 403 ×10 | `BINDING_MISMATCH` ×10 |
| the route `orders`, `payment` at 0 (retries confined) | 50 | 500 ×50 | each stamp served once; Envoy retried none |
| `orders-retry`, retrying 5xx twice, `payment` at 0 | 50 | 403 ×50 | 50: `OK`, then `OK` on the other replica, then `REPLAY` (Envoy's `rq_retry` +100) |

### `observe`

One run at 1000/s on `orders` for 20 s, after a discarded warm-up.

| What was counted | Value |
|---|---|
| requests | 20001, every one a 200 and stamped (`stamped` +20001, no refusal) |
| stamping (`paztport_edge_stamp_seconds`) | p50 27 µs, p99 96 µs, mean 34 µs |
| bodies (`paztport_edge_body_bytes`) | mean 400 B, all up to 1024 B |
| material left (`paztport_edge_material_seconds_left`) | 598984 s (6.9 days), on both pods |
| the backends' reasons | `OK` only |

| Logs scanned for the markers, the stamp's values, any `X-Path-` name and the edge's key in five encodings | Lines | Found |
|---|---|---|
| the processor (both pods, every line) | 29942 | none |
| Envoy (its access log included) | 67777 | none |
| `orders` | 565141 | none |
| `payment` | 29961 | none |

### `rollout`

At 1000/s on `orders-adopt`, one run a step.

| Step | Requests | Not 200 | Window | Backends' reasons |
|---|---|---|---|---|
| 1, the processor's pods rolled to map the route, not attached (backends without Paztport) | 90001 | 0 | | none: neither verifies yet; Envoy started no stream to the processor |
| 2, the processor attached (backends without Paztport) | 90001 | 0 | | none: neither verifies yet; Envoy's 79820 streams to the processor, the pods' 79820 stamps |
| 3, `orders` then `payment` into `enforce` | 150001 | 199 (500) | 5.420 s | `orders` `OK` 135291; `payment` `OK` 131014; no `EXPIRED`; `CHAIN_MISSING` 0 |

In step 2, Envoy started its streams from when it served the route with the filter, 10.52 s into the run (0.70 s into
the change), so the 79820 are fewer than the run's 90001 requests. After step 3, `orders` counted
`response checked CHAIN_MISSING` 4078 (payment's responses before it ran Paztport). A request straight to `orders`, past
the Gateway: 403 `CHAIN_MISSING`.

### `route`

At 1000/s on `orders`, one run a step; the new routes at 50/s, whose 404s before Envoy serves them are counted
apart.

| Step | Requests on `orders` | Not 200 | Window | Refused for material |
|---|---|---|---|---|
| a new URL, `orders-shop` (mapped, then applied) | 90001 | 0 | | none; 3801 on the new route, all 200 |
| overlap 1: the backends pin both roots | 150001 | 190 (500) | 5.438 s | none |
| overlap 2: the processor's new root, bundle and mapping; the route `payment` applied | 90001 | 0 | | none; `/pay` 189 404s before it was served, then no error |
| overlap 3: the old root unpinned everywhere | 150000 | 4526 (403: 420, 500: 4080, 503: 26) | 45.187 s | none (`EXPIRED` 420 at `orders`, 19 at `payment`); 183 errors on `/pay` |
| the old way: every root replaced at once | 150001 | 5770 (403: 3925, 500: 1845) | 57.322 s | `orders` `PATH_NOT_ALLOWED` 3776 (`EXPIRED` 149 at `orders`, 39 at `payment`); `/pay` 186 404s, no error |

The overlap against the old way, as the suite sums them; one run of each, so no spread.

| | The overlap, three steps | The old way, one step |
|---|---|---|
| refused for material (reasons other than `OK`, `EXPIRED` or `CHAIN_MISSING`) | none | `PATH_NOT_ALLOWED` 3776, at `orders` |
| rollouts | four: the backends twice, the processor twice | two: the backends and the processor once, together |
| requests on `orders` | 390002 | 150001 |
| refused for age (`EXPIRED`) | `orders` 420, `payment` 19 | `orders` 149, `payment` 39 |
| not 200 on `orders`, material refusals apart (age refusals included) | 4716 (403: 420; 500: 4270; 503: 26), the suite's sum | 1994 (403: 149; 500: 1845): k6's 5770 non-200s less `orders`' 3776 `PATH_NOT_ALLOWED` |
| load on `/pay` | 11302 requests, from just before its route was applied through step 3's rollouts; 189 404s before it was served, 183 errors | 6601, only after the rollouts, since its route comes after them; 186 404s before it was served, no error |

The overlap's other errors outnumber the old way's, 4716 to 1994, on 2.6 times the requests (390002 against 150001):
1.21% of its requests against 1.33%. Most of them came in its step 3 (4526), which, like the old way's one step, rolls
the backends and the processor together. In both, most of the 500s were Envoy's circuit breaker on the processor's
cluster (`cluster_rq_active_overflow` +3818 in step 3, +1592 in the old way), as in rotation's last step, where only the
backends rolled (+4439); [Findings](#findings) has a reading of it, not measured. That step 3 cost more than the old
way is one run of each, and the run does not say why. What the overlap closes is the refusals for material. A stamp
under the new tree was accepted while `orders`' own root was still the old one (20 of 20), and one under the old tree
refused `PATH_NOT_ALLOWED` once it was unpinned (20 of 20).

### `rotation`

The edge's key rotated at 1000/s on `orders`, one run a step.

| Step | Requests | Not 200 | Window | Backends' reasons, and Envoy |
|---|---|---|---|---|
| 1, the backends pin both keyrings | 150001 | 428 (500: 189, 503: 239) | 5.567 s | `OK` only; `cluster_rq_active_overflow` +0 |
| 2, the processor takes the new key and keyring | 90000 | 0 | | `OK` only |
| 3, the old keyring unpinned | 150000 | 5504 (403: 212, 500: 4958, 503: 334) | 7.680 s | `orders` `EXPIRED` 212, `payment` `EXPIRED` 78; `cluster_rq_active_overflow` +4439 |

A stamp under the new key was accepted while `orders`' own keyring was still the old one (20 of 20), and one under
the old key refused `BAD_SIGNATURE` once it was unpinned (20 of 20). No request reached a backend running Paztport
without a stamp (`CHAIN_MISSING` 0 in every trace) in any step of `rollout`, `route` or `rotation`.
