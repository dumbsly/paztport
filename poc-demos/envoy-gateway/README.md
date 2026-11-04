# Envoy Gateway proof of concept

Paztport at an [Envoy Gateway](https://gateway.envoyproxy.io) edge on a local [kind](https://kind.sigs.k8s.io)
cluster. A Go `ext_proc` processor stamps each request as the origin service `edge`, and the
[java-mesh](../java-mesh/README.md) services `orders` and `payment` verify it. The idea and the concepts are in the
[root README](../../README.md).

This is work in progress: the processor and its image are here, and the cluster scaffold and the checks arrive in
later commits; there are no results here yet.

## Prerequisites

`./run envoy-gateway` checks these first and stops with a `missing:` line for the first one that is not there:

| Tool | At least | Why |
|---|---|---|
| Java and Maven | 25 | build the SDK, and run the key and policy tools |
| Docker | 24 | build the images, and run the kind node |
| Go | the SDK's `go` line | build the processor |
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
`x_request_id`. It never logs a body, a Paztport header, any other header the client sent, or a key.

The image builds from the repository's root, locally, and is never pushed:

```bash
docker build -f poc-demos/envoy-gateway/processor/Dockerfile -t paztport-processor:dev .
```
