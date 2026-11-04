# Envoy Gateway proof of concept

Paztport at an [Envoy Gateway](https://gateway.envoyproxy.io) edge on a local [kind](https://kind.sigs.k8s.io)
cluster. A Go `ext_proc` processor stamps each request as the origin service `edge`, and the
[java-mesh](../java-mesh/README.md) services `orders` and `payment` verify it. The idea and the concepts are in the
[root README](../../README.md).

This is work in progress: the processor's core is here, and its server, the cluster scaffold and the checks arrive in
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
| `processor/` | the Go `ext_proc` processor: `internal/routes` names each request's receiver from its HTTPRoute, `internal/material` loads and checks the edge's keys and policy, `internal/edge` stamps each request or refuses it |

`material.sh` refuses to write over an existing `out/`; `--fresh` makes everything again. `PAZTPORT_POLICY_DAYS` sets
how long the keyring and the policy root last (default 7 days).
