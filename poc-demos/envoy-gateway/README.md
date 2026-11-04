# Envoy Gateway proof of concept

Paztport at an [Envoy Gateway](https://gateway.envoyproxy.io) edge on a local [kind](https://kind.sigs.k8s.io)
cluster. A Go `ext_proc` processor stamps each request as the origin service `edge`, and the
[java-mesh](../java-mesh/README.md) services `orders` and `payment` verify it. The idea and the concepts are in the
[root README](../../README.md).

This is work in progress: the processor, the cluster scaffold and the checks arrive in later commits, and there are
no results here yet.

## Prerequisites

`./run envoy-gateway` checks these first and stops with a `missing:` line for the first one that is not there:

| Tool | At least | Why |
|---|---|---|
| Java and Maven | 25 | build the SDK, and run the key and policy tools |
| Docker | 24 | build the images, and run the kind node |
| Go | the SDK's `go` line | build the processor |
| kind | 0.33 | the local cluster |
| kubectl | 1.33 | drive the cluster |
| Helm | 3.17 | install Envoy Gateway and the processor's chart |

macOS and Linux; on Windows use WSL.

## Layout

| Path | What it is |
|---|---|
| `paths.yaml` | the routes the policy allows: `edge → orders` and `edge → orders → payment` |
| `material.sh` | makes the keys and the signed policy into `out/`, standing in for CI |
| `out/` | what `material.sh` wrote; holds private keys and is not committed |

`material.sh` refuses to write over an existing `out/`; `--fresh` makes everything again. `PAZTPORT_POLICY_DAYS` sets
how long the keyring and the policy root last (default 7 days).
