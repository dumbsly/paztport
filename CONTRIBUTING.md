# Contributing

Issues are welcome: questions, errors in the docs, a break that is not a
vulnerability, and ports to other languages. A vulnerability goes to
[SECURITY.md](SECURITY.md), not to an issue.

Pull requests are by arrangement: open an issue first.

## The path a change takes

Every change that touches behaviour takes these steps, in order.

1. A sentence in the spec, in [poc-sdks/spec/](poc-sdks/spec/README.md).
2. The shared vectors in `poc-sdks/spec/vectors/`, each written by one exporter
   and regenerated from it, never hand-edited. The spec's section on each file
   names its exporter and how to run it:
   [v4.json](poc-sdks/spec/README.md#v4json),
   [http-v4.json](poc-sdks/spec/README.md#http-v4json),
   [events.json](poc-sdks/spec/README.md#eventsjson),
   [json.json](poc-sdks/spec/README.md#jsonjson) and
   [ed25519.json](poc-sdks/spec/README.md#ed25519json).
3. All three SDKs: [TypeScript](poc-sdks/typescript/README.md),
   [Java](poc-sdks/java/README.md) and [Go](poc-sdks/go/README.md).
4. `./run test` and `./run test --container`
   ([how they run](README.md#quick-start)).

The code is AI-written and held to the shared vectors and checks, so a contribution
is reviewed the same way.

## Licence

Contributions are under Apache-2.0, as section 5 of the [LICENSE](LICENSE) provides.
There is no CLA and no sign-off.

## Where to start

[docs/review-path.md](docs/review-path.md) is a reading path through the spec and the
code. [What adopting it costs](docs/limits.md#what-adopting-it-costs) sets out what a
deployment takes on.
