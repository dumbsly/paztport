# Licensing

Copyright 2026 The Paztport Authors. Licensed under Apache-2.0 (see
[LICENSE](LICENSE) and [NOTICE](NOTICE)). Its patent grant (section 3) licenses
each contributor's patent claims that their contribution infringes, to everyone who
uses the code, commercially included, and ends for anyone who sues over them. The
idea is meant to stay open: anyone can implement, extend, or sell path attestation,
and the only request is that improvements flow back into the open where they can.

## The source and its third-party list

The repository holds Paztport's source and, in [licenses/](licenses), the text of
each licence other than Apache-2.0 that a bundled component is declared under, the
licences [THIRD-PARTY.txt](THIRD-PARTY.txt) lists. The source tree contains no
third-party code; the built jars named below bundle some. That list covers the
runtime dependencies of both Java trees, each with the licence it is used under. All of them are permissive (Apache-2.0, MIT,
BSD-2-Clause, the MIT-style Bouncy Castle licence) or weak copyleft that is fine to
redistribute unmodified (EPL-2.0), except JMH (below). Two of them also carry
Mozilla's Public Suffix List, which is under MPL-2.0: docker-java-transport-zerodep
holds the list as a file, unmodified, whose own notice says it is under MPL-2.0 and
where that licence is published, and Guava holds public-suffix classes that its
documentation ties to the same list. The MPL-2.0 text is not in licenses/. Four
components offer a choice of licence, recorded in
[licenses/overrides.properties](licenses/overrides.properties): Logback (EPL-2.0 or
LGPL-2.1) and Jakarta Annotations (EPL-2.0 or GPL-2.0 with the Classpath Exception)
are used under EPL-2.0, JNA (Apache-2.0 or LGPL-2.1-or-later) under Apache-2.0, and
HdrHistogram (public domain under CC0, or BSD-2-Clause) under BSD-2-Clause.

Regenerate the list after changing dependencies:

```bash
(cd poc-sdks/java && mvn install -DskipTests)   # the demo resolves the SDK from here
poc-sdks/scripts/third-party.sh
```

The script runs the licence plugin in both Java trees, the SDK and the mesh demo
(which adds docker-java and its dependencies, Spring Boot's loader, and Spring Boot's
Actuator and Micrometer's Prometheus registry with their dependencies), and merges
the two lists into `THIRD-PARTY.txt`, sorted by name without duplicates.

## What each jar carries

Every jar the build produces carries `META-INF/LICENSE` (the Apache-2.0 text) and
`META-INF/NOTICE`. The ones that bundle third-party code, the shaded `keygen.jar` and
`policy-tool.jar` and the mesh demo's nine Spring Boot jars, also carry:

- `META-INF/THIRD-PARTY.txt`: exactly what that jar bundles, each component with the
  licence it is used under and its Maven Central coordinates. Its header says how
  to get each component's source (the `-sources.jar` at those coordinates), which
  EPL-2.0 §3.1(a) requires of a binary.
- `META-INF/licenses/`: the text of each licence in that list other than Apache-2.0,
  when there is one.

A Boot jar keeps each library whole under `BOOT-INF/lib`, with the library's own
files. Spring Boot's loader is unpacked at the jar root instead, so the jar's NOTICE
adds Spring Boot's. The libraries, the test jars of core and http, the bench jar and
the tools' unshaded module jars bundle nothing and carry just the two files.
`./run test` checks every one of these jars.

## Images and the other packages

The mesh demo's images are `eclipse-temurin:25.0.5_8-jre` (pinned by digest)
with one of the jars added, so an image's licences are the base image's (the
Temurin JRE and its operating system packages) plus those its jar carries. The
TypeScript packages bundle nothing; npm installs their dependencies as
published. The Go module depends on nothing beyond Go's standard library.

The Envoy Gateway processor is a Go binary, and Go compiles every module it uses into
it, so its image carries what the jars carry: in `/licenses/`, the repository's
LICENSE, a NOTICE that starts with the repository's and adds each module's own, the
processor's [THIRD-PARTY.txt](poc-demos/envoy-gateway/processor/THIRD-PARTY.txt), and
each module's licence (and patent grant, where it has one) under
`third-party/<module>@<version>/`. That list names every module the binary is built
from, Go's standard library included, each under one licence (Apache-2.0, MIT or
BSD-3-Clause), and every licence file within a module over code the binary holds,
such as the BSD-3-Clause licence of the package `client_golang` copies in, which the
image carries at its path. `./run test` checks the list against `go list -deps`, and
the image build against the built binary, failing for a module with no licence file
and for a licence file the list does not name. The base is distroless, whose own
packages carry their copyright files. The measurements' upstream, `echo` (the same
Dockerfile's target `echo`), is built from Go's standard library alone, and its build
fails if the binary holds any module; so its image carries the repository's LICENSE
and NOTICE and, under `third-party/std@<version>/`, Go's licence and patent grant.

## Bouncy Castle and JMH

Bouncy Castle appears in the build for two reasons: the SDK's `keygen` uses it to
build the mesh's X.509 certificates, and `docker-java` uses it for Docker TLS in the
responder. None of Paztport's own cryptography uses it; stamps, hashing, salts and
the certificates' signatures all come from the JDK.

JMH, the benchmark harness, is GPLv2 with the Classpath Exception. `./run bench` runs
it from the Maven class path beside the bench module's classes, so no jar bundles it.
It and its two dependencies, JOpt Simple and Apache Commons Math, are in
THIRD-PARTY.txt as the bench module's runtime dependencies; neither the SDK
libraries nor the demos use them.
