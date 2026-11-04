# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The edge's processor: a static binary on distroless, as nonroot, carrying the repository's LICENSE and NOTICE
# and the licence of every module it is built from (third-party.sh gathers them, and fails the build when the
# binary's modules are not the ones THIRD-PARTY.txt names, or one has no licence file). The module replaces the
# Go SDK with its directory, so the build context is the repository's root:
#
#   docker build -f poc-demos/envoy-gateway/processor/Dockerfile -t paztport-processor:dev .
#
# The target echo is the measurements' upstream (cmd/echo, the standard library alone), on the same base and
# carrying the same licence files:
#
#   docker build -f poc-demos/envoy-gateway/processor/Dockerfile --target echo -t paztport-echo:dev .
#
# Each base is pinned by the digest of its index. golang:1.27.3 at 2026-10-21 (docker-library/repo-info,
# repos/golang/remote/1.27.3.md at 7f748ed); distroless static-debian12:nonroot as uploaded on 2026-08-21.
FROM golang:1.27.3@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS build
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src/poc-demos/envoy-gateway/processor
COPY poc-sdks/go/ /src/poc-sdks/go/
COPY poc-demos/envoy-gateway/processor/go.mod poc-demos/envoy-gateway/processor/go.sum ./
RUN go mod download
COPY LICENSE NOTICE /src/
COPY poc-demos/envoy-gateway/processor/ ./
RUN go build -trimpath -ldflags='-s -w' -o /out/processor ./cmd/processor \
 && bash third-party.sh gather /out/processor /out/licenses

FROM build AS echo-build
RUN go build -trimpath -ldflags='-s -w' -o /out/echo ./cmd/echo

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS echo
COPY --from=echo-build /out/echo /echo
COPY --from=build /out/licenses/ /licenses/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/echo"]

# The processor's image, the default target.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/processor /processor
COPY --from=build /out/licenses/ /licenses/
USER 65532:65532
EXPOSE 9002 9090
ENTRYPOINT ["/processor"]
