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
# The target echo is the measurements' upstream (cmd/echo), on the same base. It is built from Go's standard library
# alone, and the build fails if the binary holds any module, so it carries the repository's LICENSE and NOTICE and,
# under third-party/std@<go version>/, Go's licence and patent grant, as the processor's image carries std's:
#
#   docker build -f poc-demos/envoy-gateway/processor/Dockerfile --target echo -t paztport-echo:dev .
#
# Each base is pinned by the digest of its index. golang:1.27.4 at 2026-11-10 (docker-library/repo-info,
# repos/golang/remote/1.27.4.md at 2d1d058); distroless static-debian13:nonroot as uploaded on 2026-10-31.
FROM golang:1.27.4@sha256:08bcb99a38f85a265f9a93d1d3323e2440eec333380f3ea26ee0dec9264bb41c AS build
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
RUN go build -trimpath -ldflags='-s -w' -o /out/echo ./cmd/echo \
 && if go version -m /out/echo | grep -q '^[[:space:]]*dep[[:space:]]'; then \
      echo "echo is built from modules besides the standard library, whose licences its image does not carry" >&2; \
      exit 1; \
    fi \
 && std="/out/echo-licenses/third-party/std@$(go env GOVERSION)" \
 && mkdir -p "$std" \
 && cp /src/LICENSE /src/NOTICE /out/echo-licenses/ \
 && cp "$(go env GOROOT)/LICENSE" "$(go env GOROOT)/PATENTS" "$std/"

FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS echo
COPY --from=echo-build /out/echo /echo
COPY --from=echo-build /out/echo-licenses/ /licenses/
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/echo"]

# The processor's image, the default target.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=build /out/processor /processor
COPY --from=build /out/licenses/ /licenses/
USER 65532:65532
EXPOSE 9002 9090
ENTRYPOINT ["/processor"]
