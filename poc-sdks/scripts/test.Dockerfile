# Copyright 2026 The Paztport Authors
# SPDX-License-Identifier: Apache-2.0
#
# The toolchains ./run test needs, and nothing else: the repository is not baked in. ./run test --container builds
# this image, streams the working tree into a fresh container and runs ./run test there as an unprivileged user.

# Index digest of eclipse-temurin:25-jdk-noble (JDK 25.0.5+8 on Ubuntu 24.04, the same as CI's runner), from
# `docker buildx imagetools inspect eclipse-temurin:25-jdk-noble`, so a moved tag cannot change what is built.
FROM eclipse-temurin:25-jdk-noble@sha256:80f67fb3d6f76e2d817d98a4cc2a9cf05f054d4e6adc5e2144bde671d722e63f

# Set by BuildKit to amd64 or arm64; it picks the tarball and checksum below.
ARG TARGETARCH

# gcc and libc6-dev are for the race detector, which needs cgo (CI's runner has them). Ubuntu packages are not
# version-pinned; the base digest fixes the archive snapshot they come from, near enough.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gcc git libc6-dev unzip xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Each download is checked against its pinned checksum before it is unpacked.
#
# Go 1.27.4. The checksums are the sha256 values of go.dev/dl/?mode=json for go1.27.4.linux-amd64.tar.gz and
# go1.27.4.linux-arm64.tar.gz.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) sum=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840 ;; \
      arm64) sum=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92 ;; \
      *) echo "unsupported architecture: ${TARGETARCH:-unset} (amd64 and arm64 only; build with BuildKit)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/go.tar.gz "https://go.dev/dl/go1.27.4.linux-${TARGETARCH}.tar.gz"; \
    echo "$sum  /tmp/go.tar.gz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tar.gz; \
    rm /tmp/go.tar.gz

# Node 22.23.5. The checksums are the node-v22.23.5-linux-x64.tar.xz and node-v22.23.5-linux-arm64.tar.xz lines of
# https://nodejs.org/dist/v22.23.5/SHASUMS256.txt.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) node_arch=x64; sum=cdeb8670a0c81f51b4dc4ac61919f9b1ad917b304bf8221eb939570663d240f8 ;; \
      arm64) node_arch=arm64; sum=2babb9eb5264860d540849f4b064a6fbdebcdc323657d9d382ce23d313fd5e09 ;; \
      *) echo "unsupported architecture: ${TARGETARCH:-unset} (amd64 and arm64 only; build with BuildKit)" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/node.tar.xz "https://nodejs.org/dist/v22.23.5/node-v22.23.5-linux-${node_arch}.tar.xz"; \
    echo "$sum  /tmp/node.tar.xz" | sha256sum -c -; \
    mkdir /usr/local/node; \
    tar -C /usr/local/node --strip-components=1 -xJf /tmp/node.tar.xz; \
    rm /tmp/node.tar.xz

# Maven 3.10.0. The checksum is the sha512 Apache publishes next to the archive,
# https://downloads.apache.org/maven/maven-3/3.10.0/binaries/apache-maven-3.10.0-bin.tar.gz.sha512.
RUN set -eu; \
    curl -fsSL -o /tmp/maven.tar.gz "https://archive.apache.org/dist/maven/maven-3/3.10.0/binaries/apache-maven-3.10.0-bin.tar.gz"; \
    echo "908b1501bfb420bf7c8affb855534a9c407fd6099367bfb9f2f2dcb8e9799102bffb84518cde74c679bd76870247c6528683abdd620581bffa90f95d92d175aa  /tmp/maven.tar.gz" | sha512sum -c -; \
    mkdir /usr/local/maven; \
    tar -C /usr/local/maven --strip-components=1 -xzf /tmp/maven.tar.gz; \
    rm /tmp/maven.tar.gz

# GOTOOLCHAIN=local keeps go from fetching another toolchain when a go line asks for more than 1.27.4.
ENV PATH=/usr/local/go/bin:/usr/local/node/bin:/usr/local/maven/bin:$PATH \
    GOTOOLCHAIN=local

# staticcheck 2026.2.2, built from source; go.sum verifies the modules it downloads. It goes to /usr/local/bin, and
# the module and build caches of this step are removed so that they stay out of the image.
RUN GOBIN=/usr/local/bin GOPATH=/tmp/gopath GOCACHE=/tmp/gocache go install honnef.co/go/tools/cmd/staticcheck@2026.2.2 \
 && GOPATH=/tmp/gopath go clean -modcache \
 && rm -rf /tmp/gopath /tmp/gocache

# The suites run as an unprivileged user. The cache directories exist, and belong to that user, in the image: a new
# named volume mounted over one of them takes on its owner, so the user can write to it. They hold downloads and
# build caches, nothing the suites need to keep.
RUN useradd --create-home --shell /bin/bash paztport \
 && mkdir -p /work /home/paztport/.m2/repository /home/paztport/go/pkg/mod /home/paztport/.cache/go-build /home/paztport/.npm \
 && chown -R paztport:paztport /work /home/paztport
USER paztport
ENV HOME=/home/paztport \
    GOPATH=/home/paztport/go \
    GOCACHE=/home/paztport/.cache/go-build
WORKDIR /work
