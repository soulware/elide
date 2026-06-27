# Elide coordinator container image for Fly.io.
#
# Stage 1 downloads the released elide binaries at a pinned version and verifies
# each against a digest pinned in this repo — the coordinator daemon, the `elide`
# volume/CLI binary (it opens /dev/ublk-control and carries login/enroll), and
# elide-import. Stage 2 assembles the runtime image, loads `ublk_drv`, and runs
# `elide-coordinator serve` over coord.toml.
#
# Build args:
#   ELIDE_VERSION  released elide tag to download, e.g. v0.1.0.
#   ELIDE_*_SHA256 expected sha256 of each downloaded binary; bump with ELIDE_VERSION.
#   DATA_BUCKET    the Tigris data bucket (must equal mint's DATA_BUCKET); baked
#                  into coord.toml [store].bucket.
#   MINT_APP       the mint Fly app this coordinator enrols against; baked into
#                  coord.toml [mint].url.

ARG ELIDE_VERSION=v0.1.1

FROM ubuntu:24.04 AS build
ARG ELIDE_VERSION
# curl + CA certs only — the binaries are published release artifacts, so the
# build stage needs no rust toolchain, git, or clang.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Verify each download against a digest pinned here, not the release's own
# .sha256 (an actor who can replace a binary can replace that checksum too).
ARG ELIDE_TARGET=x86_64-unknown-linux-gnu
ARG ELIDE_BASE=https://github.com/soulware/elide/releases/download
ARG ELIDE_SHA256=c5acccd0925e98c791b82d72d085c36b41ebd85682daa1d1e7b3f9e667bdab23
ARG ELIDE_COORDINATOR_SHA256=015f5b4115cbe9dbefe327ee26a185c686d181405a32c978347d9ec51d3756ba
ARG ELIDE_IMPORT_SHA256=99fa5d5545403bc346317eb6abdb0bd04a2cb6cc6041225bd2d3cf76bf8b6bd8
RUN set -eu; \
    for spec in \
      "elide:${ELIDE_SHA256}" \
      "elide-coordinator:${ELIDE_COORDINATOR_SHA256}" \
      "elide-import:${ELIDE_IMPORT_SHA256}"; do \
      bin="${spec%%:*}"; sha="${spec#*:}"; asset="${bin}-${ELIDE_TARGET}"; \
      curl --proto '=https' --tlsv1.2 -fsSLO "${ELIDE_BASE}/${ELIDE_VERSION}/${asset}"; \
      echo "${sha}  ${asset}" | sha256sum -c -; \
      install -m 0755 "${asset}" "/usr/local/bin/${bin}"; \
    done

FROM ubuntu:24.04
# kmod for `modprobe ublk_drv`; ca-certificates for HTTPS to Tigris.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates kmod \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# The three binaries share a directory: the coordinator spawns `elide` and
# `elide-import` as siblings of itself.
COPY --from=build /usr/local/bin/elide-coordinator /usr/local/bin/
COPY --from=build /usr/local/bin/elide /usr/local/bin/
COPY --from=build /usr/local/bin/elide-import /usr/local/bin/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY coord.toml /app/coord.toml

# Bake the per-deployment bucket + mint app into coord.toml (deploy/mint's
# Dockerfile seds its bucket the same way).
ARG DATA_BUCKET=elide
ARG MINT_APP=mint-for-elide
RUN sed -i \
  -e "s|^bucket = .*|bucket = \"${DATA_BUCKET}\"|" \
  -e "s|^url = .*|url = \"http://${MINT_APP}.internal:8085\"|" \
  /app/coord.toml

# Every coordinator subcommand reads ELIDE_COORD_CONFIG, so the in-container
# `elide coord enroll` needs no --config.
ENV ELIDE_COORD_CONFIG=/app/coord.toml
# The `elide` volume/CLI subcommands resolve their data_dir from ELIDE_DATA_DIR;
# set it to coord.toml's data_dir so an in-container `elide volume …` finds the
# coordinator's control socket with no --data-dir.
ENV ELIDE_DATA_DIR=/data/elide_data

CMD ["sh", "/usr/local/bin/entrypoint.sh"]
