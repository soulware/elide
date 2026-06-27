# Elide coordinator container image for Fly.io.
#
# Stage 1 downloads the released elide binaries at the pinned ELIDE_VERSION — the
# coordinator daemon, the `elide` volume/CLI binary (it opens /dev/ublk-control
# and carries login/enroll), and elide-import. Stage 2 assembles the runtime
# image, loads `ublk_drv`, and runs `elide-coordinator serve` over coord.toml.
#
# Build args:
#   ELIDE_VERSION  released elide tag to download, e.g. v0.1.1.
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

# The ELIDE_VERSION tag is the pin; HTTPS covers the transfer.
ARG ELIDE_TARGET=x86_64-unknown-linux-gnu
ARG ELIDE_BASE=https://github.com/soulware/elide/releases/download
RUN set -eu; \
    for bin in elide elide-coordinator elide-import; do \
      asset="${bin}-${ELIDE_TARGET}"; \
      curl --proto '=https' --tlsv1.2 -fsSLO "${ELIDE_BASE}/${ELIDE_VERSION}/${asset}"; \
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
