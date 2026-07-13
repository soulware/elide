# Elide coordinator container image for Fly.io, standalone (no mint).
#
# Downloads the released elide binaries — the coordinator daemon, the `elide`
# volume/CLI binary (it opens /dev/ublk-control and carries the volume verbs),
# and elide-import — then loads `ublk_drv` and runs `elide-coordinator serve`
# over coord.toml. The coordinator signs S3 with the AWS_ACCESS_KEY_ID /
# AWS_SECRET_ACCESS_KEY in its environment (Fly secrets).
#
# Build args:
#   ELIDE_RELEASE  release tag to fetch binaries from, e.g. v0.1.11 (deploy.sh
#                  passes this); empty (the default) fetches the newest release.
#   DATA_BUCKET    the Tigris bucket the keypair has read/write on; baked into
#                  coord.toml [store].bucket.

FROM ubuntu:24.04
# kmod for `modprobe ublk_drv`; ca-certificates for HTTPS to Tigris.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates kmod \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# HTTPS covers the transfer. The three binaries share a directory: the
# coordinator spawns `elide` and `elide-import` as siblings.
ARG ELIDE_RELEASE
ARG ELIDE_TARGET=x86_64-unknown-linux-gnu
ARG ELIDE_BASE=https://github.com/soulware/elide/releases
# GitHub serves a pinned tag at download/<tag>/<asset> but the newest release
# at latest/download/<asset>; the expansions pick the shape ELIDE_RELEASE needs.
ARG ELIDE_PATH=${ELIDE_RELEASE:+download/}${ELIDE_RELEASE:-latest/download}
ADD --chmod=0755 ${ELIDE_BASE}/${ELIDE_PATH}/elide-${ELIDE_TARGET}             /usr/local/bin/elide
ADD --chmod=0755 ${ELIDE_BASE}/${ELIDE_PATH}/elide-coordinator-${ELIDE_TARGET} /usr/local/bin/elide-coordinator
ADD --chmod=0755 ${ELIDE_BASE}/${ELIDE_PATH}/elide-import-${ELIDE_TARGET}      /usr/local/bin/elide-import

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY coord.toml /app/coord.toml

# Bake the per-deployment bucket into coord.toml.
ARG DATA_BUCKET=elide
RUN sed -i \
  -e "s|^bucket = .*|bucket = \"${DATA_BUCKET}\"|" \
  /app/coord.toml

# Every coordinator subcommand reads ELIDE_COORD_CONFIG, so an in-container
# `elide-coordinator` invocation needs no --config.
ENV ELIDE_COORD_CONFIG=/app/coord.toml
# The `elide` volume/CLI subcommands resolve their data_dir from ELIDE_DATA_DIR;
# set it to coord.toml's data_dir so an in-container `elide volume …` finds the
# coordinator's control socket with no --data-dir.
ENV ELIDE_DATA_DIR=/data/elide_data

CMD ["sh", "/usr/local/bin/entrypoint.sh"]
