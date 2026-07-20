# Elide coordinator + PostgreSQL container image for Fly.io: the standalone
# coordinator deploy (see ../elide-standalone) with postgres 16 and the pgsoak
# correctness-soak harness baked in. The entrypoint runs only the coordinator;
# postgres lives on an elide volume and is driven over `fly ssh` via pgsoak.
#
# Build args:
#   ELIDE_RELEASE  release tag to fetch binaries from, e.g. v0.1.21 (deploy.sh
#                  passes this); empty (the default) fetches the newest release.
#   DATA_BUCKET    the Tigris bucket the keypair has read/write on; baked into
#                  coord.toml [store].bucket.

FROM ubuntu:24.04
# kmod for `modprobe ublk_drv`; ca-certificates for HTTPS to Tigris; e2fsprogs
# for mkfs/e2fsck on the elide device; procps for pkill in the crash verbs.
# postgresql-16 ships the server, pgbench, and the amcheck extension;
# pg_dropcluster removes the cluster the deb postinst creates so the only
# data directory is the one pgsoak makes on the elide volume.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates kmod e2fsprogs procps postgresql-16 \
 && rm -rf /var/lib/apt/lists/* \
 && pg_dropcluster --stop 16 main || true

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
COPY --chmod=0755 pgsoak /usr/local/bin/pgsoak
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
