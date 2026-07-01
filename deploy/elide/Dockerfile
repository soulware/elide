# Elide coordinator container image for Fly.io.
#
# Downloads the released elide binaries at ELIDE_VERSION — the coordinator
# daemon, the `elide` volume/CLI binary (it opens /dev/ublk-control and carries
# login/enroll), and elide-import — then loads `ublk_drv` and runs
# `elide-coordinator serve` over coord.toml.
#
# Build args:
#   ELIDE_VERSION  released elide tag to download (required; deploy.sh resolves it).
#   DATA_BUCKET    the Tigris data bucket (must equal mint's DATA_BUCKET); baked
#                  into coord.toml [store].bucket.
#   MINT_APP       the mint Fly app this coordinator enrols against; baked into
#                  coord.toml [mint].url.
#   ATTEST_APP     the dedicated attestation authority (deploy/attest) this
#                  coordinator fetches discharges from; baked into coord.toml
#                  [mint].attestation_transport.

FROM ubuntu:24.04
# kmod for `modprobe ublk_drv`; ca-certificates for HTTPS to Tigris.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates kmod \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# ELIDE_VERSION has no default; an unset build fails here rather than fetching a
# malformed URL.
ARG ELIDE_VERSION
RUN [ -n "${ELIDE_VERSION}" ] || { echo "ELIDE_VERSION build-arg is required; deploy via ./deploy.sh" >&2; exit 1; }

# The tag is the pin; HTTPS covers the transfer. The three binaries share a
# directory: the coordinator spawns `elide` and `elide-import` as siblings.
ARG ELIDE_TARGET=x86_64-unknown-linux-gnu
ARG ELIDE_BASE=https://github.com/soulware/elide/releases/download
ADD --chmod=0755 ${ELIDE_BASE}/${ELIDE_VERSION}/elide-${ELIDE_TARGET}             /usr/local/bin/elide
ADD --chmod=0755 ${ELIDE_BASE}/${ELIDE_VERSION}/elide-coordinator-${ELIDE_TARGET} /usr/local/bin/elide-coordinator
ADD --chmod=0755 ${ELIDE_BASE}/${ELIDE_VERSION}/elide-import-${ELIDE_TARGET}      /usr/local/bin/elide-import

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY coord.toml /app/coord.toml

# Bake the per-deployment bucket, mint app, and attest app into coord.toml
# (deploy/mint's Dockerfile seds its bucket the same way).
ARG DATA_BUCKET=elide
ARG MINT_APP=mint-for-elide
ARG ATTEST_APP=elide-attest
RUN sed -i \
  -e "s|^bucket = .*|bucket = \"${DATA_BUCKET}\"|" \
  -e "s|^url = .*|url = \"http://${MINT_APP}.internal:8085\"|" \
  -e "s|^attestation_transport = .*|attestation_transport = \"http://${ATTEST_APP}.internal:8087\"|" \
  /app/coord.toml

# Every coordinator subcommand reads ELIDE_COORD_CONFIG, so the in-container
# `elide coord enroll` needs no --config.
ENV ELIDE_COORD_CONFIG=/app/coord.toml
# The `elide` volume/CLI subcommands resolve their data_dir from ELIDE_DATA_DIR;
# set it to coord.toml's data_dir so an in-container `elide volume …` finds the
# coordinator's control socket with no --data-dir.
ENV ELIDE_DATA_DIR=/data/elide_data

CMD ["sh", "/usr/local/bin/entrypoint.sh"]
