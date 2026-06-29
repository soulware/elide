# Elide attestation authority (coord B) container image for Fly.io.
#
# Downloads the released elide binaries at ELIDE_VERSION — the coordinator
# daemon (which carries the `attest` serve mode) and the `elide` CLI (login +
# `coord enroll --attestation`) — then runs `elide-coordinator attest` over
# coord.toml. No ublk and no elide-import: coord B serves no volumes.
#
# Build args:
#   ELIDE_VERSION  released elide tag to download (required; deploy.sh resolves it).
#   DATA_BUCKET    the Tigris data bucket (must equal mint's DATA_BUCKET); baked
#                  into coord.toml [store].bucket.
#   MINT_APP       the mint Fly app this authority enrols against; baked into
#                  coord.toml [mint].url.

FROM ubuntu:24.04
# ca-certificates for HTTPS to Tigris.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# ELIDE_VERSION has no default; an unset build fails here rather than fetching a
# malformed URL.
ARG ELIDE_VERSION
RUN [ -n "${ELIDE_VERSION}" ] || { echo "ELIDE_VERSION build-arg is required; deploy via ./deploy.sh" >&2; exit 1; }

# The tag is the pin; HTTPS covers the transfer. The `elide` CLI is the sibling
# the operator runs for `login` + `coord enroll --attestation`.
ARG ELIDE_TARGET=x86_64-unknown-linux-gnu
ARG ELIDE_BASE=https://github.com/soulware/elide/releases/download
ADD --chmod=0755 ${ELIDE_BASE}/${ELIDE_VERSION}/elide-${ELIDE_TARGET}             /usr/local/bin/elide
ADD --chmod=0755 ${ELIDE_BASE}/${ELIDE_VERSION}/elide-coordinator-${ELIDE_TARGET} /usr/local/bin/elide-coordinator

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY coord.toml /app/coord.toml

# Bake the per-deployment bucket + mint app into coord.toml (deploy/elide's
# Dockerfile seds its bucket the same way).
ARG DATA_BUCKET=elide
ARG MINT_APP=mint-for-elide
RUN sed -i \
  -e "s|^bucket = .*|bucket = \"${DATA_BUCKET}\"|" \
  -e "s|^url = .*|url = \"http://${MINT_APP}.internal:8085\"|" \
  /app/coord.toml

# Every coordinator subcommand reads ELIDE_COORD_CONFIG, so the in-container
# `elide coord enroll --attestation` and `elide-coordinator attest` need no
# --config.
ENV ELIDE_COORD_CONFIG=/app/coord.toml

CMD ["sh", "/usr/local/bin/entrypoint.sh"]
