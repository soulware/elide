# mint-for-elide container image for Fly.io.
#
# Stage 1 downloads the released `mint` binary at a pinned version, verifies it
# against a digest pinned in this repo, and renders the role templates with the
# deployment's data bucket. Stage 2 assembles the runtime image and runs
# `mint serve` over mint-fly.toml.
#
# Build args:
#   MINT_VERSION  released mint tag to download, e.g. v0.1.0 (lockstep with this
#                 coordinator).
#   MINT_SHA256   expected sha256 of the downloaded asset; bump with MINT_VERSION.
#   DATA_BUCKET   the volume-data bucket baked into the role ARNs; must equal
#                 the coordinator's [store].bucket.

ARG MINT_VERSION=v0.1.1

FROM ubuntu:24.04 AS build
ARG MINT_VERSION
# curl + CA certs only — the binary is a published release artifact, so the build
# stage needs no rust toolchain, git, or build-essential.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Verify the download against a digest pinned here, not the release's own .sha256
# (an actor who can replace the binary can replace that checksum too).
ARG MINT_ASSET=mint-x86_64-unknown-linux-gnu
ARG MINT_BASE=https://github.com/soulware/mint/releases/download
ARG MINT_SHA256=d5c1a801ba38dae84d0ad66898586960f0561154f69ee31a0417a0907dc5fce4
RUN curl --proto '=https' --tlsv1.2 -fsSLO "${MINT_BASE}/${MINT_VERSION}/${MINT_ASSET}" \
 && echo "${MINT_SHA256}  ${MINT_ASSET}" | sha256sum -c - \
 && install -m 0755 "${MINT_ASSET}" /usr/local/bin/mint

# Resolve {{build.bucket}} into the rendered roles/ that `mint serve` loads.
# A pure file pass — no S3, no credentials — done here so the unrendered
# templates stay out of the runtime image.
ARG DATA_BUCKET=elide
COPY role-templates/ /role-templates/
RUN mint render --in-dir /role-templates \
      --build "bucket=${DATA_BUCKET}" --out-dir /roles

FROM ubuntu:24.04
# ca-certificates for HTTPS to Tigris.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /usr/local/bin/mint /usr/local/bin/mint
COPY --from=build /roles /app/roles

COPY mint-fly.toml /app/mint.toml
# mint's [store].bucket (its own _mint/* admin state) is TOML-only, not an env
# input. Default it to the data bucket — _mint/* shares the bucket under a
# distinct prefix — or set STORE_BUCKET to give mint its own bucket.
ARG DATA_BUCKET=elide
ARG STORE_BUCKET=
RUN sed -i "s|^bucket = .*|bucket = \"${STORE_BUCKET:-$DATA_BUCKET}\"|" /app/mint.toml

# Every mint subcommand reads MINT_CONFIG, so serve and the in-container
# operator commands (login/seal/invite) need no --config.
ENV MINT_CONFIG=/app/mint.toml
EXPOSE 8085
CMD ["mint", "serve"]
