# mint-for-elide container image for Fly.io.
#
# Stage 1 downloads the released `mint` binary at MINT_VERSION and renders the
# role templates with the deployment's data bucket. Stage 2 assembles the
# runtime image and runs `mint serve` over mint-fly.toml.
#
# Build args:
#   MINT_VERSION  released mint tag to download (required; deploy.sh resolves it).
#   DATA_BUCKET   the volume-data bucket baked into the role ARNs; must equal
#                 the coordinator's [store].bucket.

FROM ubuntu:24.04 AS build

# MINT_VERSION has no default; an unset build fails here rather than fetching a
# malformed URL.
ARG MINT_VERSION
RUN [ -n "${MINT_VERSION}" ] || { echo "MINT_VERSION build-arg is required; deploy via ./deploy.sh" >&2; exit 1; }

# The tag is the pin; HTTPS covers the transfer.
ARG MINT_ASSET=mint-x86_64-unknown-linux-gnu
ARG MINT_BASE=https://github.com/soulware/mint/releases/download
ADD --chmod=0755 ${MINT_BASE}/${MINT_VERSION}/${MINT_ASSET} /usr/local/bin/mint

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
