# mint-for-elide container image for Fly.io.
#
# Stage 1 builds the stock `mint` binary from a pinned source ref (mint
# publishes no release artifact). Stage 2 renders the role templates with the
# deployment's data bucket and runs `mint serve` over mint-fly.toml.
#
# Build args:
#   MINT_REF     mint commit/tag to build (lockstep with this coordinator).
#   DATA_BUCKET  the volume-data bucket baked into the role ARNs; must equal
#                the coordinator's [store].bucket.

ARG MINT_REF=93ffda83e69c17e5572ce0104ae8c5d84e353d5e

FROM ubuntu:24.04 AS build
ARG MINT_REF
# Rust via rustup (no official rust image on Ubuntu, and mint is edition 2024 so
# Ubuntu's apt rustc is too old); build-essential supplies the C compiler ring
# needs. mint is rustls-based, so no libssl-dev.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git build-essential \
 && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN git clone https://github.com/soulware/mint /src \
 && git -C /src checkout "${MINT_REF}" \
 && cargo build --release --manifest-path /src/Cargo.toml --bin mint

FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/mint /usr/local/bin/mint

# Resolve {{build.bucket}} into the rendered roles/ that `mint serve` loads.
# A pure file pass — no S3 — so it runs here without credentials.
ARG DATA_BUCKET=elide
COPY role-templates/ /app/role-templates/
RUN mint render --in-dir /app/role-templates --build "bucket=${DATA_BUCKET}" --out-dir /app/roles

COPY mint-fly.toml /app/mint.toml
# mint's [store].bucket (its own _mint/* admin state) is TOML-only, not an env
# input. Default it to the data bucket — _mint/* shares the bucket under a
# distinct prefix — or set STORE_BUCKET to give mint its own bucket.
ARG STORE_BUCKET=
RUN sed -i "s|^bucket = .*|bucket = \"${STORE_BUCKET:-$DATA_BUCKET}\"|" /app/mint.toml

# Every mint subcommand reads MINT_CONFIG, so serve and the in-container
# operator commands (login/seal/invite) need no --config.
ENV MINT_CONFIG=/app/mint.toml
EXPOSE 8085
CMD ["mint", "serve"]
