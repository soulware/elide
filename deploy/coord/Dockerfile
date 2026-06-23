# Elide coordinator container image for Fly.io.
#
# Stage 1 builds the elide binaries — the coordinator daemon, the `elide`
# volume/CLI binary (it opens /dev/ublk-control and carries login/enroll), and
# elide-import — from a pinned source ref. Stage 2 assembles the runtime image,
# loads `ublk_drv`, and runs `elide-coordinator serve` over coord.toml.
#
# Build args:
#   ELIDE_REF    elide commit/tag/branch to build.
#   DATA_BUCKET  the Tigris data bucket (must equal mint's DATA_BUCKET); baked
#                into coord.toml [store].bucket.
#   MINT_APP     the mint Fly app this coordinator enrols against; baked into
#                coord.toml [mint].url.

ARG ELIDE_REF=main

FROM ubuntu:24.04 AS build
ARG ELIDE_REF
# Rust via rustup (edition 2024 needs a recent toolchain); build-essential
# supplies the C compiler the ublk/io-uring deps need. `ublk` is a default
# feature, so a plain build links it on Linux.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git build-essential \
 && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  | sh -s -- -y --profile minimal --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"
RUN git clone https://github.com/soulware/elide /src \
 && git -C /src checkout "${ELIDE_REF}" \
 && cargo build --release --manifest-path /src/Cargo.toml \
      -p elide -p elide-coordinator -p elide-import

FROM ubuntu:24.04
# kmod for `modprobe ublk_drv`; ca-certificates for HTTPS to Tigris.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates kmod \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# The three binaries share a directory: the coordinator spawns `elide` and
# `elide-import` as siblings of itself.
COPY --from=build /src/target/release/elide-coordinator /usr/local/bin/
COPY --from=build /src/target/release/elide /usr/local/bin/
COPY --from=build /src/target/release/elide-import /usr/local/bin/
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

CMD ["sh", "/usr/local/bin/entrypoint.sh"]
