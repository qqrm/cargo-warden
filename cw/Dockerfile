FROM rust:nightly AS build
WORKDIR /src
COPY . .
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libseccomp-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*
RUN cargo build --release -p cargo-warden -p warden-agent-lite

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf-dev \
    bpftool \
    ca-certificates \
    libseccomp2 \
  && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/cargo-warden /usr/local/bin/
COPY --from=build /src/target/release/warden-agent-lite /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/cargo-warden"]
