FROM rust:1 AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p qqrm-cargo-warden -p qqrm-agent-lite

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbpf-dev bpftool ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/cargo-warden /usr/local/bin/
COPY --from=build /src/target/release/qqrm-agent-lite /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/cargo-warden"]
