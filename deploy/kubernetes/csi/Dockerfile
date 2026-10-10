# SPDX-License-Identifier: CC-BY-NC-SA-4.0
# Build the Kagi NBD frontend and CSI gRPC service into one node-capable image.
FROM rust:1-bookworm AS rust-build
RUN apt-get update && apt-get install -y --no-install-recommends cmake pkg-config perl build-essential && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY vendor ./vendor
RUN cargo build --release --locked --bin kagi-volume-nbd

FROM golang:1.24-bookworm AS go-build
WORKDIR /src
COPY deploy/kubernetes/csi/go.mod ./
RUN go mod download
COPY deploy/kubernetes/csi/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/kagi-csi .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates nbd-client e2fsprogs util-linux kmod && rm -rf /var/lib/apt/lists/*
COPY --from=rust-build /src/target/release/kagi-volume-nbd /usr/local/bin/kagi-volume-nbd
COPY --from=go-build /out/kagi-csi /usr/local/bin/kagi-csi
ENTRYPOINT ["/usr/local/bin/kagi-csi"]
