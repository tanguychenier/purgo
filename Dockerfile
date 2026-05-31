# Build environment for purgo.
#
# Everything heavy (nightly toolchain, cargo-fuzz, wasm targets) lives in this
# image so that nothing is ever installed on the host. The image is pinned to a
# specific stable Rust release for reproducible builds; nightly is added on top
# because cargo-fuzz requires it.
FROM rust:1.96-bookworm

# cargo-fuzz builds instrumented binaries with libFuzzer (clang/llvm) and needs
# the linker toolchain present.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        lld \
        cmake \
    && rm -rf /var/lib/apt/lists/*

# Stable toolchain. The base image ships a version-pinned toolchain (1.96.0),
# but the project's rust-toolchain.toml pins `channel = "stable"`, which rustup
# treats as a distinct, on-demand channel. We install the `stable` channel
# explicitly here so the override is satisfied entirely from this image (no
# per-invocation download), and add the lint/format components plus the wasm
# target to it.
RUN rustup toolchain install stable --profile minimal --component clippy --component rustfmt \
    && rustup target add --toolchain stable wasm32-unknown-unknown \
    && rustup default stable

# Nightly toolchain (minimal profile) for cargo-fuzz. rust-src is required so
# fuzz builds can recompile std with sanitizer instrumentation (-Z build-std),
# and we add the wasm target on nightly as well.
RUN rustup toolchain install nightly --profile minimal --component rust-src \
    && rustup target add --toolchain nightly wasm32-unknown-unknown

# cargo-fuzz drives libFuzzer-based fuzz targets.
RUN cargo install cargo-fuzz --locked

WORKDIR /work
