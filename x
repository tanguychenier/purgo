#!/usr/bin/env bash
# Run any command inside the purgo-dev build container.
#
# The project tree is bind-mounted at /work; build outputs and the cargo
# caches live in named volumes so nothing is written to the host and rebuilds
# stay fast across invocations. Nothing heavy is ever installed on the host:
# `./x cargo ...`, `./x rustup ...`, `./x cargo +nightly fuzz ...`, etc.
set -euo pipefail

# Interactive TTY only when one is attached (keeps the wrapper usable in CI).
tty_flag=()
if [ -t 0 ]; then
  tty_flag=(-t)
fi

docker run --rm "${tty_flag[@]}" \
  -v "$(pwd)":/work -w /work \
  -v purgo-target:/work/target \
  -v purgo-fuzz-target:/work/fuzz/target \
  -v purgo-cargo-registry:/usr/local/cargo/registry \
  -v purgo-cargo-git:/usr/local/cargo/git \
  purgo-dev:latest "$@"
