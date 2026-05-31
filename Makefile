.PHONY: image build test test-sandbox fuzz-corpus lint fmt fmt-check fuzz audit all

# Everything runs inside the purgo-dev container via ./x, so nothing heavy is
# ever installed on the host. Build the image once with `make image`.
all: fmt-check lint test test-sandbox fuzz-corpus

image:
	docker build -t purgo-dev:latest .

build:
	./x cargo build --workspace

test:
	./x cargo test --workspace

# Prove the disarming really travels through the WASM sandbox. The `sandbox`
# feature is off by default (it pulls in wasmtime), so the workspace `test`
# target never builds it — this one does, and the test itself rebuilds the
# guest for wasm32-unknown-unknown (present in the image).
test-sandbox:
	./x cargo test -p purgo-adapters --features sandbox

# Anchor the "parser never panics on hostile input" invariant in the gate.
# First build every fuzz target under the instrumented toolchain (this catches
# any drift in the harness or the adapter ABI even on a fresh checkout where the
# corpus — which is generated and git-ignored — is absent). Then replay whatever
# corpus is present deterministically (no new discovery, -runs=0), time-bounded
# and offline; nightly + cargo-fuzz live in the image.
fuzz-corpus:
	./x cargo +nightly fuzz build
	./x cargo +nightly fuzz run jpeg  -- -runs=0 -max_total_time=30 fuzz/corpus/jpeg
	./x cargo +nightly fuzz run png   -- -runs=0 -max_total_time=30 fuzz/corpus/png
	./x cargo +nightly fuzz run pdf   -- -runs=0 -max_total_time=30 fuzz/corpus/pdf
	./x cargo +nightly fuzz run ooxml -- -runs=0 -max_total_time=30 fuzz/corpus/ooxml

lint:
	./x cargo clippy --workspace --all-targets -- -D warnings

fmt:
	./x cargo fmt --all

fmt-check:
	./x cargo fmt --all -- --check

# Run a fuzz target, e.g. `make fuzz TARGET=jpeg`. Requires fuzz targets under
# fuzz/ (cargo-fuzz lives in the image, nightly is used automatically).
fuzz:
	./x cargo +nightly fuzz run $(TARGET)

# Supply-chain advisory scan (cargo-audit must be available in the image).
audit:
	./x cargo audit
