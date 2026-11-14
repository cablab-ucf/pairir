#!/bin/sh
# dist/: the site, for any static host. Needs rust-toolchain.toml's
# toolchain (rustup fetches it) and wasm-bindgen-cli at Cargo.lock's version.
# Reproducible: no path of this machine in the wasm, so a commit builds to
# the same SHA256SUMS anywhere.
set -eu
cd "$(dirname "$0")"
export LC_ALL=C RUSTFLAGS="--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$(cd .. && pwd)=/pairir"
cargo build --profile web --locked --target wasm32-unknown-unknown
rm -rf dist
cp -r www dist
wasm-bindgen --target web --no-typescript --out-dir dist/pkg \
  ../target/wasm32-unknown-unknown/web/pairir_web.wasm
# Publish these apart from the site (a signed tag or release): anyone can
# rebuild the commit and check what a host serves.
(cd dist && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS)
cat dist/SHA256SUMS
