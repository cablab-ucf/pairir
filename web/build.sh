#!/bin/sh
# dist/: the site, for any static host. Needs the wasm32-unknown-unknown
# target and wasm-bindgen-cli at the version in Cargo.lock.
set -eu
cd "$(dirname "$0")"
cargo build --release --locked --target wasm32-unknown-unknown
rm -rf dist
cp -r www dist
wasm-bindgen --target web --no-typescript --out-dir dist/pkg \
  target/wasm32-unknown-unknown/release/pairir_web.wasm
# Publish these so a visitor can check what they were served.
(cd dist && find . -type f ! -name SHA256SUMS | sort | xargs sha256sum > SHA256SUMS)
cat dist/SHA256SUMS
