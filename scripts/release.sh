#!/usr/bin/env bash
#
# Builds the Linux release artifacts into dist/.
#
#   scripts/release.sh            # both architectures
#   scripts/release.sh x86_64     # just one
#
# Statically linked against musl, so one binary per architecture runs on any
# distribution — no glibc version to match, nothing to install alongside it.
# `ring` and `mimalloc` compile C, so this needs a C cross-toolchain and not
# merely a rustup target:
#
#   rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#   brew tap messense/macos-cross-toolchains
#   brew install x86_64-unknown-linux-musl aarch64-unknown-linux-musl
#
# On Linux the native toolchain already covers the host architecture; the
# linker names in .cargo/config.toml are what these packages provide.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

VERSION=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
WANT="${1:-all}"
OUT=dist
mkdir -p "$OUT"

build() {
    local arch="$1" target="$2" prefix="$3"
    if [ "$WANT" != "all" ] && [ "$WANT" != "$arch" ]; then
        return 0
    fi
    echo "==> $target"

    # cc-rs looks for these per-target; without them it reaches for the host
    # compiler and produces objects the target linker will not take.
    local up="${target//-/_}"
    export "CC_${up}=${prefix}-gcc"
    export "AR_${up}=${prefix}-ar"

    cargo build --release --target "$target"

    local bin="target/$target/release/oxiserve"
    "${prefix}-strip" "$bin"

    # Staged in a versioned directory so the tarball unpacks into one place
    # rather than scattering files over the current directory.
    local name="oxiserve-${VERSION}-linux-${arch}"
    local stage="$OUT/$name"
    rm -rf "$stage"
    mkdir -p "$stage/conf/examples"
    cp "$bin" "$stage/oxiserve"
    cp README.md "$stage/"
    cp conf/oxiserve.conf "$stage/conf/"
    cp conf/examples/*.conf conf/examples/README.md "$stage/conf/examples/"

    tar -czf "$OUT/$name.tar.gz" -C "$OUT" "$name"
    rm -rf "$stage"
    echo "    $OUT/$name.tar.gz  ($(du -h "$OUT/$name.tar.gz" | cut -f1))"
}

build x86_64  x86_64-unknown-linux-musl  x86_64-linux-musl
build aarch64 aarch64-unknown-linux-musl aarch64-linux-musl

# One checksum file for the whole release, which is what `sha256sum -c` wants.
( cd "$OUT" && shasum -a 256 ./*.tar.gz > SHA256SUMS )
echo "==> $OUT/SHA256SUMS"
cat "$OUT/SHA256SUMS"
