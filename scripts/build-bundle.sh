#!/usr/bin/env bash
# Build the riscv64 toolchain bundle (fixtures/rootfs.zkfs) from source:
# download the pinned rustc 1.96.1 riscv64 toolchain from static.rust-lang.org
# (sha256-verified), merge it with the committed glibc runtime, and pack it with
# mkbundle. No 471MB blob in git — only the ~2MB glibc + this script.
set -euo pipefail
cd "$(dirname "$0")/.."

VER=1.96.1
TGT=riscv64gc-unknown-linux-gnu
RUSTC_SHA=3d042a8cd09b46c471cf797b62fcddfe8c6297a2fda1bfe7e6da76c571e25fad
STD_SHA=e8a42534bc507e2ea4094f04516462bc2f2e21a2a14d227b728310b3bebad601
WORK=build/bundle-src
GLIBC=fixtures/glibc
OUT=fixtures/rootfs.zkfs

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
mkdir -p "$WORK"

fetch() { # url sha out
  if [ ! -f "$3" ]; then echo "  downloading $(basename "$3") ..."; curl -fL --retry 3 "$1" -o "$3"; fi
  got=$(sha256 "$3"); [ "$got" = "$2" ] || { echo "SHA mismatch for $3:"; echo "  got  $got"; echo "  want $2"; exit 1; }
  echo "  verified $(basename "$3")"
}

echo "== 1/3 fetch pinned rustc $VER $TGT toolchain =="
fetch "https://static.rust-lang.org/dist/rustc-$VER-$TGT.tar.xz"    "$RUSTC_SHA" "$WORK/rustc.tar.xz"
fetch "https://static.rust-lang.org/dist/rust-std-$VER-$TGT.tar.xz" "$STD_SHA"   "$WORK/rust-std.tar.xz"

echo "== 2/3 extract + merge toolchain =="
rm -rf "$WORK/x" "$WORK/merged"; mkdir -p "$WORK/x" "$WORK/merged"
tar -C "$WORK/x" -xf "$WORK/rustc.tar.xz"
tar -C "$WORK/x" -xf "$WORK/rust-std.tar.xz"
cp -a "$WORK/x/rustc-$VER-$TGT/rustc/."          "$WORK/merged/"
cp -a "$WORK/x/rust-std-$VER-$TGT/rust-std-$TGT/." "$WORK/merged/"

echo "== 3/3 pack bundle (toolchain + committed glibc) =="
cargo run --release --quiet --bin mkbundle -- "$WORK/merged" "$GLIBC" "$OUT"
echo "done -> $OUT"
