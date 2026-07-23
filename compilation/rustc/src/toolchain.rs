//! Builds the ZKFS1 toolchain bundle (`rustc`/`rust-lld` + sysroot rlibs)
//! from source on first use — the pinned riscv64gc rustc release, fetched
//! and sha256-verified from static.rust-lang.org, merged with a small
//! committed glibc runtime directory the caller provides. Ported from
//! `scripts/build-bundle.sh`/`bin/mkbundle.rs` into this crate so it's a
//! library call (`ensure_bundle`) rather than a separate manual shell
//! script + binary step — the same "fetch lazily, only when actually
//! needed, cache it" pattern `registry` uses for crates.io dependencies.

use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const VERSION: &str = "1.96.1";
const TARGET: &str = "riscv64gc-unknown-linux-gnu";
const RUSTC_SHA256: &str = "3d042a8cd09b46c471cf797b62fcddfe8c6297a2fda1bfe7e6da76c571e25fad";
const STD_SHA256: &str = "e8a42534bc507e2ea4094f04516462bc2f2e21a2a14d227b728310b3bebad601";

fn cache_dir() -> PathBuf {
    let base = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join(".cache/jurassic-sgx/toolchain")
}

fn download(url: &str) -> Vec<u8> {
    let mut body = Vec::new();
    ureq::get(url)
        .call()
        .unwrap_or_else(|e| panic!("download {url}: {e}"))
        .body_mut()
        .as_reader()
        .read_to_end(&mut body)
        .unwrap_or_else(|e| panic!("read body of {url}: {e}"));
    body
}

/// Download `url` into `dest` (skipped if already present) and verify its
/// sha256 matches `want`, refusing to proceed otherwise — the same
/// verify-before-trust discipline `build-bundle.sh` had, just in Rust.
fn fetch_verified(url: &str, want: &str, dest: &Path) {
    if !dest.is_file() {
        let body = download(url);
        std::fs::write(dest, &body).unwrap_or_else(|e| panic!("write {}: {e}", dest.display()));
    }
    let data = std::fs::read(dest).unwrap_or_else(|e| panic!("read {}: {e}", dest.display()));
    let got = hex::encode(Sha256::digest(&data));
    if got != want {
        panic!("sha256 mismatch for {}:\n  got  {got}\n  want {want}", dest.display());
    }
}

fn extract_tar_xz(archive: &Path, dest: &Path) {
    let compressed = std::fs::read(archive).unwrap_or_else(|e| panic!("read {}: {e}", archive.display()));
    let mut tar_bytes = Vec::new();
    lzma_rs::xz_decompress(&mut &compressed[..], &mut tar_bytes)
        .unwrap_or_else(|e| panic!("un-xz {}: {e:?}", archive.display()));
    tar::Archive::new(&tar_bytes[..])
        .unpack(dest)
        .unwrap_or_else(|e| panic!("untar {}: {e}", archive.display()));
}

fn copy_dir_all(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap_or_else(|e| panic!("create {}: {e}", dst.display()));
    for entry in std::fs::read_dir(src).unwrap_or_else(|e| panic!("read_dir {}: {e}", src.display())) {
        let entry = entry.unwrap();
        let dest_path = dst.join(entry.file_name());
        if entry.path().is_dir() {
            copy_dir_all(&entry.path(), &dest_path);
        } else {
            std::fs::copy(entry.path(), &dest_path)
                .unwrap_or_else(|e| panic!("copy {} -> {}: {e}", entry.path().display(), dest_path.display()));
        }
    }
}

/// Pack the merged toolchain directory + `glibc_dir` into ZKFS1 bytes —
/// the exact file list `bin/mkbundle.rs` packs, kept in sync with it (that
/// binary stays as a standalone CLI entry point for scripted/manual
/// rebuilds; this is the same logic reused for the automatic path).
fn pack(toolchain: &Path, glibc: &Path) -> Vec<u8> {
    let mut b = rvlinux::bundle::Builder::new();

    let tc_files = [
        ("bin/rustc", 0o755),
        ("lib/librustc_driver-50415e81ad01135f.so", 0o755),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/libcore-262ac8c5c52b8640.rlib", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/libcore-262ac8c5c52b8640.rmeta", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/liballoc-4eb3b6afe27cee19.rlib", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/liballoc-4eb3b6afe27cee19.rmeta", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/libcompiler_builtins-9efbfd211f15917a.rlib", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/libcompiler_builtins-9efbfd211f15917a.rmeta", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/librustc_std_workspace_core-0118aca45f05f0b9.rlib", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/librustc_std_workspace_core-0118aca45f05f0b9.rmeta", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/bin/rust-lld", 0o755),
    ];
    for (rel, mode) in tc_files {
        let data = std::fs::read(toolchain.join(rel))
            .unwrap_or_else(|e| panic!("missing toolchain file {rel}: {e}"));
        b.file(&format!("/opt/rust/{rel}"), data, mode);
    }

    for lib in [
        "ld-linux-riscv64-lp64d.so.1",
        "libc.so.6",
        "libdl.so.2",
        "libm.so.6",
        "libpthread.so.0",
        "libatomic.so.1",
        "libgcc_s.so.1",
        "librt.so.1",
    ] {
        let data = std::fs::read(glibc.join(lib)).unwrap_or_else(|e| panic!("missing glibc lib {lib}: {e}"));
        b.file(&format!("/usr/lib/riscv64-linux-gnu/{lib}"), data, 0o755);
    }
    b.symlink(
        "/lib/ld-linux-riscv64-lp64d.so.1",
        "/usr/lib/riscv64-linux-gnu/ld-linux-riscv64-lp64d.so.1",
    );

    b.build()
}

/// Fetch (sha256-verified) + extract + merge the pinned rustc/rust-std
/// riscv64gc release, then pack it with `glibc_dir` into ZKFS1 bytes.
/// Downloads are cached under `~/.cache/jurassic-sgx/toolchain`, keyed by
/// version+target, so this only actually hits the network once.
pub fn build_bundle(glibc_dir: &Path) -> Vec<u8> {
    let work = cache_dir().join(format!("{VERSION}-{TARGET}"));
    std::fs::create_dir_all(&work).unwrap_or_else(|e| panic!("create {}: {e}", work.display()));

    let rustc_tar = work.join("rustc.tar.xz");
    let std_tar = work.join("rust-std.tar.xz");
    eprintln!("fetching pinned rustc {VERSION} {TARGET} toolchain ...");
    fetch_verified(
        &format!("https://static.rust-lang.org/dist/rustc-{VERSION}-{TARGET}.tar.xz"),
        RUSTC_SHA256,
        &rustc_tar,
    );
    fetch_verified(
        &format!("https://static.rust-lang.org/dist/rust-std-{VERSION}-{TARGET}.tar.xz"),
        STD_SHA256,
        &std_tar,
    );

    let merged = work.join("merged");
    if !merged.join("bin/rustc").is_file() {
        let _ = std::fs::remove_dir_all(&merged);
        let extracted_rustc = work.join("x-rustc");
        let extracted_std = work.join("x-std");
        extract_tar_xz(&rustc_tar, &extracted_rustc);
        extract_tar_xz(&std_tar, &extracted_std);
        copy_dir_all(&extracted_rustc.join(format!("rustc-{VERSION}-{TARGET}/rustc")), &merged);
        copy_dir_all(&extracted_std.join(format!("rust-std-{VERSION}-{TARGET}/rust-std-{TARGET}")), &merged);
    }

    pack(&merged, glibc_dir)
}

/// Return the toolchain bundle bytes at `bundle_path`, building it from
/// source (see `build_bundle`) and caching the result there if it doesn't
/// exist yet.
pub fn ensure_bundle(bundle_path: &Path, glibc_dir: &Path) -> Vec<u8> {
    if let Ok(bytes) = std::fs::read(bundle_path) {
        return bytes;
    }
    eprintln!(
        "no toolchain bundle at {} — building it from source (one-time, ~500MB download+build)",
        bundle_path.display()
    );
    let bytes = build_bundle(glibc_dir);
    if let Some(parent) = bundle_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(bundle_path, &bytes).unwrap_or_else(|e| panic!("write {}: {e}", bundle_path.display()));
    eprintln!(
        "wrote {}: {} bytes ({} MiB)",
        bundle_path.display(),
        bytes.len(),
        bytes.len() / 1024 / 1024
    );
    bytes
}
