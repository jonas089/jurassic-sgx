//! Build the ZKFS1 rootfs bundle the enclave compiles against.
//!
//! Usage: mkbundle <merged-toolchain-dir> <glibc-dir> <out.zkfs>
//!
//! Packs only the ~17 files rustc + rust-lld actually touch (the file-name
//! hash suffixes are those of the pinned rustc 1.96.1 riscv64gc release), plus
//! the Debian-sid riscv64 glibc runtime. Ported from the verifiable-compilation
//! repo so the bundle can be rebuilt from source here.

use sha2::{Digest, Sha256};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [toolchain, glibc, out] = &args[..] else {
        eprintln!("usage: mkbundle <toolchain-dir> <glibc-dir> <out.zkfs>");
        std::process::exit(2);
    };

    let mut b = rvlinux::bundle::Builder::new();

    let tc_files = [
        ("bin/rustc", 0o755),
        ("lib/librustc_driver-50415e81ad01135f.so", 0o755),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/libcore-262ac8c5c52b8640.rlib", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/libcore-262ac8c5c52b8640.rmeta", 0o644),
        // liballoc: closes the no_std heap gap (Vec/Box/String/...). It's a
        // sysroot crate like libcore — rustc finds it via --sysroot inference
        // from its own path, so `extern crate alloc;` needs no --extern flag.
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/liballoc-4eb3b6afe27cee19.rlib", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/liballoc-4eb3b6afe27cee19.rmeta", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/libcompiler_builtins-9efbfd211f15917a.rlib", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/libcompiler_builtins-9efbfd211f15917a.rmeta", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/librustc_std_workspace_core-0118aca45f05f0b9.rlib", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/lib/librustc_std_workspace_core-0118aca45f05f0b9.rmeta", 0o644),
        ("lib/rustlib/riscv64gc-unknown-linux-gnu/bin/rust-lld", 0o755),
    ];
    for (rel, mode) in tc_files {
        let data = std::fs::read(format!("{toolchain}/{rel}"))
            .unwrap_or_else(|e| { eprintln!("missing toolchain file {rel}: {e}"); std::process::exit(1); });
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
        let data = std::fs::read(format!("{glibc}/{lib}"))
            .unwrap_or_else(|e| { eprintln!("missing glibc lib {lib}: {e}"); std::process::exit(1); });
        b.file(&format!("/usr/lib/riscv64-linux-gnu/{lib}"), data, 0o755);
    }
    b.symlink(
        "/lib/ld-linux-riscv64-lp64d.so.1",
        "/usr/lib/riscv64-linux-gnu/ld-linux-riscv64-lp64d.so.1",
    );

    let bytes = b.build();
    let hash = hex::encode(Sha256::digest(&bytes));
    std::fs::write(out, &bytes).unwrap();
    println!("wrote {out}: {} bytes ({} MiB), sha256 = {hash}", bytes.len(), bytes.len() / 1024 / 1024);
}
