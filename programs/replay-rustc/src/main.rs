//! replay-rustc: in-enclave verifiable compilation.
//!
//!   enroll                    → emit enrollment proof on stdout
//!   compile <hex-source>      → run the REAL rustc + rust-lld compile inside
//!                               the rvlinux emulator over a rootfs bundle read
//!                               from stdin, then emit a signed Envelope whose
//!                               payload (CompilationPublicValues) binds
//!                               source → object → binary.
//!   compute <hex-transcript>  → (legacy) selective transcript replay.
//!
//! `compile` is pure computation (the emulator is no_std+alloc), so it runs on
//! `x86_64-fortanix-unknown-sgx`. The large toolchain bundle arrives on stdin;
//! the small source arrives as a hex argv so the Envelope stays small. Because
//! the enclave re-executes the compile itself, a wrong source cannot be bound
//! to a given binary.

use std::io::Read;

use attestations::core::sha256;
use attestations::replay::replay;
use attestations::transcript::Transcript;
use wrapped_rustc_lib::{argv_bytes, CompilationPublicValues};

const PROGRAM_NAME: &str = "replay-rustc";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("compile");

    match mode {
        "enroll" => attestations::enclave::enroll(PROGRAM_NAME),
        "compile" => compile_mode(args.get(2).cloned().unwrap_or_default()),
        "compute" => {
            let hex_transcript = args.get(2).cloned().unwrap_or_default();
            let transcript_bytes = hex::decode(hex_transcript.trim())
                .expect("transcript arg must be hex-encoded JSON");
            attestations::enclave::commit_with_input(PROGRAM_NAME, transcript_bytes, |input| {
                let transcript: Transcript =
                    serde_json::from_slice(input).expect("deserialize transcript");
                let report = replay(&transcript);
                serde_json::to_vec(&report).expect("serialize replay report")
            });
        }
        other => {
            eprintln!(
                "unknown mode: {} (expected: enroll | compile <hex-source> | compute <hex-transcript>)",
                other
            );
            std::process::exit(2);
        }
    }
}

/// Read the toolchain bundle from stdin, run the real rustc→rust-lld→run
/// pipeline inside the emulator over `source`, and emit a signed Envelope
/// committing the CompilationPublicValues (source→binary binding).
fn compile_mode(source_hex: String) {
    let source = hex::decode(source_hex.trim()).expect("source must be hex-encoded");
    let mut bundle = Vec::new();
    std::io::stdin().read_to_end(&mut bundle).expect("read bundle from stdin");

    // Hash + unpack the toolchain, then free the raw bundle before compiling so
    // the enclave's peak working set stays as small as possible (EPC is scarce).
    let bundle_sha256 = sha256(&bundle);
    let mut fs = rvlinux::fs::Fs::new();
    rvlinux::bundle::parse_into(&mut fs, &bundle).expect("parse bundle");
    drop(bundle);

    attestations::enclave::commit_with_input(PROGRAM_NAME, source, move |source| {
        let rustc_argv = rvlinux::pipeline::default_rustc_argv();
        let lld_argv = rvlinux::pipeline::default_lld_argv();
        let envp = rvlinux::pipeline::default_envp();

        // Live progress bar on stderr (stdout carries the envelope). Runs on
        // the SGX server so you can watch the compile advance under EPC paging.
        let mut last_stage = String::new();
        let res = rvlinux::pipeline::compile_link_run_reporting(
            fs, source, &rustc_argv, &lld_argv, &envp, 0,
            &mut |stage, instret| draw_progress(&mut last_stage, stage, instret),
        )
        .expect("compile pipeline failed");
        eprintln!(); // finish the last bar line

        let pv = CompilationPublicValues {
            bundle_sha256,
            source_sha256: sha256(source),
            rustc_argv_sha256: sha256(&argv_bytes(&rustc_argv)),
            lld_argv_sha256: sha256(&argv_bytes(&lld_argv)),
            obj_sha256: sha256(&res.obj),
            bin_sha256: sha256(&res.bin),
            stdout_sha256: sha256(&res.run.stdout),
            rustc_exit: res.rustc.exit_code,
            lld_exit: res.lld.exit_code,
            run_exit: res.run.exit_code,
            rustc_instret: res.rustc.instret,
            lld_instret: res.lld.instret,
            run_instret: res.run.instret,
        };
        serde_json::to_vec(&pv).expect("serialize public values")
    });
}

/// Draw a per-stage progress bar to stderr, overwriting one line with `\r`.
/// Percentages are against rough per-stage instruction estimates — enough to
/// watch the compile advance (esp. under slow EPC paging on SGX); each stage
/// starts on a fresh line.
fn draw_progress(last_stage: &mut String, stage: &str, instret: u64) {
    use std::io::Write as _;
    if stage != last_stage {
        if !last_stage.is_empty() {
            eprintln!();
        }
        *last_stage = stage.to_string();
    }
    let est: u64 = match stage {
        "rustc" => 60_000_000,
        "rust-lld" => 17_000_000,
        _ => 1_000_000,
    };
    let pct = core::cmp::min(99, instret.saturating_mul(100) / est.max(1));
    let filled = (pct / 5) as usize; // 20-cell bar
    let bar: String = core::iter::repeat('#')
        .take(filled)
        .chain(core::iter::repeat('.').take(20 - filled))
        .collect();
    eprint!("\r  [{:<8}] [{}] {:>2}%  {:>4}M instr", stage, bar, pct, instret / 1_000_000);
    let _ = std::io::stderr().flush();
}
