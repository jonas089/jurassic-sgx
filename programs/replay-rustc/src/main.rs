//! replay-rustc: in-enclave verifiable compilation.
//!
//!   enroll                    → emit enrollment proof on stdout
//!   compile <hex-source>      → run the REAL rustc + rust-lld compile inside
//!                               the rvlinux emulator over a rootfs bundle read
//!                               from stdin, then emit a signed Envelope whose
//!                               payload (CompilationPublicValues) binds
//!                               source → object → binary.
//!   compile-workspace <hex-plan> <port>
//!                             → same, but for a multi-crate workspace: the
//!                               CLI sends the toolchain bundle *and* the
//!                               packed source tree over the socket, and a
//!                               `BuildPlanDto` (which local crates to
//!                               compile, in order, and how they `--extern`
//!                               on each other) as the hex argv. The enclave
//!                               executes exactly that plan and signs a
//!                               WorkspacePublicValues committing to it.
//!
//! `compile` is pure computation (the emulator is no_std+alloc), so it runs on
//! `x86_64-fortanix-unknown-sgx`. The large toolchain bundle arrives on stdin;
//! the small source arrives as a hex argv so the Envelope stays small. Because
//! the enclave re-executes the compile itself, a wrong source cannot be bound
//! to a given binary.

use std::io::Read;
use std::net::{SocketAddr, TcpStream};

use attestations::core::sha256;
use compilation_rustc::public_values::{
    BuildPlanDto, CompilationPublicValues, PlanCrateType, UnitPublicValues, WorkspacePublicValues,
};
use compilation_rustc::argv_bytes;

const PROGRAM_NAME: &str = "replay-rustc";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("compile");

    match mode {
        "enroll" => attestations::enclave::enroll(PROGRAM_NAME),
        "compile" => compile_mode(
            args.get(2).cloned().unwrap_or_default(),
            args.get(3).cloned().unwrap_or_default(),
        ),
        "compile-workspace" => compile_workspace_mode(
            args.get(2).cloned().unwrap_or_default(),
            args.get(3).cloned().unwrap_or_default(),
        ),
        other => {
            eprintln!(
                "unknown mode: {} (expected: enroll | compile <hex-source> | \
                 compile-workspace <hex-plan> <port>)",
                other
            );
            std::process::exit(2);
        }
    }
}

/// Fetch the toolchain bundle over a localhost TCP socket (the CLI serves it),
/// run the real rustc→rust-lld→run pipeline inside the emulator over `source`,
/// and emit a signed Envelope committing the CompilationPublicValues
/// (source→binary binding).
///
/// TCP is used instead of stdin because it reliably streams the ~471 MB bundle
/// into an SGX enclave (a first-class EDP usercall), and `read_exact` fails
/// loudly on any short delivery rather than silently truncating.
fn compile_mode(source_hex: String, port_str: String) {
    let source = hex::decode(source_hex.trim()).expect("source must be hex-encoded");
    let port: u16 = port_str.trim().parse().expect("bundle server port (argv[3])");

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect(addr).expect("connect to bundle server");
    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf).expect("read bundle length");
    let len = u64::from_le_bytes(len_buf) as usize;
    let mut bundle = vec![0u8; len];
    stream.read_exact(&mut bundle).expect("read bundle body (short delivery)");
    eprintln!("[bundle] received {} bytes over tcp", bundle.len());

    // Hash + unpack the toolchain, then free the raw bundle before compiling so
    // the enclave's peak working set stays as small as possible (EPC is scarce).
    let bundle_sha256 = sha256(&bundle);
    let mut fs = rvlinux::fs::Fs::new();
    rvlinux::bundle::parse_into(&mut fs, &bundle).expect("parse bundle");
    drop(bundle);

    attestations::enclave::commit_with_input(PROGRAM_NAME, source, move |source| {
        let rustc_argv = compilation_rustc::pipeline::default_rustc_argv();
        let lld_argv = compilation_rustc::pipeline::default_lld_argv();
        let envp = compilation_rustc::pipeline::default_envp();

        // Live progress bar on stderr (stdout carries the envelope). Runs on
        // the SGX server so you can watch the compile advance under EPC paging.
        let mut last_stage = String::new();
        let res = compilation_rustc::pipeline::compile_link_run_reporting(
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

/// Read one `[u64 len][body]` length-prefixed blob off `stream`.
fn read_len_prefixed(stream: &mut TcpStream) -> Vec<u8> {
    let mut len_buf = [0u8; 8];
    stream.read_exact(&mut len_buf).expect("read length prefix");
    let len = u64::from_le_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).expect("read body (short delivery)");
    buf
}

/// Same as [`compile_mode`], but for a multi-crate workspace: the CLI sends
/// the toolchain bundle *and* the packed source tree over the same socket
/// (two length-prefixed blobs), and the build plan (which local crates to
/// compile, in order, and their `--extern` wiring) as the hex argv. The
/// enclave commits to `plan_sha256` (== the signed Envelope's `input_hash`,
/// since the plan bytes are exactly what gets passed to `commit_with_input`)
/// so a verifier can recover and inspect the exact plan that ran.
fn compile_workspace_mode(plan_hex: String, port_str: String) {
    let plan_json = hex::decode(plan_hex.trim()).expect("plan must be hex-encoded JSON");
    let port: u16 = port_str.trim().parse().expect("bundle server port (argv[3])");

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect(addr).expect("connect to bundle server");
    let bundle = read_len_prefixed(&mut stream);
    eprintln!("[bundle] received {} bytes over tcp", bundle.len());
    let tree = read_len_prefixed(&mut stream);
    eprintln!("[source-tree] received {} bytes over tcp", tree.len());

    let bundle_sha256 = sha256(&bundle);
    let source_tree_sha256 = sha256(&tree);

    let mut fs = rvlinux::fs::Fs::new();
    rvlinux::bundle::parse_into(&mut fs, &bundle).expect("parse toolchain bundle");
    rvlinux::bundle::parse_into(&mut fs, &tree).expect("parse source tree bundle");
    drop(bundle);
    drop(tree);

    let dto: BuildPlanDto = serde_json::from_slice(&plan_json).expect("parse build plan json");
    let plan = compilation_rustc::pipeline::BuildPlan::from(&dto);

    attestations::enclave::commit_with_input(PROGRAM_NAME, plan_json, move |plan_json| {
        let plan_sha256 = sha256(plan_json);
        let envp = compilation_rustc::pipeline::default_envp();

        let mut last_stage = String::new();
        let res = match compilation_rustc::pipeline::compile_workspace_run_reporting(
            fs, &plan, &envp, 0,
            &mut |stage, instret| draw_progress(&mut last_stage, stage, instret),
        ) {
            Ok(r) => r,
            Err(e) => {
                eprintln!();
                match e {
                    compilation_rustc::pipeline::WorkspaceError::UnitFailed { unit, exit_code, stderr } => {
                        eprintln!(
                            "crate `{unit}` failed to compile (exit {exit_code}):\n{}",
                            String::from_utf8_lossy(&stderr)
                        );
                    }
                    compilation_rustc::pipeline::WorkspaceError::LinkFailed { exit_code, stderr } => {
                        eprintln!(
                            "linking failed (exit {exit_code}):\n{}",
                            String::from_utf8_lossy(&stderr)
                        );
                    }
                    other => eprintln!("workspace compile pipeline failed: {other:?}"),
                }
                std::process::exit(1);
            }
        };
        eprintln!(); // finish the last bar line

        let units: Vec<UnitPublicValues> = res
            .units
            .iter()
            .map(|u| UnitPublicValues {
                name: u.name.clone(),
                crate_type: match u.crate_type {
                    compilation_rustc::pipeline::CrateType::Lib => PlanCrateType::Lib,
                    compilation_rustc::pipeline::CrateType::Bin => PlanCrateType::Bin,
                },
                externs: u.externs.clone(),
                argv_sha256: sha256(&argv_bytes(&u.argv)),
                artifact_sha256: sha256(&u.artifact),
                exit_code: u.stage.exit_code,
                instret: u.stage.instret,
            })
            .collect();

        let pv = WorkspacePublicValues {
            bundle_sha256,
            source_tree_sha256,
            plan_sha256,
            units,
            link_argv_sha256: sha256(&argv_bytes(&res.link_argv)),
            bin_sha256: sha256(&res.bin),
            stdout_sha256: sha256(&res.run.stdout),
            link_exit: res.link.exit_code,
            run_exit: res.run.exit_code,
            link_instret: res.link.instret,
            run_instret: res.run.instret,
        };
        serde_json::to_vec(&pv).expect("serialize workspace public values")
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
