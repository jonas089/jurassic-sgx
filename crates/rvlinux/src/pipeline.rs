//! The verifiable compilation pipeline: rustc -> rust-lld -> run the result.
//! Shared verbatim between the host runner and the SP1 guest so both compute
//! the exact same thing.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::fs::{Fs, Node};
use crate::{Machine, RunError};

pub const SOURCE_PATH: &str = "/work/hello.rs";
pub const OBJ_PATH: &str = "/work/hello.o";
pub const BIN_PATH: &str = "/work/hello";

pub fn default_rustc_argv() -> Vec<String> {
    [
        "/opt/rust/bin/rustc",
        "--edition",
        "2024",
        "-O",
        "-C",
        "panic=abort",
        "-C",
        "codegen-units=1",
        "--emit=obj",
        "hello.rs",
        "-o",
        "hello.o",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn default_lld_argv() -> Vec<String> {
    [
        "/opt/rust/lib/rustlib/riscv64gc-unknown-linux-gnu/bin/rust-lld",
        "-flavor",
        "gnu",
        "-static",
        "-e",
        "_start",
        "hello.o",
        "-o",
        "hello",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

pub fn default_envp() -> Vec<String> {
    ["PATH=/usr/bin:/bin", "HOME=/root", "TERM=dumb"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

pub struct StageResult {
    pub exit_code: i32,
    pub instret: u64,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub struct PipelineResult {
    pub rustc: StageResult,
    pub lld: StageResult,
    pub run: StageResult,
    pub obj: Vec<u8>,
    pub bin: Vec<u8>,
    pub total_instret: u64,
}

#[derive(Debug)]
pub enum PipelineError {
    Emulator(&'static str, RunError),
    StageFailed(&'static str, i32),
    MissingArtifact(&'static str),
}

/// Add the /proc, /tmp etc. stubs every stage needs.
pub fn add_std_stubs(fs: &mut Fs, exe: &str) {
    fs.mkdir_all("/work");
    fs.mkdir_all("/tmp");
    fs.mkdir_all("/dev/shm");
    fs.add_symlink("/proc/self/exe", exe);
    fs.add_file("/proc/self/maps", Vec::new(), 0o444);
    fs.add_file(
        "/proc/self/statm",
        b"1000 500 300 50 0 400 0\n".to_vec(),
        0o444,
    );
}

fn run_stage(
    mut fs: Fs,
    argv: &[String],
    envp: &[String],
    name: &'static str,
    max_instret: u64,
) -> Result<(Fs, StageResult), PipelineError> {
    add_std_stubs(&mut fs, &argv[0]);
    let mut m = Machine::new(fs, "/work");
    m.load_program(&argv[0], argv, envp)
        .map_err(|e| PipelineError::Emulator(name, e))?;
    let out = m
        .run(max_instret)
        .map_err(|e| PipelineError::Emulator(name, e))?;
    let res = StageResult {
        exit_code: out.exit_code,
        instret: out.instret,
        stdout: core::mem::take(&mut m.stdout),
        stderr: core::mem::take(&mut m.stderr),
    };
    Ok((m.into_fs(), res))
}

fn read_file(fs: &Fs, path: &str) -> Option<Vec<u8>> {
    let resolved = fs.resolve(path, true).ok()?;
    match fs.get(&resolved) {
        Some(Node::File { data, .. }) => Some(data.bytes().to_vec()),
        _ => None,
    }
}

fn run_stage_reporting(
    mut fs: Fs,
    argv: &[String],
    envp: &[String],
    name: &'static str,
    max_instret: u64,
    on_progress: &mut dyn FnMut(&str, u64),
) -> Result<(Fs, StageResult), PipelineError> {
    add_std_stubs(&mut fs, &argv[0]);
    let mut m = Machine::new(fs, "/work");
    m.load_program(&argv[0], argv, envp)
        .map_err(|e| PipelineError::Emulator(name, e))?;
    let out = m
        .run_reporting(max_instret, 1_000_000, &mut |instret| on_progress(name, instret))
        .map_err(|e| PipelineError::Emulator(name, e))?;
    let res = StageResult {
        exit_code: out.exit_code,
        instret: out.instret,
        stdout: core::mem::take(&mut m.stdout),
        stderr: core::mem::take(&mut m.stderr),
    };
    Ok((m.into_fs(), res))
}

/// Same as [`compile_link_run`], but report progress per stage via
/// `on_progress(stage_name, instret)`. Byte-identical results to
/// `compile_link_run` (reporting does not affect execution).
pub fn compile_link_run_reporting(
    mut fs: Fs,
    source: &[u8],
    rustc_argv: &[String],
    lld_argv: &[String],
    envp: &[String],
    max_instret_per_stage: u64,
    on_progress: &mut dyn FnMut(&str, u64),
) -> Result<PipelineResult, PipelineError> {
    fs.add_file(SOURCE_PATH, source.to_vec(), 0o644);

    let (fs, rustc_res) = run_stage_reporting(fs, rustc_argv, envp, "rustc", max_instret_per_stage, on_progress)?;
    if rustc_res.exit_code != 0 {
        return Err(PipelineError::StageFailed("rustc", rustc_res.exit_code));
    }
    let obj = read_file(&fs, OBJ_PATH).ok_or(PipelineError::MissingArtifact("hello.o"))?;

    let (fs, lld_res) = run_stage_reporting(fs, lld_argv, envp, "rust-lld", max_instret_per_stage, on_progress)?;
    if lld_res.exit_code != 0 {
        return Err(PipelineError::StageFailed("rust-lld", lld_res.exit_code));
    }
    let bin = read_file(&fs, BIN_PATH).ok_or(PipelineError::MissingArtifact("hello"))?;

    let run_argv = alloc::vec![BIN_PATH.to_string()];
    let (_fs, run_res) = run_stage_reporting(fs, &run_argv, envp, "run", max_instret_per_stage, on_progress)?;

    let total = rustc_res.instret + lld_res.instret + run_res.instret;
    Ok(PipelineResult {
        rustc: rustc_res,
        lld: lld_res,
        run: run_res,
        obj,
        bin,
        total_instret: total,
    })
}

/// Run compile + link + execute. `fs` must contain the toolchain rootfs.
pub fn compile_link_run(
    mut fs: Fs,
    source: &[u8],
    rustc_argv: &[String],
    lld_argv: &[String],
    envp: &[String],
    max_instret_per_stage: u64,
) -> Result<PipelineResult, PipelineError> {
    fs.add_file(SOURCE_PATH, source.to_vec(), 0o644);

    let (fs, rustc_res) = run_stage(fs, rustc_argv, envp, "rustc", max_instret_per_stage)?;
    if rustc_res.exit_code != 0 {
        return Err(PipelineError::StageFailed("rustc", rustc_res.exit_code));
    }
    let obj = read_file(&fs, OBJ_PATH).ok_or(PipelineError::MissingArtifact("hello.o"))?;

    let (fs, lld_res) = run_stage(fs, lld_argv, envp, "rust-lld", max_instret_per_stage)?;
    if lld_res.exit_code != 0 {
        return Err(PipelineError::StageFailed("rust-lld", lld_res.exit_code));
    }
    let bin = read_file(&fs, BIN_PATH).ok_or(PipelineError::MissingArtifact("hello"))?;

    let run_argv = alloc::vec![BIN_PATH.to_string()];
    let (_fs, run_res) = run_stage(fs, &run_argv, envp, "hello", max_instret_per_stage)?;

    let total = rustc_res.instret + lld_res.instret + run_res.instret;
    Ok(PipelineResult {
        rustc: rustc_res,
        lld: lld_res,
        run: run_res,
        obj,
        bin,
        total_instret: total,
    })
}
