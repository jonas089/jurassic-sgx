//! The verifiable compilation pipeline: rustc -> rust-lld -> run the result,
//! for both a single source file and a multi-crate workspace. Built on top
//! of `rvlinux` (the generic RISC-V emulator) but specific to "compile Rust
//! source with the real rustc/rust-lld" — that's why it lives here rather
//! than in `rvlinux` itself.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use rvlinux::fs::{Fs, Node};
use rvlinux::{Machine, RunError};

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

// ---------------------------------------------------------------------------
// Multi-crate workspace builds: an ordered list of `rustc` invocations (each
// producing an rlib, except the last which must be the `Bin` crate's object
// file), linked together by `rust-lld` against every produced rlib. `fs` must
// already contain the toolchain rootfs *and* the workspace source tree.
//
// Note: the `Bin` unit compiles with `--emit=obj` and gets linked by us as a
// separate stage, rather than letting `rustc` invoke its own linker via `-C
// linker=...` — this emulator has no `execve` (syscall 221 is a hardcoded
// ENOSYS stub), so a guest `rustc` can never fork+exec a linker subprocess
// itself. Every pipeline stage must stay a separate, host-orchestrated
// `Machine`, which is also why `alloc` support needs the sysroot's
// `liballoc.rlib` explicitly listed as a link input below — the
// `__rust_alloc`/OOM-handler/`format!` shim code rustc would normally
// generate as part of driving its own link isn't available to us; what we
// get instead is whatever's already compiled into the prebuilt rlib.

/// Whether a compile unit produces a linkable library (`--emit=link`, an
/// rlib later consumed via `--extern`) or the final binary's object file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CrateType {
    Lib,
    Bin,
}

/// One `rustc` invocation in a [`BuildPlan`].
#[derive(Clone, Debug)]
pub struct CrateUnit {
    pub name: String,
    /// Absolute path (inside the guest fs) to the crate root `.rs` file.
    pub entry: String,
    pub crate_type: CrateType,
    /// `(extern_name, dependency unit name)` pairs; each dependency must
    /// appear earlier in [`BuildPlan::units`].
    pub externs: Vec<(String, String)>,
}

/// An ordered, already-topologically-sorted list of crates to compile.
/// Exactly one unit must be [`CrateType::Bin`] (the final linked program).
pub struct BuildPlan {
    pub units: Vec<CrateUnit>,
}

#[derive(Debug)]
pub enum WorkspaceError {
    Pipeline(PipelineError),
    /// A unit's `--extern` referenced a dependency that wasn't compiled
    /// earlier in the plan (the plan is not a valid topological order).
    UnknownExtern { unit: String, dep: String },
    /// The plan contained zero (or more than one) `Bin` units.
    NoBinCrate,
    /// `rustc` exited non-zero compiling `unit`; `stderr` is included since a
    /// bare exit code is useless for diagnosing a real compile error.
    UnitFailed { unit: String, exit_code: i32, stderr: Vec<u8> },
    /// `rust-lld` exited non-zero linking the final binary.
    LinkFailed { exit_code: i32, stderr: Vec<u8> },
}

impl From<PipelineError> for WorkspaceError {
    fn from(e: PipelineError) -> Self {
        WorkspaceError::Pipeline(e)
    }
}

/// Everything produced by compiling one [`CrateUnit`]: the exact argv used
/// (so it can be hashed into the attestation) and the resulting artifact.
pub struct UnitOutcome {
    pub name: String,
    pub crate_type: CrateType,
    pub externs: Vec<(String, String)>,
    pub argv: Vec<String>,
    pub stage: StageResult,
    pub artifact: Vec<u8>,
}

pub struct WorkspaceResult {
    pub units: Vec<UnitOutcome>,
    pub link_argv: Vec<String>,
    pub link: StageResult,
    pub run: StageResult,
    pub bin: Vec<u8>,
}

const SYSROOT_LIB_DIR: &str = "/opt/rust/lib/rustlib/riscv64gc-unknown-linux-gnu/lib";

/// Find `core`/`alloc`/`compiler_builtins`/`rustc_std_workspace_core` in the
/// toolchain's sysroot lib dir by filename prefix (their hash suffix is
/// derived from the compiler build and not worth hardcoding here — it's
/// already pinned once, in `mkbundle`, by way of the toolchain version).
fn sysroot_core_rlibs(fs: &Fs) -> Vec<String> {
    const PREFIXES: [&str; 4] =
        ["libcore-", "liballoc-", "libcompiler_builtins-", "librustc_std_workspace_core-"];
    let mut out: Vec<String> = fs
        .list_dir(SYSROOT_LIB_DIR)
        .into_iter()
        .filter(|(name, dtype)| {
            *dtype == 8 && name.ends_with(".rlib") && PREFIXES.iter().any(|p| name.starts_with(p))
        })
        .map(|(name, _)| alloc::format!("{}/{}", SYSROOT_LIB_DIR, name))
        .collect();
    out.sort();
    out
}

fn crate_out_path(name: &str, crate_type: &CrateType) -> String {
    match crate_type {
        CrateType::Lib => alloc::format!("/work/out/lib{}.rlib", name),
        CrateType::Bin => "/work/out/app.o".to_string(),
    }
}

fn unit_rustc_argv(
    unit: &CrateUnit,
    out_path: &str,
    artifact_path: &alloc::collections::BTreeMap<String, String>,
) -> Result<Vec<String>, WorkspaceError> {
    let mut argv: Vec<String> = [
        "/opt/rust/bin/rustc",
        "--edition",
        "2024",
        "-O",
        "-C",
        "panic=abort",
        "-C",
        "codegen-units=1",
        "--crate-name",
        unit.name.as_str(),
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();

    match unit.crate_type {
        CrateType::Lib => {
            argv.push("--crate-type".to_string());
            argv.push("lib".to_string());
            argv.push("--emit=link".to_string());
        }
        CrateType::Bin => argv.push("--emit=obj".to_string()),
    }
    // Every already-built rlib lives here. Direct dependencies still need an
    // explicit `--extern` (source resolves them by that name), but rustc also
    // needs to *locate* transitive dependencies referenced only in a direct
    // dependency's metadata (e.g. `app` doesn't `use leftpad` itself, but
    // `greet`'s rlib does) — it finds those by searching `-L` for a matching
    // crate name/hash, not via `--extern`.
    argv.push("-L".to_string());
    argv.push("dependency=/work/out".to_string());
    for (extern_name, dep) in &unit.externs {
        let dep_path = artifact_path.get(dep).ok_or_else(|| WorkspaceError::UnknownExtern {
            unit: unit.name.clone(),
            dep: dep.clone(),
        })?;
        argv.push("--extern".to_string());
        argv.push(alloc::format!("{}={}", extern_name, dep_path));
    }
    argv.push(unit.entry.clone());
    argv.push("-o".to_string());
    argv.push(out_path.to_string());
    Ok(argv)
}

/// Compile every crate in `plan` in order (each may `--extern` on earlier
/// ones), link the final `Bin` crate's object file against all produced
/// rlibs, then run the result.
pub fn compile_workspace_run_reporting(
    mut fs: Fs,
    plan: &BuildPlan,
    envp: &[String],
    max_instret_per_stage: u64,
    on_progress: &mut dyn FnMut(&str, u64),
) -> Result<WorkspaceResult, WorkspaceError> {
    // rustc writes per-codegen-unit intermediates next to `-o` before
    // assembling the final artifact, so the output dir must pre-exist.
    fs.mkdir_all("/work/out");

    let mut artifact_path: alloc::collections::BTreeMap<String, String> =
        alloc::collections::BTreeMap::new();
    let mut units = Vec::new();
    let mut rlib_paths = Vec::new();
    let mut bin_obj_path: Option<String> = None;

    for unit in &plan.units {
        let out_path = crate_out_path(&unit.name, &unit.crate_type);
        let argv = unit_rustc_argv(unit, &out_path, &artifact_path)?;

        let (next_fs, stage) =
            run_stage_reporting(fs, &argv, envp, "rustc", max_instret_per_stage, on_progress)?;
        fs = next_fs;
        if stage.exit_code != 0 {
            return Err(WorkspaceError::UnitFailed {
                unit: unit.name.clone(),
                exit_code: stage.exit_code,
                stderr: stage.stderr,
            });
        }
        let artifact = read_file(&fs, &out_path)
            .ok_or(WorkspaceError::Pipeline(PipelineError::MissingArtifact("crate-artifact")))?;

        artifact_path.insert(unit.name.clone(), out_path.clone());
        match unit.crate_type {
            CrateType::Lib => rlib_paths.push(out_path.clone()),
            CrateType::Bin => bin_obj_path = Some(out_path.clone()),
        }
        units.push(UnitOutcome {
            name: unit.name.clone(),
            crate_type: unit.crate_type.clone(),
            externs: unit.externs.clone(),
            argv,
            stage,
            artifact,
        });
    }

    let obj_path = bin_obj_path.ok_or(WorkspaceError::NoBinCrate)?;
    // The prebuilt sysroot `libcore.rlib` bundles unrelated functions into a
    // single object-file archive member, so pulling in any one symbol (e.g.
    // the slice-bounds-check panic path) pulls in that whole member — IPv6
    // parsing, bignum formatting, all of it — and their own unresolved refs
    // with it. `--gc-sections` drops the ones nothing actually reaches.
    let mut link_argv: Vec<String> = [
        "/opt/rust/lib/rustlib/riscv64gc-unknown-linux-gnu/bin/rust-lld",
        "-flavor",
        "gnu",
        "-static",
        "--gc-sections",
        "-e",
        "_start",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    link_argv.push(obj_path);
    link_argv.extend(rlib_paths);
    // Unlike the single-file demo (whose object never references anything
    // outside its own hand-rolled `_start`), real crate code pulls in
    // `core`/`alloc`/`compiler_builtins` symbols. Those rlibs already ship in
    // the toolchain bundle's sysroot; find them by prefix rather than
    // hardcoding their hash-suffixed names.
    link_argv.extend(sysroot_core_rlibs(&fs));
    link_argv.push("-o".to_string());
    link_argv.push(BIN_PATH.to_string());

    let (fs, link) =
        run_stage_reporting(fs, &link_argv, envp, "rust-lld", max_instret_per_stage, on_progress)?;
    if link.exit_code != 0 {
        return Err(WorkspaceError::LinkFailed { exit_code: link.exit_code, stderr: link.stderr });
    }
    let bin = read_file(&fs, BIN_PATH)
        .ok_or(WorkspaceError::Pipeline(PipelineError::MissingArtifact("hello")))?;

    let run_argv = alloc::vec![BIN_PATH.to_string()];
    let (_fs, run) = run_stage_reporting(fs, &run_argv, envp, "run", max_instret_per_stage, on_progress)?;

    Ok(WorkspaceResult { units, link_argv, link, run, bin })
}

/// Same as [`compile_workspace_run_reporting`] without progress callbacks.
pub fn compile_workspace_run(
    fs: Fs,
    plan: &BuildPlan,
    envp: &[String],
    max_instret_per_stage: u64,
) -> Result<WorkspaceResult, WorkspaceError> {
    compile_workspace_run_reporting(fs, plan, envp, max_instret_per_stage, &mut |_, _| {})
}
