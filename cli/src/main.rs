//! sgx-attest — single CLI for the whole pipeline.
//! Subcommands: enroll, publish, run, verify.
//!
//! `run` and `enroll` load and execute the enclave from this process directly
//! via the `enclave-runner` + `sgxs-loaders` + `aesm-client` crates — no
//! `ftxsgx-runner` shellout required.
//!
//! On non-SGX platforms (e.g. macOS) pass `--native <binary>` instead of
//! `--sgxs`: the program runs as an ordinary process with a stub identity
//! (dry run — no hardware root of trust, but the full pipeline works).

use std::path::PathBuf;

use attestations::core::{sha256, Envelope, Hash32, Leaf, Mrenclave, PubKey};
use attestations::registry::Registry;
use attestations::replay::canonical_ast_hash;
use attestations::transcript::{PublicInput, Replay, ReplayReport, Step, Transcript};
use attestations::verify::verify_envelope;
use clap::{Parser, Subcommand};
use wrapped_rustc_lib::CompilationPublicValues;

#[derive(Parser, Debug)]
#[command(name = "sgx-attest", about = "SGX attestation pipeline (Merkle-rooted)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the enclave in `enroll` mode and append the leaf to a registry file.
    Enroll {
        /// Path to the .sgxs enclave image.
        #[arg(long, conflicts_with = "native")]
        sgxs: Option<PathBuf>,
        /// Dry run: path to a native binary, executed without SGX.
        #[arg(long)]
        native: Option<PathBuf>,
        /// Registry JSON to update (created if missing).
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
    },
    /// Print the Merkle root of a registry; write `root.txt` next to it.
    Publish {
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
    },
    /// Run the enclave in `compute` mode with the given args; write the envelope.
    Run {
        #[arg(long, conflicts_with = "native")]
        sgxs: Option<PathBuf>,
        /// Dry run: path to a native binary, executed without SGX.
        #[arg(long)]
        native: Option<PathBuf>,
        /// Output file for the JSON Envelope.
        #[arg(long, default_value = "envelope.json")]
        out: PathBuf,
        /// Arguments forwarded to the enclave (after `--`).
        #[arg(last = true)]
        enclave_args: Vec<String>,
    },
    /// Verify an envelope against a registry.
    Verify {
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
        #[arg(long, default_value = "envelope.json")]
        envelope: PathBuf,
    },
    /// End-to-end smoke test: enroll, publish, run with N, verify.
    Demo {
        #[arg(long, conflicts_with = "native")]
        sgxs: Option<PathBuf>,
        /// Dry run: path to a native binary, executed without SGX.
        #[arg(long)]
        native: Option<PathBuf>,
        /// Fibonacci index to compute.
        #[arg(long, default_value_t = 20)]
        n: u64,
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
        #[arg(long, default_value = "envelope.json")]
        envelope: PathBuf,
    },
    /// Tamper test: mutate the envelope output and confirm the verifier rejects.
    TamperTest {
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
        #[arg(long, default_value = "envelope.json")]
        envelope: PathBuf,
    },
    /// Host-side: run the real rustc on a source file and record a compilation
    /// transcript (artifacts hashed at each pass boundary + public inputs).
    Transcribe {
        /// Path to the `.rs` source file to compile.
        source: PathBuf,
        /// Logical program name recorded in the transcript.
        #[arg(long, default_value = "hello")]
        name: String,
        /// Directory for the emitted artifacts (created if missing).
        #[arg(long, default_value = "build")]
        out_dir: PathBuf,
        /// Where to write the transcript JSON.
        #[arg(long, default_value = "transcript.json")]
        transcript: PathBuf,
    },
    /// Run the replay enclave over a transcript; write the signed envelope.
    Replay {
        #[arg(long, conflicts_with = "native")]
        sgxs: Option<PathBuf>,
        /// Dry run: path to a native binary, executed without SGX.
        #[arg(long)]
        native: Option<PathBuf>,
        #[arg(long, default_value = "transcript.json")]
        transcript: PathBuf,
        #[arg(long, default_value = "envelope.json")]
        out: PathBuf,
    },
    /// Host validation: run the rvlinux emulator over a rootfs bundle to
    /// compile a Rust source (rustc → rust-lld → run), printing the hashes.
    /// This is the exact computation the enclave will re-execute and attest.
    EmuCompile {
        /// ZKFS1 rootfs bundle containing the riscv64 rustc toolchain.
        #[arg(long)]
        bundle: PathBuf,
        /// Rust source file to compile.
        #[arg(long)]
        source: PathBuf,
        /// Optional expected linked-binary sha256 (hex) to assert against.
        #[arg(long)]
        expect_bin: Option<String>,
    },
    /// Run the replay enclave in `compile` mode: feed it the toolchain bundle
    /// (stdin) + source, capture the signed Envelope binding source→binary.
    CompileAttest {
        #[arg(long, conflicts_with = "native")]
        sgxs: Option<PathBuf>,
        #[arg(long)]
        native: Option<PathBuf>,
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long, default_value = "envelope.json")]
        out: PathBuf,
    },
    /// Verify a compile Envelope: signature + Merkle, then the committed
    /// CompilationPublicValues (source→object→binary).
    VerifyCompile {
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
        #[arg(long, default_value = "envelope.json")]
        envelope: PathBuf,
        /// Optional expected linked-binary sha256 (hex) to assert against.
        #[arg(long)]
        expect_bin: Option<String>,
    },
    /// Verify a replay envelope and print what was replayed vs. trusted.
    VerifyTranscript {
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
        #[arg(long, default_value = "envelope.json")]
        envelope: PathBuf,
        /// Optional: the produced binary; its hash is checked against the attested one.
        #[arg(long)]
        binary: Option<PathBuf>,
    },
}

/// What to execute: a real SGX enclave image, or a native binary (dry run).
enum Target {
    Sgxs(PathBuf),
    Native(PathBuf),
}

fn resolve_target(sgxs: Option<PathBuf>, native: Option<PathBuf>) -> Target {
    match (sgxs, native) {
        (Some(s), None) => Target::Sgxs(s),
        (None, Some(n)) => {
            eprintln!("[dry-run] executing {} natively — stub identity, no hardware root of trust", n.display());
            Target::Native(n)
        }
        _ => {
            eprintln!("pass --sgxs <image.sgxs> (SGX) or --native <binary> (dry run, no SGX)");
            std::process::exit(2);
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Enroll { sgxs, native, registry } => cmd_enroll(&resolve_target(sgxs, native), &registry),
        Cmd::Publish { registry } => cmd_publish(&registry),
        Cmd::Run { sgxs, native, out, enclave_args } => cmd_run(&resolve_target(sgxs, native), &out, &enclave_args),
        Cmd::Verify { registry, envelope } => cmd_verify(&registry, &envelope),
        Cmd::Demo { sgxs, native, n, registry, envelope } => cmd_demo(&resolve_target(sgxs, native), n, &registry, &envelope),
        Cmd::TamperTest { registry, envelope } => cmd_tamper_test(&registry, &envelope),
        Cmd::Transcribe { source, name, out_dir, transcript } => {
            cmd_transcribe(&source, &name, &out_dir, &transcript)
        }
        Cmd::Replay { sgxs, native, transcript, out } => {
            cmd_replay(&resolve_target(sgxs, native), &transcript, &out)
        }
        Cmd::VerifyTranscript { registry, envelope, binary } => {
            cmd_verify_transcript(&registry, &envelope, binary.as_deref())
        }
        Cmd::EmuCompile { bundle, source, expect_bin } => {
            cmd_emu_compile(&bundle, &source, expect_bin.as_deref())
        }
        Cmd::CompileAttest { sgxs, native, bundle, source, out } => {
            cmd_compile_attest(&resolve_target(sgxs, native), &bundle, &source, &out)
        }
        Cmd::VerifyCompile { registry, envelope, expect_bin } => {
            cmd_verify_compile(&registry, &envelope, expect_bin.as_deref())
        }
    }
}

/// Serve the bundle over a localhost TCP socket, run the replay program in
/// `compile` mode (it connects back for the bundle), and capture the Envelope.
/// TCP reliably streams the ~471 MB bundle into an SGX enclave — unlike a large
/// stdin feed — and reuses the same stdout capture the other commands use.
fn cmd_compile_attest(target: &Target, bundle: &PathBuf, source: &PathBuf, out: &PathBuf) {
    use std::io::Write as _;
    use std::net::TcpListener;

    let bundle_bytes = std::fs::read(bundle).expect("read bundle");
    let source_hex = hex::encode(std::fs::read(source).expect("read source"));

    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind bundle server");
    let port = listener.local_addr().unwrap().port();
    eprintln!("serving {} MiB bundle on 127.0.0.1:{}", bundle_bytes.len() / 1024 / 1024, port);
    let server = std::thread::spawn(move || {
        // One shot: the enclave connects once, we send [u64 len][bundle].
        match listener.accept() {
            Ok((mut sock, _)) => {
                let hdr = (bundle_bytes.len() as u64).to_le_bytes();
                if let Err(e) = sock.write_all(&hdr).and_then(|_| sock.write_all(&bundle_bytes)) {
                    eprintln!("bundle server: send failed: {e}");
                }
            }
            Err(e) => eprintln!("bundle server: accept failed: {e}"),
        }
    });

    let args = ["compile".to_string(), source_hex, port.to_string()];
    let raw = run_program_capturing(target, &args);
    server.join().ok();

    std::fs::write(out, &raw).unwrap();
    println!("wrote {} ({} bytes)", out.display(), raw.len());
}

/// Verify a compile Envelope and print the committed source→binary binding.
fn cmd_verify_compile(registry_path: &PathBuf, envelope_path: &PathBuf, expect_bin: Option<&str>) {
    let registry: Registry =
        serde_json::from_str(&std::fs::read_to_string(registry_path).unwrap()).unwrap();
    let envelope: Envelope =
        serde_json::from_str(&std::fs::read_to_string(envelope_path).unwrap()).unwrap();

    let root = registry.root();
    let mr = envelope.signed.att.mrenclave.0;
    let leaf = registry.leaves.iter().find(|l| l.mrenclave.0 == mr)
        .unwrap_or_else(|| panic!("MRENCLAVE {} not in registry", hex::encode(mr)))
        .clone();
    let proof = registry.prove(&mr).expect("merkle proof");

    let verified = match verify_envelope(&root, &leaf, &proof, &envelope) {
        Ok(v) => v,
        Err(e) => { eprintln!("FAIL: envelope invalid: {:?}", e); std::process::exit(1); }
    };
    let pv: CompilationPublicValues =
        serde_json::from_slice(verified.output).expect("output is not CompilationPublicValues");

    println!("envelope signature + merkle : OK");
    println!("  enclave (MRENCLAVE)  = {}", hex::encode(verified.mrenclave));
    println!("  toolchain bundle sha = {}", hex::encode(pv.bundle_sha256));
    println!("  source  sha256       = {}", hex::encode(pv.source_sha256));
    println!("  object  sha256       = {}", hex::encode(pv.obj_sha256));
    println!("  binary  sha256       = {}", hex::encode(pv.bin_sha256));
    println!("  stdout  sha256       = {}", hex::encode(pv.stdout_sha256));
    println!("  exits (rustc/lld/run)= {}/{}/{}", pv.rustc_exit, pv.lld_exit, pv.run_exit);
    println!("  instret (rustc/lld/run) = {}/{}/{}", pv.rustc_instret, pv.lld_instret, pv.run_instret);

    if pv.rustc_exit != 0 || pv.lld_exit != 0 {
        eprintln!("FAIL: compilation did not succeed inside the enclave");
        std::process::exit(1);
    }
    if let Some(want) = expect_bin {
        if hex::encode(pv.bin_sha256) == want.trim() {
            println!("VERIFIED: attested binary matches expected hash — source→binary bound by MRENCLAVE");
        } else {
            eprintln!("FAIL: attested bin {} != expected {}", hex::encode(pv.bin_sha256), want.trim());
            std::process::exit(1);
        }
    } else {
        println!("VERIFIED: signed source→binary binding");
    }
}

/// Run the emulator pipeline over a bundle + source and report the hashes.
fn cmd_emu_compile(bundle: &PathBuf, source: &PathBuf, expect_bin: Option<&str>) {
    let bundle_bytes = std::fs::read(bundle).expect("read bundle");
    let source_bytes = std::fs::read(source).expect("read source");

    let mut fs = rvlinux::fs::Fs::new();
    let n = rvlinux::bundle::parse_into(&mut fs, &bundle_bytes).expect("parse bundle");
    eprintln!("loaded bundle: {} entries, {} MiB", n, bundle_bytes.len() / 1024 / 1024);

    let rustc_argv = rvlinux::pipeline::default_rustc_argv();
    let lld_argv = rvlinux::pipeline::default_lld_argv();
    let envp = rvlinux::pipeline::default_envp();

    let t0 = std::time::Instant::now();
    let res = rvlinux::pipeline::compile_link_run(fs, &source_bytes, &rustc_argv, &lld_argv, &envp, 0)
        .unwrap_or_else(|e| { eprintln!("pipeline failed: {:?}", e); std::process::exit(1); });
    let dt = t0.elapsed();

    let bin_hash = sha256(&res.bin);
    println!("source  sha256 = {}", hex::encode(sha256(&source_bytes)));
    println!("obj     sha256 = {}", hex::encode(sha256(&res.obj)));
    println!("bin     sha256 = {}", hex::encode(bin_hash));
    println!("stdout         = {:?}", String::from_utf8_lossy(&res.run.stdout));
    println!("exits          = rustc:{} lld:{} run:{}", res.rustc.exit_code, res.lld.exit_code, res.run.exit_code);
    println!("instret total  = {} ({:.1}s, {:.1} MIPS)",
             res.total_instret, dt.as_secs_f64(),
             res.total_instret as f64 / dt.as_secs_f64() / 1e6);

    if let Some(want) = expect_bin {
        if hex::encode(bin_hash) == want.trim() {
            println!("BIN MATCHES expected hash — real source→binary reproduced");
        } else {
            eprintln!("FAIL: bin hash != expected {}", want.trim());
            std::process::exit(1);
        }
    }
}

fn run_program_capturing(target: &Target, args: &[String]) -> Vec<u8> {
    match target {
        Target::Sgxs(sgxs) => run_enclave_capturing(sgxs, args),
        Target::Native(bin) => run_native_capturing(bin, args),
    }
}

/// Dry run: execute the program as an ordinary child process and capture its
/// stdout. The `attestations` crate substitutes a stub MRENCLAVE/seal key when
/// not compiled for `target_env = "sgx"`, so the whole pipeline works — it
/// just proves nothing about hardware.
fn run_native_capturing(bin: &PathBuf, args: &[String]) -> Vec<u8> {
    let out = std::process::Command::new(bin).args(args).output().unwrap_or_else(|e| {
        eprintln!("failed to execute {}: {}", bin.display(), e);
        std::process::exit(1);
    });
    if !out.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&out.stderr));
    }
    if !out.status.success() {
        eprintln!("native program exited with {}", out.status);
        std::process::exit(1);
    }
    out.stdout
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
fn run_enclave_capturing(_sgxs: &PathBuf, _args: &[String]) -> Vec<u8> {
    eprintln!("--sgxs requires x86_64 Linux with an SGX driver; on this platform use --native <binary> for a dry run");
    std::process::exit(2);
}

/// Capture the enclave's stdout into a Vec<u8>:
/// 1. dup current stdout (saved fd) so we can restore it later
/// 2. create a pipe
/// 3. dup2 the write end onto fd 1 (stdout)
/// 4. spawn a reader thread on the read end
/// 5. run the enclave (its `println!`s land in the pipe)
/// 6. flush, restore fd 1, close write end → reader thread sees EOF
/// 7. join reader, return buffer
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn run_enclave_capturing(sgxs: &PathBuf, args: &[String]) -> Vec<u8> {
    use std::io::{Read, Write as _};
    use std::os::unix::io::FromRawFd;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use aesm_client::AesmClient;
    use enclave_runner::EnclaveBuilder;
    use enclave_runner_sgx::EnclaveBuilder as EnclaveBuilderSgx;
    use sgxs_loaders::isgx::Device as IsgxDevice;

    // Build runner.
    let aesm = AesmClient::new();
    let mut device = IsgxDevice::new()
        .expect("open /dev/isgx (legacy SGX driver)")
        .einittoken_provider(aesm)
        .build();

    let mut sgx_builder = EnclaveBuilderSgx::new(sgxs.as_path());
    if sgx_builder.coresident_signature().is_err() {
        // Fall back to dummy signature for debug enclaves (matches ftxsgx-runner default).
        sgx_builder.dummy_signature();
    }
    let mut builder = EnclaveBuilder::new(sgx_builder);
    builder.args(args);
    let enclave = builder.build(&mut device).expect("build enclave");

    // Set up pipe + fd swap.
    std::io::stdout().flush().ok();
    let saved_stdout = unsafe { libc::dup(libc::STDOUT_FILENO) };
    if saved_stdout < 0 { panic!("dup stdout"); }
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } < 0 { panic!("pipe"); }
    let (rd, wr) = (pipe_fds[0], pipe_fds[1]);
    if unsafe { libc::dup2(wr, libc::STDOUT_FILENO) } < 0 { panic!("dup2"); }
    unsafe { libc::close(wr) };

    // Reader thread.
    let captured = Arc::new(Mutex::new(Vec::<u8>::new()));
    let reader_buf = captured.clone();
    let reader = thread::spawn(move || {
        let mut f = unsafe { std::fs::File::from_raw_fd(rd) };
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).ok();
        *reader_buf.lock().unwrap() = buf;
    });

    // Run the enclave — this blocks until exit.
    let run_result = enclave.run();

    // Restore stdout, close write end (drops fd 1 dup; the close above already
    // dropped the original write fd, but the dup2'd copy on fd 1 still keeps
    // the pipe alive — restoring fd 1 to the saved fd closes the last writer).
    std::io::stdout().flush().ok();
    if unsafe { libc::dup2(saved_stdout, libc::STDOUT_FILENO) } < 0 { panic!("dup2 restore"); }
    unsafe { libc::close(saved_stdout) };

    reader.join().expect("reader thread");

    if let Err(e) = run_result {
        eprintln!("enclave run error: {:?}", e);
        std::process::exit(1);
    }
    Arc::try_unwrap(captured).unwrap().into_inner().unwrap()
}

fn cmd_enroll(target: &Target, registry_path: &PathBuf) {
    let raw = run_program_capturing(target, &["enroll".to_string()]);
    let s = std::str::from_utf8(&raw).expect("enrollment proof not utf8");
    let proof: serde_json::Value = serde_json::from_str(s.trim()).expect("parse proof");

    let mrenclave_hex = proof["mrenclave"].as_str().expect("mrenclave");
    let pubkey_hex    = proof["pubkey"].as_str().expect("pubkey");
    let program_name  = proof["program_name"].as_str().expect("program_name");
    let sig_hex       = proof["self_signature"].as_str().expect("self_signature");

    let mrenclave: [u8; 32] = hex::decode(mrenclave_hex).unwrap().try_into().unwrap();
    let pubkey:    [u8; 32] = hex::decode(pubkey_hex).unwrap().try_into().unwrap();
    let sig_bytes: [u8; 64] = hex::decode(sig_hex).unwrap().try_into().unwrap();

    // sanity: self-signature
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"sgx-attest:enroll:v1");
    h.update(mrenclave);
    h.update(pubkey);
    h.update(program_name.as_bytes());
    let digest: [u8; 32] = h.finalize().into();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pubkey).expect("pubkey");
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    use ed25519_dalek::Verifier;
    vk.verify(&digest, &sig).expect("self-signature invalid");

    let mut registry: Registry = if registry_path.exists() {
        serde_json::from_str(&std::fs::read_to_string(registry_path).unwrap()).unwrap_or_default()
    } else { Registry::new() };
    registry.add(Leaf {
        mrenclave: Mrenclave(mrenclave),
        pubkey: PubKey(pubkey),
        program_name: program_name.to_string(),
    });
    std::fs::write(registry_path, serde_json::to_string_pretty(&registry).unwrap()).unwrap();

    println!("enrolled program={} MRENCLAVE={}", program_name, mrenclave_hex);
    println!("registry root = {}", hex::encode(registry.root()));
}

fn cmd_publish(registry_path: &PathBuf) {
    let s = std::fs::read_to_string(registry_path).unwrap();
    let r: Registry = serde_json::from_str(&s).unwrap();
    let root = r.root();
    println!("Merkle root: {}", hex::encode(root));
    println!("Leaves     : {}", r.leaves.len());
    for l in &r.leaves {
        println!("  - program={:<16} MRENCLAVE={} PUBKEY={}",
                 l.program_name, hex::encode(l.mrenclave.0), hex::encode(l.pubkey.0));
    }
    let dst = registry_path.with_file_name("root.txt");
    std::fs::write(&dst, format!("{}\n", hex::encode(root))).unwrap();
    println!("wrote {}", dst.display());
}

fn cmd_run(target: &Target, out: &PathBuf, enclave_args: &[String]) {
    let mut full_args = vec!["compute".to_string()];
    full_args.extend(enclave_args.iter().cloned());
    let raw = run_program_capturing(target, &full_args);
    std::fs::write(out, &raw).unwrap();
    println!("wrote {} ({} bytes)", out.display(), raw.len());
}

fn cmd_demo(target: &Target, n: u64, registry: &PathBuf, envelope: &PathBuf) {
    // Start fresh.
    for f in [registry, envelope, &PathBuf::from("envelope_tampered.json"), &PathBuf::from("root.txt")] {
        let _ = std::fs::remove_file(f);
    }
    println!("=== ENROLL ===");
    cmd_enroll(target, registry);
    println!("\n=== PUBLISH ===");
    cmd_publish(registry);
    println!("\n=== RUN fib({}) ===", n);
    cmd_run(target, envelope, &[n.to_string()]);
    println!("\n=== VERIFY ===");
    cmd_verify(registry, envelope);
}

fn cmd_tamper_test(registry: &PathBuf, envelope: &PathBuf) {
    let s = std::fs::read_to_string(envelope).expect("read envelope");
    let mut e: serde_json::Value = serde_json::from_str(&s).unwrap();
    // Replace output bytes with bogus content.
    let bogus = b"{\"fib_n\":\"9999\",\"n\":20}".to_vec();
    e["output"] = serde_json::Value::Array(
        bogus.into_iter().map(|b| serde_json::Value::from(b)).collect()
    );
    let tampered = PathBuf::from("envelope_tampered.json");
    std::fs::write(&tampered, serde_json::to_string(&e).unwrap()).unwrap();

    // Run verify in-process and expect failure.
    let registry_data: Registry =
        serde_json::from_str(&std::fs::read_to_string(registry).unwrap()).unwrap();
    let envelope_data: Envelope =
        serde_json::from_str(&std::fs::read_to_string(&tampered).unwrap()).unwrap();
    let root = registry_data.root();
    let mr = envelope_data.signed.att.mrenclave.0;
    let leaf = registry_data.leaves.iter().find(|l| l.mrenclave.0 == mr).unwrap().clone();
    let proof = registry_data.prove(&mr).unwrap();

    match verify_envelope(&root, &leaf, &proof, &envelope_data) {
        Ok(_) => { eprintln!("FAIL: tampered envelope verified — should have been rejected!"); std::process::exit(1); }
        Err(e) => println!("tamper-test PASS (verifier rejected: {:?})", e),
    }
}

/// Hash a file's bytes; exit with a clear message if it can't be read.
fn hash_file(path: &std::path::Path) -> Hash32 {
    let bytes = std::fs::read(path)
        .unwrap_or_else(|e| { eprintln!("read {}: {}", path.display(), e); std::process::exit(1); });
    sha256(&bytes)
}

/// Parse a rustc `dep-info` (`.d`) file: the first line is
/// `target: dep1 dep2 ...`. Return the dependency paths (the source + any
/// sysroot rlibs rustc read), which we pin as public inputs.
fn parse_dep_info(dep_info: &str) -> Vec<PathBuf> {
    dep_info
        .lines()
        .find_map(|l| l.split_once(": ").map(|(_, deps)| deps))
        .map(|deps| deps.split_whitespace().map(PathBuf::from).collect())
        .unwrap_or_default()
}

/// Host-side: run the real rustc, capture the artifacts at each pass boundary,
/// and write a compact transcript for the enclave to replay.
fn cmd_transcribe(source: &PathBuf, name: &str, out_dir: &PathBuf, transcript_path: &PathBuf) {
    std::fs::create_dir_all(out_dir).expect("create out dir");
    let src_bytes = std::fs::read(source).expect("read source file");

    // rustc version + host target (recorded, and version pinned as a public input).
    let vv = std::process::Command::new("rustc").arg("-vV").output().expect("run rustc -vV");
    let vv_text = String::from_utf8_lossy(&vv.stdout).to_string();
    let rustc_version = vv_text.lines().next().unwrap_or("rustc ?").to_string();
    let target = vv_text
        .lines()
        .find_map(|l| l.strip_prefix("host: "))
        .unwrap_or("unknown")
        .to_string();

    // Emit MIR, LLVM-IR, object, dep-info and the linked binary, with the
    // determinism knobs that make source->binary a reproducible function.
    let mir = out_dir.join(format!("{name}.mir"));
    let ll = out_dir.join(format!("{name}.ll"));
    let obj = out_dir.join(format!("{name}.o"));
    let dep = out_dir.join(format!("{name}.d"));
    let bin = out_dir.join(name);
    let cwd = std::env::current_dir().expect("cwd");

    let emit = format!(
        "dep-info={},mir={},llvm-ir={},obj={},link",
        dep.display(), mir.display(), ll.display(), obj.display()
    );
    let status = std::process::Command::new("rustc")
        .arg(source)
        .args(["--crate-name", name, "--edition", "2021"])
        .args(["-C", "codegen-units=1", "-C", "debuginfo=0"])
        .arg("--remap-path-prefix").arg(format!("{}=.", cwd.display()))
        .arg(format!("--emit={emit}"))
        .arg("-o").arg(&bin)
        .env("SOURCE_DATE_EPOCH", "0")
        .status()
        .expect("spawn rustc");
    if !status.success() {
        eprintln!("rustc failed with {status}");
        std::process::exit(1);
    }

    // Hash each artifact.
    let source_hash = sha256(&src_bytes);
    let ast_hash = canonical_ast_hash(&src_bytes).expect("source did not parse with syn");
    let mir_hash = hash_file(&mir);
    let ll_hash = hash_file(&ll);
    let obj_hash = hash_file(&obj);
    let bin_hash = hash_file(&bin);

    // Public inputs: the rustc binary + everything dep-info says rustc read
    // (the source and any sysroot rlibs), pinned by hash.
    let mut public_inputs = Vec::new();
    if let Ok(which) = std::process::Command::new("which").arg("rustc").output() {
        let p = String::from_utf8_lossy(&which.stdout).trim().to_string();
        if !p.is_empty() {
            public_inputs.push(PublicInput { name: format!("rustc:{p}"), hash: hash_file(std::path::Path::new(&p)) });
        }
    }
    let src_canon = std::fs::canonicalize(source).ok();
    if let Ok(dep_text) = std::fs::read_to_string(&dep) {
        for d in parse_dep_info(&dep_text) {
            if !d.exists() || d.is_dir() { continue; }
            if src_canon.as_ref().and_then(|c| std::fs::canonicalize(&d).ok().map(|dc| &dc == c)).unwrap_or(false) {
                continue; // skip the source itself; it's carried in full
            }
            public_inputs.push(PublicInput { name: d.display().to_string(), hash: hash_file(&d) });
        }
    }

    // The compilation chain. `source` and `ast` are replayed in-enclave; the
    // heavy transforms are pinned as public inputs and hash-linked.
    let steps = vec![
        Step { name: "source".into(),  replay: Replay::InEnclave { replayer: "source-sha256".into() },     inputs: vec![],           output: source_hash },
        Step { name: "ast".into(),     replay: Replay::InEnclave { replayer: "syn-canonical-ast".into() },  inputs: vec![source_hash], output: ast_hash },
        Step { name: "mir".into(),     replay: Replay::PublicInput, inputs: vec![ast_hash], output: mir_hash },
        Step { name: "llvm-ir".into(), replay: Replay::PublicInput, inputs: vec![mir_hash], output: ll_hash },
        Step { name: "obj".into(),     replay: Replay::PublicInput, inputs: vec![ll_hash],  output: obj_hash },
        Step { name: "binary".into(),  replay: Replay::PublicInput, inputs: vec![obj_hash], output: bin_hash },
    ];

    let transcript = Transcript {
        program: name.to_string(),
        rustc_version,
        target,
        flags: vec!["-Ccodegen-units=1".into(), "-Cdebuginfo=0".into(), "--remap-path-prefix".into(), "SOURCE_DATE_EPOCH=0".into()],
        source: src_bytes,
        public_inputs,
        steps,
        binary: bin_hash,
    };

    std::fs::write(transcript_path, serde_json::to_string_pretty(&transcript).unwrap()).unwrap();

    println!("transcribed {} with {}", name, transcript.rustc_version);
    println!("  target       = {}", transcript.target);
    println!("  source  sha  = {}", hex::encode(source_hash));
    println!("  ast     sha  = {}", hex::encode(ast_hash));
    println!("  mir     sha  = {}", hex::encode(mir_hash));
    println!("  llvm-ir sha  = {}", hex::encode(ll_hash));
    println!("  obj     sha  = {}", hex::encode(obj_hash));
    println!("  binary  sha  = {}", hex::encode(bin_hash));
    println!("  public inputs= {} (rustc + sysroot deps)", transcript.public_inputs.len());
    println!("wrote {} ({} bytes) and artifacts in {}", transcript_path.display(),
             std::fs::metadata(transcript_path).map(|m| m.len()).unwrap_or(0), out_dir.display());
}

/// Feed a transcript to the replay enclave and capture the signed envelope.
fn cmd_replay(target: &Target, transcript_path: &PathBuf, out: &PathBuf) {
    let transcript_json = std::fs::read(transcript_path).expect("read transcript");
    // Sanity: it must deserialize before we ship it to the enclave.
    let _: Transcript = serde_json::from_slice(&transcript_json).expect("transcript is not valid JSON");
    let hex_arg = hex::encode(&transcript_json);

    let raw = run_program_capturing(target, &["compute".to_string(), hex_arg]);
    std::fs::write(out, &raw).unwrap();
    println!("wrote {} ({} bytes)", out.display(), raw.len());
}

/// Verify a replay envelope and print what the enclave replayed vs. trusted.
fn cmd_verify_transcript(registry_path: &PathBuf, envelope_path: &PathBuf, binary: Option<&std::path::Path>) {
    let registry: Registry =
        serde_json::from_str(&std::fs::read_to_string(registry_path).unwrap()).unwrap();
    let envelope: Envelope =
        serde_json::from_str(&std::fs::read_to_string(envelope_path).unwrap()).unwrap();

    let root = registry.root();
    let mr = envelope.signed.att.mrenclave.0;
    let leaf = registry.leaves.iter().find(|l| l.mrenclave.0 == mr)
        .unwrap_or_else(|| panic!("MRENCLAVE {} not in registry", hex::encode(mr)))
        .clone();
    let proof = registry.prove(&mr).expect("merkle proof");

    let verified = match verify_envelope(&root, &leaf, &proof, &envelope) {
        Ok(v) => v,
        Err(e) => { eprintln!("FAIL: envelope signature/merkle invalid: {:?}", e); std::process::exit(1); }
    };

    let report: ReplayReport =
        serde_json::from_slice(verified.output).expect("envelope output is not a ReplayReport");

    println!("envelope signature + merkle : OK");
    println!("  enclave (MRENCLAVE)  = {}", hex::encode(verified.mrenclave));
    println!("  program              = {}", report.program);
    println!("  rustc                = {}", report.rustc_version);
    println!("  target               = {}", report.target);
    println!("  source  sha256       = {}", hex::encode(report.source_hash));
    println!("  binary  sha256       = {}", hex::encode(report.binary_hash));
    println!("  chain contiguous     = {}", report.chain_ok);
    println!("  all replays matched  = {}", report.all_replays_ok);
    println!("  replayed in-enclave  ({}):", report.replayed.len());
    for s in &report.replayed {
        println!("    - {:<8} via {:<20} {}", s.name, s.replayer, if s.ok { "OK" } else { "MISMATCH" });
    }
    println!("  trusted public inputs ({}):", report.public_inputs.len());
    for p in report.public_inputs.iter().take(8) {
        println!("    - {} = {}", hex::encode(p.hash), p.name);
    }
    if report.public_inputs.len() > 8 {
        println!("    - ... {} more", report.public_inputs.len() - 8);
    }

    if let Some(bin_path) = binary {
        let actual = hash_file(bin_path);
        if actual == report.binary_hash {
            println!("  binary on disk       = MATCHES attested hash ({})", bin_path.display());
        } else {
            eprintln!("FAIL: binary {} hashes to {} but envelope attests {}",
                      bin_path.display(), hex::encode(actual), hex::encode(report.binary_hash));
            std::process::exit(1);
        }
    }

    if report.verified() {
        println!("VERIFIED: source→binary transcript is chain-consistent and all in-enclave replays passed");
    } else {
        eprintln!("FAIL: replay report did not verify (chain_ok={}, all_replays_ok={})",
                  report.chain_ok, report.all_replays_ok);
        std::process::exit(1);
    }
}

fn cmd_verify(registry_path: &PathBuf, envelope_path: &PathBuf) {
    let registry: Registry =
        serde_json::from_str(&std::fs::read_to_string(registry_path).unwrap()).unwrap();
    let envelope: Envelope =
        serde_json::from_str(&std::fs::read_to_string(envelope_path).unwrap()).unwrap();

    let root = registry.root();
    let mr = envelope.signed.att.mrenclave.0;
    let leaf = registry.leaves.iter().find(|l| l.mrenclave.0 == mr)
        .unwrap_or_else(|| panic!("MRENCLAVE {} not in registry", hex::encode(mr)))
        .clone();
    let proof = registry.prove(&mr).expect("merkle proof");

    match verify_envelope(&root, &leaf, &proof, &envelope) {
        Ok(v) => {
            println!("PASS");
            println!("  registry root = {}", hex::encode(root));
            println!("  MRENCLAVE     = {}", hex::encode(v.mrenclave));
            println!("  program       = {}", v.program_name);
            println!("  timestamp     = {}", v.timestamp_unix);
            println!("  input  ({:>4}B) = {}", v.input.len(),
                     std::str::from_utf8(v.input).unwrap_or(&hex::encode(v.input)));
            println!("  output ({:>4}B) = {}", v.output.len(),
                     std::str::from_utf8(v.output).unwrap_or(&hex::encode(v.output)));
        }
        Err(e) => { eprintln!("FAIL: {:?}", e); std::process::exit(1); }
    }
}
