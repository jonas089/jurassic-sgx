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

use attestations::core::{Envelope, Leaf, Mrenclave, PubKey};
use attestations::registry::Registry;
use attestations::verify::verify_envelope;
use clap::{Parser, Subcommand};

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
