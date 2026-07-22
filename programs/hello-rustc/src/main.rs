//! hello-rustc: verifiable-compilation example. Single binary, two modes.
//!   `hello-rustc enroll`                 → emit enrollment proof on stdout
//!   `hello-rustc compute [source.rs]`    → compile the source with `rustc`,
//!                                          run the produced binary, emit a
//!                                          signed Envelope binding
//!                                          source → (binary hash, stdout)
//!
//! With no source argument a built-in "Hello, world!" program is compiled.
//! Spawning `rustc` needs a real OS process, which the Fortanix SGX target
//! does not provide — run this one via `--native` (dry run).

use attestations::core::sha256;

const PROGRAM_NAME: &str = "hello-rustc";

const DEFAULT_SOURCE: &str = "fn main() {\n    println!(\"Hello, world!\");\n}\n";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("compute");

    match mode {
        "enroll" => attestations::enclave::enroll(PROGRAM_NAME),
        "compute" => {
            let source = match args.get(2) {
                Some(path) => std::fs::read(path).expect("read source file"),
                None => DEFAULT_SOURCE.as_bytes().to_vec(),
            };
            attestations::enclave::commit_with_input(PROGRAM_NAME, source, |input| {
                serde_json::to_vec(&compile_and_run(input)).unwrap()
            });
        }
        other => {
            eprintln!("unknown mode: {} (expected: enroll | compute [source.rs])", other);
            std::process::exit(2);
        }
    }
}

/// Write the source to a temp dir, compile it with `rustc`, run the result.
fn compile_and_run(source: &[u8]) -> serde_json::Value {
    let dir = std::env::temp_dir().join(format!("hello-rustc-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let src_path = dir.join("main.rs");
    let bin_path = dir.join("main");
    std::fs::write(&src_path, source).expect("write source");

    let compile = std::process::Command::new("rustc")
        .arg(&src_path)
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("spawn rustc (is it on PATH?)");
    if !compile.status.success() {
        eprint!("{}", String::from_utf8_lossy(&compile.stderr));
        eprintln!("rustc failed with {}", compile.status);
        std::process::exit(1);
    }

    let binary = std::fs::read(&bin_path).expect("read compiled binary");
    let run = std::process::Command::new(&bin_path).output().expect("run compiled binary");
    let _ = std::fs::remove_dir_all(&dir);

    serde_json::json!({
        "binary_sha256": hex::encode(sha256(&binary)),
        "binary_len": binary.len(),
        "exit_code": run.status.code(),
        "stdout": String::from_utf8_lossy(&run.stdout),
    })
}
