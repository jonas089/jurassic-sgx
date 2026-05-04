//! Fibonacci enclave: single binary, two modes.
//!   `fibonacci enroll`       → emit enrollment proof on stdout
//!   `fibonacci compute <n>`  → emit signed Envelope on stdout

const PROGRAM_NAME: &str = "fibonacci";

fn parse_n(s: &str) -> u64 { s.trim().parse::<u64>().unwrap_or(0) }

fn fib(n: u64) -> u128 {
    let (mut a, mut b) = (0u128, 1u128);
    for _ in 0..n { let t = a + b; a = b; b = t; }
    a
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("compute");

    match mode {
        "enroll" => attestations::enclave::enroll(PROGRAM_NAME),
        "compute" => {
            let n_str = args.get(2).cloned().unwrap_or_default();
            attestations::enclave::commit_with_input(
                PROGRAM_NAME,
                n_str.as_bytes().to_vec(),
                |input| {
                    let n = parse_n(std::str::from_utf8(input).unwrap_or(""));
                    serde_json::to_vec(&serde_json::json!({
                        "n": n, "fib_n": fib(n).to_string(),
                    })).unwrap()
                },
            );
        }
        other => {
            eprintln!("unknown mode: {} (expected: enroll | compute <n>)", other);
            std::process::exit(2);
        }
    }
}
