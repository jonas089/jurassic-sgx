//! crates.io fetching: resolves a semver requirement against the sparse
//! index, downloads the matching `.crate` tarball, and extracts it into a
//! local cache. This is the host-side, untrusted planning step's only
//! window onto the outside world — the enclave itself has no network
//! access at all (see `rvlinux`'s SPEC.md), so nothing fetched here is
//! trusted as-is: the extracted source becomes part of the packed source
//! tree `workspace::discover` hashes into the attestation like everything
//! else, so a verifier still sees exactly what got compiled.
//!
//! Deliberately simplified versus real Cargo: a dependency name is resolved
//! **once per build, globally** — if two crates in the graph request
//! different (even incompatible) version requirements for the same
//! crates.io crate, whichever is resolved first wins for both, rather than
//! building two separate copies the way Cargo's resolver can. Diamond
//! dependencies with genuinely conflicting version constraints aren't
//! supported.

use std::io::Read;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Deserialize)]
struct IndexEntry {
    vers: String,
    #[serde(default)]
    yanked: bool,
}

/// crates.io's sparse-index path convention for a package name (same layout
/// the old git index used): 1/2/3-char names get their own short prefix
/// buckets, everything else buckets on its first four characters.
fn index_path(name: &str) -> String {
    let lower = name.to_lowercase();
    match lower.len() {
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", &lower[0..1]),
        _ => format!("{}/{}/{lower}", &lower[0..2], &lower[2..4]),
    }
}

fn fetch_index(name: &str) -> Vec<IndexEntry> {
    let url = format!("https://index.crates.io/{}", index_path(name));
    let body = ureq::get(&url)
        .call()
        .unwrap_or_else(|e| panic!("fetch crates.io index for \"{name}\": {e}"))
        .body_mut()
        .read_to_string()
        .unwrap_or_else(|e| panic!("read crates.io index body for \"{name}\": {e}"));
    body.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            serde_json::from_str(l)
                .unwrap_or_else(|e| panic!("parse crates.io index entry for \"{name}\": {e}\n{l}"))
        })
        .collect()
}

fn cache_dir() -> PathBuf {
    let base = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    base.join(".cache/jurassic-sgx/registry")
}

pub struct ResolvedPackage {
    pub version: String,
    pub dir: PathBuf,
}

/// Resolve `req` (a Cargo-style semver requirement, e.g. `"1.2"` or `"^1"`)
/// against `name`'s crates.io index, pick the highest matching non-yanked
/// version, and ensure it's downloaded + extracted into the local cache
/// (reused on later calls — the cache is keyed by name+version, so this
/// never re-fetches a version it already has). Dependency graph and
/// features for the resolved package come from its own extracted
/// `Cargo.toml`, parsed the same way as any local crate — the index is
/// used only to pick a version, not as a second source of truth for its
/// metadata.
pub fn resolve_and_fetch(name: &str, req: &str) -> ResolvedPackage {
    let requirement = semver::VersionReq::parse(req).unwrap_or_else(|e| {
        panic!("crates.io dependency \"{name}\": bad version requirement {req:?}: {e}")
    });

    let best = fetch_index(name)
        .into_iter()
        .filter(|e| !e.yanked)
        .filter_map(|e| semver::Version::parse(&e.vers).ok())
        .filter(|v| requirement.matches(v))
        .max()
        .unwrap_or_else(|| panic!("no version of \"{name}\" on crates.io satisfies {req:?}"));
    let version = best.to_string();

    let cache = cache_dir();
    let dest = cache.join(format!("{name}-{version}"));
    if !dest.join("Cargo.toml").is_file() {
        std::fs::create_dir_all(&cache).expect("create registry cache dir");
        eprintln!("fetching {name} {version} from crates.io ...");
        let url = format!("https://static.crates.io/crates/{name}/{name}-{version}.crate");
        let mut body = Vec::new();
        ureq::get(&url)
            .call()
            .unwrap_or_else(|e| panic!("download {name}-{version}.crate: {e}"))
            .body_mut()
            .as_reader()
            .read_to_end(&mut body)
            .unwrap_or_else(|e| panic!("read {name}-{version}.crate body: {e}"));
        let tar = flate2::read::GzDecoder::new(&body[..]);
        tar::Archive::new(tar)
            .unpack(&cache)
            .unwrap_or_else(|e| panic!("extract {name}-{version}.crate: {e}"));
    }

    ResolvedPackage { version, dir: dest }
}
