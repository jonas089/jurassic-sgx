//! Host-side workspace scanner (untrusted planning step — see the design
//! discussion this implements: the enclave never runs `cargo` or resolves
//! dependencies; it just executes an explicit, ordered `rustc --extern ...`
//! plan). This module discovers every local crate (a directory with a
//! `Cargo.toml` `[package]`) under a workspace root, resolves *local path*
//! dependencies between them (crates.io/registry deps are rejected), and
//! topologically sorts them into the `BuildPlanDto` the enclave will
//! execute — plus a ZKFS1 bundle of every `.rs` file in the tree so
//! `mod foo;` file resolution works exactly as it would on a real fs.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::public_values::{BuildPlanDto, PlanCrateType, PlanCrateUnit};
use crate::WORKSPACE_SRC_ROOT;

#[derive(serde::Deserialize)]
struct Manifest {
    package: Option<Package>,
    #[serde(default)]
    dependencies: BTreeMap<String, DepValue>,
}

#[derive(serde::Deserialize)]
struct Package {
    name: String,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum DepValue {
    Detailed { path: Option<String> },
    #[allow(dead_code)]
    Other(toml::Value),
}

struct LocalCrate {
    name: String,
    dir: PathBuf,
    entry: PathBuf,
    crate_type: PlanCrateType,
    /// (extern_name, dependency crate directory), resolved to a crate name
    /// once every manifest has been read.
    dep_dirs: Vec<(String, PathBuf)>,
}

fn normalize_name(name: &str) -> String {
    name.replace('-', "_")
}

fn walk(root: &Path, matches: &dyn Fn(&Path) -> bool, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let skip = path
                .file_name()
                .map(|n| n == "target" || n == ".git")
                .unwrap_or(false);
            if !skip {
                walk(&path, matches, out);
            }
        } else if matches(&path) {
            out.push(path);
        }
    }
}

/// Scan `root` for local crates and build the compile plan + packed source
/// tree. Panics with a clear message on crates.io/registry dependencies,
/// missing entry points, dependency cycles, or anything but exactly one
/// binary crate — all of these are workspace authoring mistakes the caller
/// needs to fix, not recoverable states.
pub fn discover(root: &Path) -> (BuildPlanDto, Vec<u8>) {
    let root = root.canonicalize().expect("canonicalize workspace root");

    let mut manifest_paths = Vec::new();
    walk(&root, &|p| p.file_name().map(|n| n == "Cargo.toml").unwrap_or(false), &mut manifest_paths);

    let mut crates: Vec<LocalCrate> = Vec::new();
    for manifest_path in &manifest_paths {
        let text = std::fs::read_to_string(manifest_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));
        let manifest: Manifest = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("parse {}: {e}", manifest_path.display()));
        let Some(package) = manifest.package else { continue }; // workspace-only manifest
        let dir = manifest_path.parent().unwrap().to_path_buf();

        let (entry, crate_type) = if dir.join("src/main.rs").is_file() {
            (dir.join("src/main.rs"), PlanCrateType::Bin)
        } else if dir.join("src/lib.rs").is_file() {
            (dir.join("src/lib.rs"), PlanCrateType::Lib)
        } else {
            panic!("crate {} has neither src/main.rs nor src/lib.rs", package.name);
        };

        let mut dep_dirs = Vec::new();
        for (dep_name, dep_value) in &manifest.dependencies {
            match dep_value {
                DepValue::Detailed { path: Some(rel) } => {
                    let dep_dir = dir.join(rel).canonicalize().unwrap_or_else(|e| {
                        panic!("dependency \"{dep_name}\" path {rel} (from {}): {e}", dir.display())
                    });
                    dep_dirs.push((dep_name.clone(), dep_dir));
                }
                _ => panic!(
                    "crate {} depends on \"{}\" without a `path = \"...\"` — only local path \
                     dependencies are supported (no crates.io/registry deps)",
                    package.name, dep_name
                ),
            }
        }

        crates.push(LocalCrate { name: normalize_name(&package.name), dir, entry, crate_type, dep_dirs });
    }

    if crates.is_empty() {
        panic!("no crates found under {}", root.display());
    }

    let dir_to_name: BTreeMap<PathBuf, String> =
        crates.iter().map(|c| (c.dir.clone(), c.name.clone())).collect();
    let externs: BTreeMap<String, Vec<(String, String)>> = crates
        .iter()
        .map(|c| {
            let edges = c
                .dep_dirs
                .iter()
                .map(|(extern_name, dep_dir)| {
                    let dep_name = dir_to_name.get(dep_dir).unwrap_or_else(|| {
                        panic!(
                            "crate {} depends on path {} which isn't a discovered crate under {}",
                            c.name, dep_dir.display(), root.display()
                        )
                    });
                    (normalize_name(extern_name), dep_name.clone())
                })
                .collect();
            (c.name.clone(), edges)
        })
        .collect();

    // Kahn's algorithm: `deps_remaining[name]` counts this crate's own local
    // deps not yet scheduled; `dependents[name]` lists crates depending on it.
    let mut deps_remaining: BTreeMap<String, usize> =
        crates.iter().map(|c| (c.name.clone(), externs[&c.name].len())).collect();
    let mut dependents: BTreeMap<String, Vec<String>> =
        crates.iter().map(|c| (c.name.clone(), Vec::new())).collect();
    for c in &crates {
        for (_, dep) in &externs[&c.name] {
            dependents.get_mut(dep).unwrap().push(c.name.clone());
        }
    }

    let mut queue: Vec<String> =
        deps_remaining.iter().filter(|(_, &d)| d == 0).map(|(n, _)| n.clone()).collect();
    queue.sort();
    let mut order = Vec::new();
    while let Some(name) = queue.pop() {
        order.push(name.clone());
        for dependent in dependents[&name].clone() {
            let d = deps_remaining.get_mut(&dependent).unwrap();
            *d -= 1;
            if *d == 0 {
                queue.push(dependent);
            }
        }
    }
    if order.len() != crates.len() {
        panic!("dependency cycle detected among local crates");
    }

    let bin_count = crates.iter().filter(|c| c.crate_type == PlanCrateType::Bin).count();
    if bin_count != 1 {
        panic!("expected exactly one binary crate (with src/main.rs), found {bin_count}");
    }

    let by_name: BTreeMap<&str, &LocalCrate> = crates.iter().map(|c| (c.name.as_str(), c)).collect();
    let units = order
        .iter()
        .map(|name| {
            let c = by_name[name.as_str()];
            let rel = c.entry.strip_prefix(&root).expect("entry under workspace root");
            PlanCrateUnit {
                name: c.name.clone(),
                entry: rel.to_string_lossy().replace('\\', "/"),
                crate_type: c.crate_type,
                externs: externs[&c.name].clone(),
            }
        })
        .collect();

    // Pack every .rs file under the workspace root, preserving relative
    // paths, so rustc's `mod foo;` sibling-file resolution works unmodified.
    // Mounted at WORKSPACE_SRC_ROOT inside the guest fs — the enclave builds
    // each unit's `entry` as `{WORKSPACE_SRC_ROOT}/{relative path}`.
    let mut rs_files = Vec::new();
    walk(&root, &|p| p.extension().map(|e| e == "rs").unwrap_or(false), &mut rs_files);
    let mut builder = rvlinux::bundle::Builder::new();
    for path in &rs_files {
        let rel = path.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
        let data = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        builder.file(&format!("{WORKSPACE_SRC_ROOT}/{rel}"), data, 0o644);
    }

    (BuildPlanDto { units }, builder.build())
}
