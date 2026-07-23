//! Host-side workspace scanner (untrusted planning step — the enclave never
//! runs `cargo` or resolves dependencies/features itself; it just executes
//! an explicit, ordered `rustc --extern --cfg` plan). This module:
//!
//! - discovers every local crate (a directory with a `Cargo.toml`
//!   `[package]`) under a workspace root;
//! - resolves local *path* dependencies directly, and crates.io
//!   dependencies by fetching them (see `registry`), recursively, following
//!   *their* dependencies the same way;
//! - resolves Cargo's `[features]` graph (default features, optional
//!   dependencies, `dep:name` / bare-name activation — see `expand_features`
//!   for exactly what subset is implemented) to decide which crates and
//!   which `#[cfg(feature = ...)]` branches are actually reachable from the
//!   one binary crate being built;
//! - topologically sorts the reachable set into the `BuildPlanDto` the
//!   enclave will execute, plus a ZKFS1 bundle of every `.rs` file needed
//!   (workspace-local files under the workspace root, fetched crates.io
//!   packages under their own `registry/<name>-<version>/` prefix) so
//!   `mod foo;` file resolution works exactly as it would on a real fs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::public_values::{BuildPlanDto, PlanCrateType, PlanCrateUnit};
use crate::WORKSPACE_SRC_ROOT;

#[derive(serde::Deserialize)]
struct Manifest {
    package: Option<Package>,
    #[serde(default)]
    dependencies: BTreeMap<String, DepValue>,
    /// Only ever merged into the *root bin crate's* own `deps` (see
    /// `load_crate`), and only when the caller opts in — matching real
    /// Cargo, where dev-dependencies are never linked into a normal build,
    /// only test/bench/example builds, and never propagate to a crate's
    /// dependents.
    #[serde(rename = "dev-dependencies", default)]
    dev_dependencies: BTreeMap<String, DepValue>,
    #[serde(default)]
    features: BTreeMap<String, Vec<String>>,
}

#[derive(serde::Deserialize)]
struct Package {
    name: String,
    #[serde(default)]
    edition: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum DepValue {
    /// `foo = "1.2"` — a bare version requirement string.
    Simple(String),
    /// `foo = { path = "...", version = "...", optional = ..., features =
    /// [...], default-features = ..., package = "..." }` — any subset of
    /// these keys; all but one (`path` or `version`) are optional.
    Detailed {
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        optional: bool,
        #[serde(default)]
        features: Vec<String>,
        #[serde(default = "default_true")]
        default_features: bool,
        #[serde(default)]
        package: Option<String>,
    },
}

fn default_true() -> bool {
    true
}

/// Where one dependency edge points: an already-canonicalized local
/// directory, or a crates.io package name + version requirement still to
/// be resolved (see `registry::resolve_and_fetch`).
enum DepTarget {
    Local(PathBuf),
    Registry { crate_name: String, req: String },
}

/// One `[dependencies]` entry, as declared — not yet known to be reachable
/// (that's decided later by feature activation).
struct DepEdge {
    /// What the depending crate's source uses (`use extern_name::...`);
    /// normalized (`-` -> `_`) since that's what Rust identifiers require.
    extern_name: String,
    target: DepTarget,
    optional: bool,
    requested_features: Vec<String>,
    default_features: bool,
}

/// One discovered crate — local or fetched from crates.io; treated
/// uniformly from here on (both are just "a directory with a Cargo.toml").
struct Crate {
    /// Path relative to `WORKSPACE_SRC_ROOT`, forward-slash — already
    /// accounts for whether this crate's files are packed under the
    /// workspace root directly (local) or under `registry/<name>-<version>/`
    /// (fetched; see `registry_pack`).
    entry_rel: String,
    crate_type: PlanCrateType,
    edition: String,
    features_table: BTreeMap<String, Vec<String>>,
    deps: Vec<DepEdge>,
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

/// Pack every `.rs` file under `dir` into `builder`, mounted at
/// `WORKSPACE_SRC_ROOT/<prefix><path relative to dir>`.
fn pack_tree(builder: &mut rvlinux::bundle::Builder, dir: &Path, prefix: &str) {
    let mut rs_files = Vec::new();
    walk(dir, &|p| p.extension().map(|e| e == "rs").unwrap_or(false), &mut rs_files);
    for path in &rs_files {
        let rel = path.strip_prefix(dir).unwrap().to_string_lossy().replace('\\', "/");
        let data = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        builder.file(&format!("{WORKSPACE_SRC_ROOT}/{prefix}{rel}"), data, 0o644);
    }
}

/// Turn a manifest's `[dependencies]` table into `DepEdge`s. `allow_path`
/// is false for crates.io-fetched manifests: once a crate is published,
/// Cargo (and this scanner) ignores any `path` key on *its* dependencies
/// and resolves by version instead — `path` deps only make sense inside
/// the original author's own workspace.
fn dep_edges(dir: &Path, deps: &BTreeMap<String, DepValue>, allow_path: bool) -> Vec<DepEdge> {
    deps.iter()
        .map(|(key, v)| {
            let (path, version, optional, features, default_features, package) = match v {
                DepValue::Simple(ver) => (None, Some(ver.clone()), false, Vec::new(), true, None),
                DepValue::Detailed { path, version, optional, features, default_features, package } => {
                    (path.clone(), version.clone(), *optional, features.clone(), *default_features, package.clone())
                }
            };
            let target = if allow_path && path.is_some() {
                let rel = path.unwrap();
                let dep_dir = dir.join(&rel).canonicalize().unwrap_or_else(|e| {
                    panic!("dependency \"{key}\" path {rel} (from {}): {e}", dir.display())
                });
                DepTarget::Local(dep_dir)
            } else if let Some(req) = version {
                DepTarget::Registry { crate_name: package.unwrap_or_else(|| key.clone()), req }
            } else {
                panic!(
                    "crate at {}: dependency \"{key}\" needs a `path` (local) or a version \
                     requirement (crates.io) — dev-dependencies, git deps, and other forms \
                     aren't supported",
                    dir.display()
                );
            };
            DepEdge {
                extern_name: normalize_name(key),
                target,
                optional,
                requested_features: features,
                default_features,
            }
        })
        .collect()
}

/// Parse `dir/Cargo.toml` and turn it into a `(unit name, Crate)`.
/// `is_registry` controls both `dep_edges`'s `path`-ignoring behavior and
/// entry-point resolution: a fetched dependency must be a library (no
/// `src/main.rs` fallback — we don't want to accidentally build someone
/// else's binary as part of this one). `strip_base` is what the entry
/// path is made relative to (the workspace root for a local crate, since
/// `pack_tree` packs the whole local tree relative to it in one walk; the
/// crate's own directory for a registry crate, since each is packed
/// separately under its own prefix) and `entry_rel_prefix` is prepended
/// after that (empty for local, `registry/<name>-<version>/` for fetched).
/// `want_dev_deps` requests merging `[dev-dependencies]` into this crate's
/// own `deps`, but only takes effect if this crate turns out to be the
/// (local, binary) one — matching Cargo's rule that dev-dependencies apply
/// only to the crate being built directly, never to a dependency (pass
/// `false` for every registry crate) and never propagate to dependents.
fn load_crate(
    dir: &Path,
    is_registry: bool,
    strip_base: &Path,
    entry_rel_prefix: &str,
    want_dev_deps: bool,
) -> (String, Crate) {
    let manifest_path = dir.join("Cargo.toml");
    let text = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));
    let manifest: Manifest = toml::from_str(&text)
        .unwrap_or_else(|e| panic!("parse {}: {e}", manifest_path.display()));
    let package = manifest
        .package
        .unwrap_or_else(|| panic!("{}: missing [package]", manifest_path.display()));
    // Cargo's real default when `edition` is omitted.
    let edition = package.edition.unwrap_or_else(|| "2015".to_string());

    let (entry, crate_type) = if is_registry {
        if dir.join("src/lib.rs").is_file() {
            (dir.join("src/lib.rs"), PlanCrateType::Lib)
        } else {
            panic!(
                "crates.io dependency \"{}\" has no src/lib.rs — only library crates.io \
                 dependencies are supported",
                package.name
            );
        }
    } else if dir.join("src/main.rs").is_file() {
        (dir.join("src/main.rs"), PlanCrateType::Bin)
    } else if dir.join("src/lib.rs").is_file() {
        (dir.join("src/lib.rs"), PlanCrateType::Lib)
    } else {
        panic!("crate {} has neither src/main.rs nor src/lib.rs", package.name);
    };

    let entry_rel = format!(
        "{entry_rel_prefix}{}",
        entry.strip_prefix(strip_base).unwrap().to_string_lossy().replace('\\', "/")
    );
    let mut deps = dep_edges(dir, &manifest.dependencies, !is_registry);
    if want_dev_deps && !is_registry && crate_type == PlanCrateType::Bin {
        deps.extend(dep_edges(dir, &manifest.dev_dependencies, true));
    }
    let name = normalize_name(&package.name);
    (
        name,
        Crate { entry_rel, crate_type, edition, features_table: manifest.features, deps },
    )
}

/// Expand a requested feature set through `table` (this crate's own
/// `[features]` graph) into the final activated feature names plus the set
/// of optional dependencies it activates. Handles plain feature names
/// (recursively), `dep:name` (activates the named optional dependency
/// without also implying a same-named feature), and bare names that match
/// an optional dependency (legacy Cargo behavior: naming an optional
/// dependency directly in a feature list activates it *and* implies a
/// feature of that same name). Does **not** implement the `pkg/feat` /
/// `pkg?/feat` syntax's specific "activate `feat` on `pkg`" effect beyond
/// activating `pkg` itself — the extra feature request on the dependency is
/// dropped. That's a real gap versus Cargo, scoped out for now.
fn expand_features(
    table: &BTreeMap<String, Vec<String>>,
    optional_dep_names: &BTreeSet<String>,
    requested: &BTreeSet<String>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let mut seen = BTreeSet::new();
    let mut active_features = BTreeSet::new();
    let mut active_deps = BTreeSet::new();
    let mut queue: Vec<String> = requested.iter().cloned().collect();
    while let Some(item) = queue.pop() {
        if !seen.insert(item.clone()) {
            continue;
        }
        if let Some(dep) = item.strip_prefix("dep:") {
            active_deps.insert(dep.to_string());
            continue;
        }
        if let Some((pkg, _feat)) = item.split_once('/') {
            active_deps.insert(pkg.trim_end_matches('?').to_string());
            continue;
        }
        if optional_dep_names.contains(&item) {
            active_deps.insert(item.clone());
        }
        active_features.insert(item.clone());
        if let Some(implied) = table.get(&item) {
            queue.extend(implied.iter().cloned());
        }
    }
    (active_features, active_deps)
}

/// Scan `root` for local crates (recursively fetching any crates.io
/// dependencies it finds — see module doc), resolve which crates and
/// features are actually reachable from the one binary crate, and build the
/// compile plan + packed source tree. `include_dev_deps` makes the root bin
/// crate's `[dev-dependencies]` available to it too (as ordinary `--extern`s
/// — there's no separate test-harness mode here; the attested run *is* the
/// bin crate's `_start`, dev-deps and all). Panics with a clear message on
/// missing entry points, dependency cycles, or anything but exactly one
/// local binary crate — all of these are workspace authoring mistakes the
/// caller needs to fix, not recoverable states.
pub fn discover(root: &Path, include_dev_deps: bool) -> (BuildPlanDto, Vec<u8>) {
    let root = root.canonicalize().expect("canonicalize workspace root");

    // 1. Discover every local crate under `root`.
    let mut manifest_paths = Vec::new();
    walk(&root, &|p| p.file_name().map(|n| n == "Cargo.toml").unwrap_or(false), &mut manifest_paths);

    let mut crates: BTreeMap<String, Crate> = BTreeMap::new();
    let mut dir_to_name: BTreeMap<PathBuf, String> = BTreeMap::new();
    for manifest_path in &manifest_paths {
        let text = std::fs::read_to_string(manifest_path)
            .unwrap_or_else(|e| panic!("read {}: {e}", manifest_path.display()));
        let peek: Manifest = toml::from_str(&text)
            .unwrap_or_else(|e| panic!("parse {}: {e}", manifest_path.display()));
        if peek.package.is_none() {
            continue; // workspace-only manifest
        }
        let dir = manifest_path.parent().unwrap().to_path_buf();
        let (name, krate) = load_crate(&dir, false, &root, "", include_dev_deps);
        dir_to_name.insert(dir, name.clone());
        crates.insert(name, krate);
    }
    if crates.is_empty() {
        panic!("no crates found under {}", root.display());
    }

    // 2. Exactly one local binary crate (registry crates can never be one —
    // see `load_crate` — so this check only needs what step 1 found).
    let bin_units: Vec<String> = crates
        .iter()
        .filter(|(_, c)| c.crate_type == PlanCrateType::Bin)
        .map(|(n, _)| n.clone())
        .collect();
    if bin_units.len() != 1 {
        panic!("expected exactly one binary crate (with src/main.rs), found {}", bin_units.len());
    }
    let bin_name = bin_units[0].clone();

    // 3. Dependency edges, resolved to concrete unit names — but a registry
    // target's *manifest* (its own deps/features/edition) is only fetched
    // lazily, in step 4, the first time some activated feature set actually
    // reaches it. This matters: a crate can declare an optional dependency
    // (with its own further dependency tree) that nothing ever activates —
    // eagerly fetching those would mean needless network round-trips at
    // best, and a hard failure at worst if that unused branch happens to be
    // something this scanner can't handle (e.g. a proc-macro crate).
    struct ResolvedEdge {
        extern_name: String,
        dep_unit: String,
        optional: bool,
        requested_features: Vec<String>,
        default_features: bool,
    }
    let mut edges: BTreeMap<String, Vec<ResolvedEdge>> = BTreeMap::new();
    // unit name -> (crates.io name, version requirement) for the first edge
    // that referenced it — what `resolve_and_fetch` needs once activated.
    let mut registry_targets: BTreeMap<String, (String, String)> = BTreeMap::new();
    // unit name -> (extracted source dir, bundle pack prefix), filled in as
    // each registry crate is actually fetched.
    let mut registry_pack: BTreeMap<String, (PathBuf, String)> = BTreeMap::new();

    fn resolve_edges(
        name: &str,
        c: &Crate,
        dir_to_name: &BTreeMap<PathBuf, String>,
        registry_targets: &mut BTreeMap<String, (String, String)>,
    ) -> Vec<ResolvedEdge> {
        c.deps
            .iter()
            .map(|d| {
                let dep_unit = match &d.target {
                    DepTarget::Local(dir) => dir_to_name.get(dir).cloned().unwrap_or_else(|| {
                        panic!(
                            "crate {name} depends on path {} which isn't a discovered crate",
                            dir.display()
                        )
                    }),
                    DepTarget::Registry { crate_name, req } => {
                        let unit = normalize_name(crate_name);
                        registry_targets
                            .entry(unit.clone())
                            .or_insert_with(|| (crate_name.clone(), req.clone()));
                        unit
                    }
                };
                ResolvedEdge {
                    extern_name: d.extern_name.clone(),
                    dep_unit,
                    optional: d.optional,
                    requested_features: d.requested_features.clone(),
                    default_features: d.default_features,
                }
            })
            .collect()
    }
    for (name, c) in &crates {
        let resolved = resolve_edges(name, c, &dir_to_name, &mut registry_targets);
        edges.insert(name.clone(), resolved);
    }

    // 4. Feature activation + reachability: a worklist fixed-point starting
    // from the bin crate's own default features, propagating requested
    // features down activated dependency edges (optional deps only become
    // reachable once something enables them) until nothing changes.
    // `requested[unit]` accumulates every feature anyone has asked `unit`
    // to activate so far; `resolved_features`/`resolved_active_deps` hold
    // the settled expansion for units that have been processed at least
    // once (a unit is "activated"/reachable iff it has an entry here). A
    // unit reached for the first time that isn't in `crates` yet is, by
    // construction, a registry target recorded in `registry_targets` —
    // fetched right here, the only place any network access happens.
    let mut requested: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    requested.entry(bin_name.clone()).or_default().insert("default".to_string());
    let mut resolved_features: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut resolved_active_deps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut worklist: Vec<String> = vec![bin_name.clone()];

    while let Some(name) = worklist.pop() {
        if !crates.contains_key(&name) {
            let (crate_name, req) = registry_targets
                .get(&name)
                .unwrap_or_else(|| panic!("internal error: unresolved unit \"{name}\""))
                .clone();
            let resolved = crate::registry::resolve_and_fetch(&crate_name, &req);
            let prefix = format!("registry/{crate_name}-{}/", resolved.version);
            let (_, krate) = load_crate(&resolved.dir, true, &resolved.dir, &prefix, false);
            let unit_edges = resolve_edges(&name, &krate, &dir_to_name, &mut registry_targets);
            edges.insert(name.clone(), unit_edges);
            registry_pack.insert(name.clone(), (resolved.dir, prefix));
            crates.insert(name.clone(), krate);
        }

        let c = &crates[&name];
        let optional_names: BTreeSet<String> =
            c.deps.iter().filter(|d| d.optional).map(|d| d.extern_name.clone()).collect();
        let req = requested.get(&name).cloned().unwrap_or_default();
        let (active_features, active_deps) = expand_features(&c.features_table, &optional_names, &req);
        resolved_features.insert(name.clone(), active_features);
        resolved_active_deps.insert(name.clone(), active_deps.clone());

        for edge in &edges[&name] {
            if edge.optional && !active_deps.contains(&edge.extern_name) {
                continue;
            }
            let already_seen = requested.contains_key(&edge.dep_unit);
            let entry = requested.entry(edge.dep_unit.clone()).or_default();
            let mut grew = !already_seen;
            if edge.default_features {
                grew |= entry.insert("default".to_string());
            }
            for f in &edge.requested_features {
                grew |= entry.insert(f.clone());
            }
            if grew {
                worklist.push(edge.dep_unit.clone());
            }
        }
    }
    let activated: BTreeSet<String> = resolved_features.keys().cloned().collect();

    // 6. Filter every unit's edges down to the ones actually activated
    // (respecting each edge's own optional-activation decision from step 5),
    // then Kahn's algorithm over that subgraph.
    let mut final_edges: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for name in &activated {
        let active_deps = &resolved_active_deps[name];
        let list: Vec<(String, String)> = edges[name]
            .iter()
            .filter(|e| activated.contains(&e.dep_unit))
            .filter(|e| !e.optional || active_deps.contains(&e.extern_name))
            .map(|e| (e.extern_name.clone(), e.dep_unit.clone()))
            .collect();
        final_edges.insert(name.clone(), list);
    }

    let mut deps_remaining: BTreeMap<String, usize> =
        activated.iter().map(|n| (n.clone(), final_edges[n].len())).collect();
    let mut dependents: BTreeMap<String, Vec<String>> =
        activated.iter().map(|n| (n.clone(), Vec::new())).collect();
    for name in &activated {
        for (_, dep) in &final_edges[name] {
            dependents.get_mut(dep).unwrap().push(name.clone());
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
    if order.len() != activated.len() {
        panic!("dependency cycle detected among activated crates");
    }

    // 7. Build the plan, then pack the source tree: local files in one walk
    // over the workspace root, each activated fetched registry package
    // under its own recorded prefix.
    let units = order
        .iter()
        .map(|name| {
            let c = &crates[name];
            let mut cfg_features: Vec<String> = resolved_features[name].iter().cloned().collect();
            cfg_features.sort();
            PlanCrateUnit {
                name: name.clone(),
                entry: c.entry_rel.clone(),
                crate_type: c.crate_type,
                edition: c.edition.clone(),
                cfg_features,
                externs: final_edges[name].clone(),
            }
        })
        .collect();

    let mut builder = rvlinux::bundle::Builder::new();
    pack_tree(&mut builder, &root, "");
    for name in &activated {
        if let Some((dir, prefix)) = registry_pack.get(name) {
            pack_tree(&mut builder, dir, prefix);
        }
    }

    (BuildPlanDto { units }, builder.build())
}
