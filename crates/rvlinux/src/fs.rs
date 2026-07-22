//! In-memory filesystem with normalized absolute paths, plus fd table and pipes.
//!
//! Deterministic by construction: directory listings come from a BTreeMap so
//! they are always sorted; there are no timestamps unless we invent them.
//!
//! This module has no RISC-V ISA content of its own — it implements enough
//! of Linux's VFS/file-descriptor model (paths, symlinks, directories,
//! pipes, fd table) for `sys.rs`'s syscall handlers to sit on top of. See
//! `../SPEC.md`'s syscall coverage table for which filesystem syscalls are
//! implemented and which deliberately aren't (e.g. no real permission
//! enforcement — `add_file`/`create_file`'s `mode` is stored and returned by
//! `stat` but never checked against an access request).

use alloc::collections::BTreeMap;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

#[derive(Clone)]
pub enum FileData {
    Ro(Arc<Vec<u8>>),
    Rw(Vec<u8>),
}

impl FileData {
    /// Byte length regardless of which variant is holding the data.
    pub fn len(&self) -> u64 {
        match self {
            FileData::Ro(d) => d.len() as u64,
            FileData::Rw(d) => d.len() as u64,
        }
    }
    /// Borrow the contents regardless of variant — the read path never
    /// needs to know whether a file started as bundle-provided (`Ro`) or
    /// was created/written by the guest (`Rw`).
    pub fn bytes(&self) -> &[u8] {
        match self {
            FileData::Ro(d) => d,
            FileData::Rw(d) => d,
        }
    }
    /// Copy-on-write upgrade: a file that started as a shared, `Arc`-backed
    /// read-only blob (e.g. straight from the toolchain bundle) becomes its
    /// own private, mutable `Vec` the first time anything writes to it —
    /// so writing to one open file never mutates the shared bundle data
    /// other, unrelated file handles might still be referencing.
    fn make_rw(&mut self) -> &mut Vec<u8> {
        if let FileData::Ro(d) = self {
            *self = FileData::Rw(d.as_ref().clone());
        }
        match self {
            FileData::Rw(d) => d,
            _ => unreachable!(),
        }
    }
    /// Arc snapshot for mmap backing — `Memory::map`'s `Backing::File`
    /// holds an `Arc<Vec<u8>>` so a file-backed mapping keeps working even
    /// if the file is later modified or removed from the fs (matching
    /// Linux's "the mapping outlives an unlink" semantics).
    pub fn snapshot(&self) -> Arc<Vec<u8>> {
        match self {
            FileData::Ro(d) => d.clone(),
            FileData::Rw(d) => Arc::new(d.clone()),
        }
    }
}

#[derive(Clone)]
pub enum Node {
    Dir,
    File { data: FileData, mode: u32 },
    Symlink(String),
}

pub struct Fs {
    /// Normalized absolute path -> node. "/" itself is implicit.
    pub nodes: BTreeMap<String, Node>,
    /// Monotonic inode assignment for stat: path -> ino.
    inos: BTreeMap<String, u64>,
    next_ino: u64,
}

pub const ENOENT: i64 = 2;
pub const EBADF: i64 = 9;
pub const EACCES: i64 = 13;
pub const EFAULT: i64 = 14;
pub const EEXIST: i64 = 17;
pub const ENOTDIR: i64 = 20;
pub const EISDIR: i64 = 21;
pub const EINVAL: i64 = 22;
pub const EMFILE: i64 = 24;
pub const ENOTTY: i64 = 25;
pub const ESPIPE: i64 = 29;
pub const EPIPE: i64 = 32;
pub const ERANGE: i64 = 34;
pub const ENOSYS: i64 = 38;
pub const ENOTEMPTY: i64 = 39;
pub const ELOOP: i64 = 40;
pub const EAGAIN: i64 = 11;
pub const ECHILD: i64 = 10;
pub const ESRCH: i64 = 3;
pub const ENOTSOCK: i64 = 88;
pub const EAFNOSUPPORT: i64 = 97;
pub const ETIMEDOUT: i64 = 110;

/// Normalize `path` relative to `cwd` (both '/'-separated). Does NOT follow
/// symlinks; purely lexical for "." and "..", collapse of "//".
pub fn normalize(cwd: &str, path: &str) -> String {
    let mut comps: Vec<&str> = Vec::new();
    let base = if path.starts_with('/') { "" } else { cwd };
    for part in base.split('/').chain(path.split('/')) {
        match part {
            "" | "." => {}
            ".." => {
                comps.pop();
            }
            p => comps.push(p),
        }
    }
    let mut out = String::from("/");
    out.push_str(&comps.join("/"));
    out
}

/// The directory component of `path` (everything before the last `/`) —
/// used to find/create a new node's parent directory.
fn parent_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => path[..i].to_string(),
        None => "/".to_string(),
    }
}

impl Fs {
    /// Empty filesystem: just the implicit root — everything else (the
    /// toolchain bundle, workspace source tree, `/proc`/`/tmp` stubs) is
    /// added afterward via `bundle::parse_into` and `add_file`/`mkdir_all`.
    pub fn new() -> Self {
        Fs {
            nodes: BTreeMap::new(),
            inos: BTreeMap::new(),
            next_ino: 100,
        }
    }

    /// Assign (or recall) a stable inode number for `path` — Linux `stat`
    /// callers expect distinct files to have distinct, *stable-within-a-run*
    /// inode numbers (some build tools compare them for hardlink/identity
    /// detection); numbering starts at 100 and increases monotonically per
    /// first-seen path, so it's a pure function of access order, not real
    /// filesystem allocation.
    pub fn ino(&mut self, path: &str) -> u64 {
        if let Some(&i) = self.inos.get(path) {
            return i;
        }
        let i = self.next_ino;
        self.next_ino += 1;
        self.inos.insert(path.to_string(), i);
        i
    }

    /// `mkdir -p` — create every path component that doesn't already exist
    /// as a directory (existing entries, of any kind, are left untouched
    /// via `or_insert`).
    pub fn mkdir_all(&mut self, path: &str) {
        let norm = normalize("/", path);
        let mut cur = String::new();
        for part in norm.split('/').filter(|s| !s.is_empty()) {
            cur.push('/');
            cur.push_str(part);
            self.nodes.entry(cur.clone()).or_insert(Node::Dir);
        }
    }

    /// Install a read-only file at `path`, creating parent directories as
    /// needed. This is the bulk-loading path (`bundle::parse_into` calls it
    /// for every file in the packed toolchain/source tree) — `Ro` since
    /// bundle content should never need copying until something actually
    /// writes to it (see `FileData::make_rw`).
    pub fn add_file(&mut self, path: &str, data: Vec<u8>, mode: u32) {
        let norm = normalize("/", path);
        self.mkdir_all(&parent_of(&norm));
        self.nodes.insert(
            norm,
            Node::File {
                data: FileData::Ro(Arc::new(data)),
                mode,
            },
        );
    }

    /// Install a symlink at `path` pointing at `target` (not resolved or
    /// validated here — `resolve` is what follows it later).
    pub fn add_symlink(&mut self, path: &str, target: &str) {
        let norm = normalize("/", path);
        self.mkdir_all(&parent_of(&norm));
        self.nodes.insert(norm, Node::Symlink(target.to_string()));
    }

    /// Resolve symlinks in all components of `path` (which must already be
    /// normalized absolute). Returns final normalized path (whose last
    /// component may or may not exist). If `follow_last` is false, a symlink
    /// in the final component is not followed — this is exactly the
    /// `AT_SYMLINK_NOFOLLOW`/`lstat`-vs-`stat` distinction Linux path
    /// resolution makes. The 40-hop symlink-loop limit (`ELOOP`) matches
    /// Linux's own `MAXSYMLINKS`, not an arbitrary choice.
    pub fn resolve(&self, path: &str, follow_last: bool) -> Result<String, i64> {
        let mut result = String::from("/");
        let comps: Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let mut hops = 0;
        let mut stack: Vec<String> = comps;
        stack.reverse();
        let mut resolved: Vec<String> = Vec::new();
        while let Some(comp) = stack.pop() {
            match comp.as_str() {
                "" | "." => continue,
                ".." => {
                    resolved.pop();
                    continue;
                }
                _ => {}
            }
            resolved.push(comp);
            let cur = {
                let mut s = String::from("/");
                s.push_str(&resolved.join("/"));
                s
            };
            let is_last = stack.is_empty();
            if let Some(Node::Symlink(t)) = self.nodes.get(&cur) {
                if is_last && !follow_last {
                    break;
                }
                hops += 1;
                if hops > 40 {
                    return Err(ELOOP);
                }
                resolved.pop();
                let target = t.clone();
                if target.starts_with('/') {
                    resolved.clear();
                }
                // push target components (reversed) back onto stack
                let tcomps: Vec<String> = target
                    .split('/')
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect();
                for c in tcomps.into_iter().rev() {
                    stack.push(c);
                }
            }
        }
        result.push_str(&resolved.join("/"));
        Ok(result)
    }

    /// Look up an already-`resolve`d path. `/` itself is special-cased since
    /// the root directory is implicit (never actually stored as a `Node` in
    /// `nodes`) — every other directory *does* get an explicit `Node::Dir`
    /// entry via `mkdir_all`.
    pub fn get(&self, resolved: &str) -> Option<&Node> {
        if resolved == "/" {
            return Some(&Node::Dir);
        }
        self.nodes.get(resolved)
    }

    /// `getdents64`'s data source: every direct child of `dir`, as
    /// `(name, d_type)` pairs using the real Linux `DT_*` constants
    /// (`DT_DIR`=4, `DT_REG`=8, `DT_LNK`=10) so callers can pass them
    /// straight through to a `linux_dirent64` buffer. Walking a `BTreeMap`
    /// range naturally yields entries in sorted order — this is also what
    /// makes directory listings deterministic across runs, since a real
    /// filesystem's readdir order is normally unspecified/insertion-order-
    /// dependent.
    pub fn list_dir(&self, dir: &str) -> Vec<(String, u8)> {
        let prefix = if dir == "/" {
            String::from("/")
        } else {
            let mut p = dir.to_string();
            p.push('/');
            p
        };
        let mut out = Vec::new();
        for (path, node) in self.nodes.range(prefix.clone()..) {
            if !path.starts_with(prefix.as_str()) {
                break;
            }
            let rest = &path[prefix.len()..];
            if rest.is_empty() || rest.contains('/') {
                continue;
            }
            let dt = match node {
                Node::Dir => 4u8,      // DT_DIR
                Node::File { .. } => 8, // DT_REG
                Node::Symlink(_) => 10, // DT_LNK
            };
            out.push((rest.to_string(), dt));
        }
        out
    }

    /// `open(2)` with `O_CREAT`: makes a new, empty, writable file at an
    /// already-resolved path, provided the parent directory actually
    /// exists (`ENOENT` otherwise — matches Linux: you can't create a file
    /// in a nonexistent directory) and nothing with that name is already a
    /// directory (`EISDIR`).
    pub fn create_file(&mut self, resolved: &str, mode: u32) -> Result<(), i64> {
        if let Some(Node::Dir) = self.nodes.get(resolved) {
            return Err(EISDIR);
        }
        let parent = parent_of(resolved);
        if parent != "/" && !matches!(self.get(&parent), Some(Node::Dir)) {
            return Err(ENOENT);
        }
        self.nodes.insert(
            resolved.to_string(),
            Node::File {
                data: FileData::Rw(Vec::new()),
                mode,
            },
        );
        Ok(())
    }

    /// `pwrite64`'s core: write `buf` at absolute offset `pos`, growing the
    /// file (zero-filling any gap) if `pos + buf.len()` extends past the
    /// current end — matching POSIX `pwrite`'s "writing past EOF extends
    /// the file, with a hole read back as zero" behavior. Every write
    /// syscall in `sys.rs` (`write`, `pwrite64`, append-mode `write_to_fd`,
    /// ...) funnels through this.
    pub fn write_at(&mut self, resolved: &str, pos: u64, buf: &[u8]) -> Result<usize, i64> {
        match self.nodes.get_mut(resolved) {
            Some(Node::File { data, .. }) => {
                let v = data.make_rw();
                let end = pos as usize + buf.len();
                if v.len() < end {
                    v.resize(end, 0);
                }
                v[pos as usize..end].copy_from_slice(buf);
                Ok(buf.len())
            }
            Some(_) => Err(EISDIR),
            None => Err(ENOENT),
        }
    }

    /// `ftruncate(2)`: resize a file in place, zero-filling on grow —
    /// backs both the `ftruncate` syscall and `openat`'s `O_TRUNC` flag.
    pub fn truncate(&mut self, resolved: &str, len: u64) -> Result<(), i64> {
        match self.nodes.get_mut(resolved) {
            Some(Node::File { data, .. }) => {
                data.make_rw().resize(len as usize, 0);
                Ok(())
            }
            Some(_) => Err(EISDIR),
            None => Err(ENOENT),
        }
    }
}

// ---- fd table ----

#[derive(Clone)]
pub enum FdKind {
    Stdin,
    Stdout,
    Stderr,
    File { path: String, pos: u64, append: bool },
    Dir { path: String, pos: u64 },
    PipeR { id: usize },
    PipeW { id: usize },
}

#[derive(Clone)]
pub struct Fd {
    pub kind: FdKind,
    pub cloexec: bool,
    pub nonblock: bool,
}

pub struct Pipe {
    pub buf: VecDeque<u8>,
    pub readers: u32,
    pub writers: u32,
}

pub struct FdTable {
    pub fds: Vec<Option<Fd>>,
    pub pipes: Vec<Pipe>,
}

impl FdTable {
    /// Every process starts with exactly fds 0/1/2 = stdin/stdout/stderr
    /// already open — the POSIX/Linux convention every C runtime assumes
    /// without ever calling `open` for them.
    pub fn new() -> Self {
        FdTable {
            fds: alloc::vec![
                Some(Fd { kind: FdKind::Stdin, cloexec: false, nonblock: false }),
                Some(Fd { kind: FdKind::Stdout, cloexec: false, nonblock: false }),
                Some(Fd { kind: FdKind::Stderr, cloexec: false, nonblock: false }),
            ],
            pipes: Vec::new(),
        }
    }

    /// Allocate the lowest-numbered free fd `>= min` (POSIX's mandated
    /// "lowest available" allocation policy — required by `dup2`/`F_DUPFD`
    /// callers, and by plain `open` returning predictable fd numbers),
    /// growing the table if every existing slot at/above `min` is taken.
    pub fn alloc(&mut self, fd: Fd, min: usize) -> i64 {
        for i in min..self.fds.len() {
            if self.fds[i].is_none() {
                self.fds[i] = Some(fd);
                return i as i64;
            }
        }
        if self.fds.len() < min {
            self.fds.resize(min, None);
        }
        self.fds.push(Some(fd));
        (self.fds.len() - 1) as i64
    }

    /// Look up an open fd — negative fds (and anything past the table end
    /// or already closed) return `None`, becoming `EBADF` at the syscall
    /// layer, matching Linux's rejection of negative fd numbers.
    pub fn get(&self, fd: i64) -> Option<&Fd> {
        if fd < 0 {
            return None;
        }
        self.fds.get(fd as usize)?.as_ref()
    }

    /// Mutable counterpart of `get`, for handlers that update fd state in
    /// place (e.g. advancing a file's read/write position).
    pub fn get_mut(&mut self, fd: i64) -> Option<&mut Fd> {
        if fd < 0 {
            return None;
        }
        self.fds.get_mut(fd as usize)?.as_mut()
    }

    /// `close(2)`: frees the fd slot and, for a pipe end, decrements the
    /// pipe's reader/writer count — that count is what lets a pipe reader
    /// see EOF once every writer has closed (checked in `sys_read`), the
    /// same "last writer closing signals EOF" contract real Linux pipes
    /// have.
    pub fn close(&mut self, fd: i64) -> Result<Fd, i64> {
        if fd < 0 || fd as usize >= self.fds.len() {
            return Err(EBADF);
        }
        let old = self.fds[fd as usize].take().ok_or(EBADF)?;
        match &old.kind {
            FdKind::PipeR { id } => self.pipes[*id].readers -= 1,
            FdKind::PipeW { id } => self.pipes[*id].writers -= 1,
            _ => {}
        }
        Ok(old)
    }
}
