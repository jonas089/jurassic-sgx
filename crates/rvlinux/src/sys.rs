//! Linux syscall emulation (riscv64 ABI), deterministic by construction.

use alloc::string::String;
use alloc::vec::Vec;

use crate::fs::*;
use crate::mem::Backing;
use crate::{BlockOn, Machine, TimeoutPolicy};

pub enum SysResult {
    Ret(i64),
    Block(BlockOn),
    ExitThread(i32),
    ExitGroup(i32),
    Unhandled(u64),
}

const AT_FDCWD: i64 = -100;

// open flags
const O_WRONLY: u64 = 1;
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0x40;
const O_EXCL: u64 = 0x80;
const O_TRUNC: u64 = 0x200;
const O_APPEND: u64 = 0x400;
const O_NONBLOCK: u64 = 0x800;
const O_DIRECTORY: u64 = 0x10000;
const O_CLOEXEC: u64 = 0x80000;

const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;
const S_IFIFO: u32 = 0o010000;
const S_IFCHR: u32 = 0o020000;

impl Machine {
    /// Resolve a (dirfd, path) pair to a normalized absolute path (before
    /// symlink resolution).
    fn at_path(&mut self, dirfd: i64, path_ptr: u64) -> Result<String, i64> {
        let raw = self
            .mem
            .read_cstr(path_ptr, 4096)
            .map_err(|_| EFAULT)?;
        let path = String::from_utf8_lossy(&raw).into_owned();
        if path.starts_with('/') {
            return Ok(normalize("/", &path));
        }
        let base = if dirfd == AT_FDCWD {
            self.cwd.clone()
        } else {
            match self.fdt.get(dirfd).map(|f| f.kind.clone()) {
                Some(FdKind::Dir { path, .. }) => path,
                Some(FdKind::File { path, .. }) => path,
                _ => return Err(EBADF),
            }
        };
        Ok(normalize(&base, &path))
    }

    fn write_stat(&mut self, addr: u64, node_path: Option<&str>, kind: &FdKind) -> Result<(), i64> {
        let mut buf = [0u8; 128];
        let put32 = |b: &mut [u8; 128], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
        let put64 = |b: &mut [u8; 128], off: usize, v: u64| b[off..off + 8].copy_from_slice(&v.to_le_bytes());

        let (mode, size, ino) = match kind {
            FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => (S_IFCHR | 0o620, 0u64, 10),
            FdKind::PipeR { id } | FdKind::PipeW { id } => (S_IFIFO | 0o600, 0, 50 + *id as u64),
            FdKind::Dir { path, .. } => (S_IFDIR | 0o755, 4096, self.fs.ino(path)),
            FdKind::File { path, .. } => {
                let p = path.clone();
                match self.fs.get(&p) {
                    Some(Node::File { data, mode }) => {
                        let sz = data.len();
                        let m = *mode;
                        (S_IFREG | (m & 0o7777), sz, self.fs.ino(&p))
                    }
                    Some(Node::Dir) => (S_IFDIR | 0o755, 4096, self.fs.ino(&p)),
                    Some(Node::Symlink(t)) => {
                        let l = t.len() as u64;
                        (S_IFLNK | 0o777, l, self.fs.ino(&p))
                    }
                    None => return Err(ENOENT),
                }
            }
        };
        let _ = node_path;
        put64(&mut buf, 0, 23); // st_dev
        put64(&mut buf, 8, ino);
        put32(&mut buf, 16, mode);
        put32(&mut buf, 20, 1); // nlink
        put32(&mut buf, 24, 0); // uid
        put32(&mut buf, 28, 0); // gid
        put64(&mut buf, 32, 0); // rdev
        put64(&mut buf, 48, size);
        put32(&mut buf, 56, 4096); // blksize
        put64(&mut buf, 64, (size + 511) / 512); // blocks
        // atime/mtime/ctime: fixed epoch for determinism
        for off in [72usize, 88, 104] {
            put64(&mut buf, off, 1_700_000_000);
        }
        self.mem.write_bytes(addr, &buf).map_err(|_| EFAULT)
    }

    fn stat_path(&mut self, path: &str, follow: bool, addr: u64) -> Result<(), i64> {
        let resolved = self.fs.resolve(path, follow)?;
        match self.fs.get(&resolved) {
            Some(_) => {
                let kind = FdKind::File {
                    path: resolved,
                    pos: 0,
                    append: false,
                };
                self.write_stat(addr, None, &kind)
            }
            None => Err(ENOENT),
        }
    }

    pub(crate) fn syscall(&mut self, n: u64, a: [u64; 6]) -> SysResult {
        use SysResult::*;
        match n {
            17 => {
                // getcwd
                let cwd = self.cwd.clone();
                let need = cwd.len() as u64 + 1;
                if a[1] < need {
                    return Ret(-ERANGE);
                }
                let mut bytes = Vec::from(cwd.as_bytes());
                bytes.push(0);
                if self.mem.write_bytes(a[0], &bytes).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(need as i64)
            }
            23 => {
                // dup
                match self.fdt.get(a[0] as i64).cloned() {
                    Some(fd) => {
                        if let FdKind::PipeR { id } = fd.kind {
                            self.fdt.pipes[id].readers += 1;
                        } else if let FdKind::PipeW { id } = fd.kind {
                            self.fdt.pipes[id].writers += 1;
                        }
                        Ret(self.fdt.alloc(fd, 0))
                    }
                    None => Ret(-EBADF),
                }
            }
            24 => {
                // dup3
                let old = a[0] as i64;
                let new = a[1] as i64;
                if old == new {
                    return Ret(-EINVAL);
                }
                match self.fdt.get(old).cloned() {
                    Some(mut fd) => {
                        fd.cloexec = a[2] & O_CLOEXEC != 0;
                        if let FdKind::PipeR { id } = fd.kind {
                            self.fdt.pipes[id].readers += 1;
                        } else if let FdKind::PipeW { id } = fd.kind {
                            self.fdt.pipes[id].writers += 1;
                        }
                        let _ = self.fdt.close(new);
                        if (new as usize) >= self.fdt.fds.len() {
                            self.fdt.fds.resize(new as usize + 1, None);
                        }
                        self.fdt.fds[new as usize] = Some(fd);
                        Ret(new)
                    }
                    None => Ret(-EBADF),
                }
            }
            25 => {
                // fcntl
                const F_DUPFD: u64 = 0;
                const F_GETFD: u64 = 1;
                const F_SETFD: u64 = 2;
                const F_GETFL: u64 = 3;
                const F_SETFL: u64 = 4;
                const F_DUPFD_CLOEXEC: u64 = 1030;
                let fd = a[0] as i64;
                match a[1] {
                    F_DUPFD | F_DUPFD_CLOEXEC => match self.fdt.get(fd).cloned() {
                        Some(mut f) => {
                            f.cloexec = a[1] == F_DUPFD_CLOEXEC;
                            if let FdKind::PipeR { id } = f.kind {
                                self.fdt.pipes[id].readers += 1;
                            } else if let FdKind::PipeW { id } = f.kind {
                                self.fdt.pipes[id].writers += 1;
                            }
                            Ret(self.fdt.alloc(f, a[2] as usize))
                        }
                        None => Ret(-EBADF),
                    },
                    F_GETFD => match self.fdt.get(fd) {
                        Some(f) => Ret(f.cloexec as i64),
                        None => Ret(-EBADF),
                    },
                    F_SETFD => match self.fdt.get_mut(fd) {
                        Some(f) => {
                            f.cloexec = a[2] & 1 != 0;
                            Ret(0)
                        }
                        None => Ret(-EBADF),
                    },
                    F_GETFL => match self.fdt.get(fd) {
                        Some(f) => {
                            let mut fl = 0u64;
                            if f.nonblock {
                                fl |= O_NONBLOCK;
                            }
                            match f.kind {
                                FdKind::Stdout | FdKind::Stderr | FdKind::PipeW { .. } => fl |= O_WRONLY,
                                FdKind::File { .. } => fl |= O_RDWR,
                                _ => {}
                            }
                            Ret(fl as i64)
                        }
                        None => Ret(-EBADF),
                    },
                    F_SETFL => match self.fdt.get_mut(fd) {
                        Some(f) => {
                            f.nonblock = a[2] & O_NONBLOCK != 0;
                            Ret(0)
                        }
                        None => Ret(-EBADF),
                    },
                    _ => Ret(-EINVAL),
                }
            }
            29 => Ret(-ENOTTY), // ioctl
            34 => {
                // mkdirat
                let path = match self.at_path(a[0] as i64, a[1]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let resolved = match self.fs.resolve(&path, true) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                if self.fs.get(&resolved).is_some() {
                    return Ret(-EEXIST);
                }
                self.fs.nodes.insert(resolved, Node::Dir);
                Ret(0)
            }
            35 => {
                // unlinkat
                const AT_REMOVEDIR: u64 = 0x200;
                let path = match self.at_path(a[0] as i64, a[1]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let resolved = match self.fs.resolve(&path, false) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                match self.fs.get(&resolved) {
                    None => Ret(-ENOENT),
                    Some(Node::Dir) if a[2] & AT_REMOVEDIR == 0 => Ret(-EISDIR),
                    Some(Node::Dir) => {
                        if !self.fs.list_dir(&resolved).is_empty() {
                            return Ret(-ENOTEMPTY);
                        }
                        self.fs.nodes.remove(&resolved);
                        Ret(0)
                    }
                    Some(_) => {
                        self.fs.nodes.remove(&resolved);
                        Ret(0)
                    }
                }
            }
            36 => {
                // symlinkat(target, dirfd, linkpath)
                let target = match self.mem.read_cstr(a[0], 4096) {
                    Ok(t) => String::from_utf8_lossy(&t).into_owned(),
                    Err(_) => return Ret(-EFAULT),
                };
                let link = match self.at_path(a[1] as i64, a[2]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                self.fs.add_symlink(&link, &target);
                Ret(0)
            }
            37 => {
                // linkat: emulate as copy of the node
                let old = match self.at_path(a[0] as i64, a[1]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let new = match self.at_path(a[2] as i64, a[3]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let old_r = match self.fs.resolve(&old, true) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                match self.fs.get(&old_r).cloned() {
                    Some(node) => {
                        let new_r = match self.fs.resolve(&new, true) {
                            Ok(p) => p,
                            Err(e) => return Ret(-e),
                        };
                        self.fs.nodes.insert(new_r, node);
                        Ret(0)
                    }
                    None => Ret(-ENOENT),
                }
            }
            38 | 276 => {
                // renameat / renameat2
                let old = match self.at_path(a[0] as i64, a[1]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let new = match self.at_path(a[2] as i64, a[3]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let old_r = match self.fs.resolve(&old, false) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let new_r = match self.fs.resolve(&new, false) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                match self.fs.nodes.remove(&old_r) {
                    Some(node) => {
                        // Move children if dir.
                        if matches!(node, Node::Dir) {
                            let mut prefix = old_r.clone();
                            prefix.push('/');
                            let moves: Vec<(String, Node)> = self
                                .fs
                                .nodes
                                .range(prefix.clone()..)
                                .take_while(|(k, _)| k.starts_with(prefix.as_str()))
                                .map(|(k, v)| (k.clone(), v.clone()))
                                .collect();
                            for (k, v) in moves {
                                self.fs.nodes.remove(&k);
                                let mut nk = new_r.clone();
                                nk.push_str(&k[old_r.len()..]);
                                self.fs.nodes.insert(nk, v);
                            }
                        }
                        self.fs.nodes.insert(new_r, node);
                        Ret(0)
                    }
                    None => Ret(-ENOENT),
                }
            }
            43 | 44 => {
                // statfs / fstatfs: dummy tmpfs
                let mut buf = [0u8; 120];
                buf[0..8].copy_from_slice(&0x01021994u64.to_le_bytes()); // TMPFS_MAGIC
                buf[8..16].copy_from_slice(&4096u64.to_le_bytes()); // bsize
                if self.mem.write_bytes(a[1], &buf).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(0)
            }
            46 => {
                // ftruncate
                match self.fdt.get(a[0] as i64).map(|f| f.kind.clone()) {
                    Some(FdKind::File { path, .. }) => match self.fs.truncate(&path, a[1]) {
                        Ok(()) => Ret(0),
                        Err(e) => Ret(-e),
                    },
                    Some(_) => Ret(-EINVAL),
                    None => Ret(-EBADF),
                }
            }
            48 | 439 => {
                // faccessat / faccessat2
                let path = match self.at_path(a[0] as i64, a[1]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let resolved = match self.fs.resolve(&path, true) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                match self.fs.get(&resolved) {
                    Some(Node::File { mode, .. }) => {
                        // X_OK check
                        if a[2] & 1 != 0 && mode & 0o111 == 0 {
                            return Ret(-EACCES);
                        }
                        Ret(0)
                    }
                    Some(_) => Ret(0),
                    None => Ret(-ENOENT),
                }
            }
            49 => {
                // chdir
                let path = match self.at_path(AT_FDCWD, a[0]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let resolved = match self.fs.resolve(&path, true) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                match self.fs.get(&resolved) {
                    Some(Node::Dir) => {
                        self.cwd = resolved;
                        Ret(0)
                    }
                    Some(_) => Ret(-ENOTDIR),
                    None => Ret(-ENOENT),
                }
            }
            52 | 53 => Ret(0), // fchmod / fchmodat (permissions don't matter)
            55 | 54 => Ret(0), // fchown / fchownat
            56 => {
                // openat
                let flags = a[2];
                let path = match self.at_path(a[0] as i64, a[1]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let resolved = match self.fs.resolve(&path, true) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let exists = self.fs.get(&resolved).is_some();
                if !exists {
                    if flags & O_CREAT == 0 {
                        return Ret(-ENOENT);
                    }
                    if let Err(e) = self.fs.create_file(&resolved, (a[3] & 0o7777) as u32) {
                        return Ret(-e);
                    }
                } else if flags & O_CREAT != 0 && flags & O_EXCL != 0 {
                    return Ret(-EEXIST);
                }
                let is_dir = matches!(self.fs.get(&resolved), Some(Node::Dir)) || resolved == "/";
                if flags & O_DIRECTORY != 0 && !is_dir {
                    return Ret(-ENOTDIR);
                }
                if is_dir {
                    let fd = Fd {
                        kind: FdKind::Dir {
                            path: resolved,
                            pos: 0,
                        },
                        cloexec: flags & O_CLOEXEC != 0,
                        nonblock: false,
                    };
                    return Ret(self.fdt.alloc(fd, 0));
                }
                if flags & O_TRUNC != 0 && (flags & (O_WRONLY | O_RDWR)) != 0 {
                    let _ = self.fs.truncate(&resolved, 0);
                }
                let append = flags & O_APPEND != 0;
                let fd = Fd {
                    kind: FdKind::File {
                        path: resolved,
                        pos: 0,
                        append,
                    },
                    cloexec: flags & O_CLOEXEC != 0,
                    nonblock: flags & O_NONBLOCK != 0,
                };
                Ret(self.fdt.alloc(fd, 0))
            }
            57 => match self.fdt.close(a[0] as i64) {
                Ok(_) => Ret(0),
                Err(e) => Ret(-e),
            },
            59 => {
                // pipe2
                let id = self.fdt.pipes.len();
                self.fdt.pipes.push(Pipe {
                    buf: Default::default(),
                    readers: 1,
                    writers: 1,
                });
                let r = self.fdt.alloc(
                    Fd {
                        kind: FdKind::PipeR { id },
                        cloexec: a[1] & O_CLOEXEC != 0,
                        nonblock: a[1] & O_NONBLOCK != 0,
                    },
                    0,
                );
                let w = self.fdt.alloc(
                    Fd {
                        kind: FdKind::PipeW { id },
                        cloexec: a[1] & O_CLOEXEC != 0,
                        nonblock: a[1] & O_NONBLOCK != 0,
                    },
                    0,
                );
                let mut buf = [0u8; 8];
                buf[..4].copy_from_slice(&(r as u32).to_le_bytes());
                buf[4..].copy_from_slice(&(w as u32).to_le_bytes());
                if self.mem.write_bytes(a[0], &buf).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(0)
            }
            61 => {
                // getdents64
                let fd = a[0] as i64;
                let (path, pos) = match self.fdt.get(fd).map(|f| f.kind.clone()) {
                    Some(FdKind::Dir { path, pos }) => (path, pos),
                    Some(_) => return Ret(-ENOTDIR),
                    None => return Ret(-EBADF),
                };
                let entries = self.fs.list_dir(&path);
                let mut out: Vec<u8> = Vec::new();
                let mut new_pos = pos;
                for (idx, (name, dt)) in entries.iter().enumerate().skip(pos as usize) {
                    let reclen = (19 + name.len() + 1 + 7) & !7;
                    if out.len() + reclen > a[2] as usize {
                        break;
                    }
                    let mut child = path.clone();
                    if !child.ends_with('/') {
                        child.push('/');
                    }
                    child.push_str(name);
                    let ino = self.fs.ino(&child);
                    let mut rec = alloc::vec![0u8; reclen];
                    rec[0..8].copy_from_slice(&ino.to_le_bytes());
                    rec[8..16].copy_from_slice(&((idx as u64 + 1).to_le_bytes()));
                    rec[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
                    rec[18] = *dt;
                    rec[19..19 + name.len()].copy_from_slice(name.as_bytes());
                    out.extend_from_slice(&rec);
                    new_pos = idx as u64 + 1;
                }
                if let Some(f) = self.fdt.get_mut(fd) {
                    f.kind = FdKind::Dir {
                        path,
                        pos: new_pos,
                    };
                }
                if self.mem.write_bytes(a[1], &out).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(out.len() as i64)
            }
            62 => {
                // lseek
                let fd = a[0] as i64;
                let off = a[1] as i64;
                let whence = a[2];
                match self.fdt.get(fd).map(|f| f.kind.clone()) {
                    Some(FdKind::File { path, pos, append }) => {
                        let size = match self.fs.get(&path) {
                            Some(Node::File { data, .. }) => data.len(),
                            _ => 0,
                        };
                        let new = match whence {
                            0 => off,
                            1 => pos as i64 + off,
                            2 => size as i64 + off,
                            _ => return Ret(-EINVAL),
                        };
                        if new < 0 {
                            return Ret(-EINVAL);
                        }
                        if let Some(f) = self.fdt.get_mut(fd) {
                            f.kind = FdKind::File {
                                path,
                                pos: new as u64,
                                append,
                            };
                        }
                        Ret(new)
                    }
                    Some(FdKind::Dir { .. }) => Ret(0),
                    Some(_) => Ret(-ESPIPE),
                    None => Ret(-EBADF),
                }
            }
            63 => self.sys_read(a[0] as i64, a[1], a[2] as usize),
            64 => self.sys_write(a[0] as i64, a[1], a[2] as usize),
            65 | 66 => {
                // readv / writev
                let fd = a[0] as i64;
                let mut total: i64 = 0;
                for i in 0..a[2] {
                    let base = match self.mem.ld(a[1] + i * 16) {
                        Ok(v) => v,
                        Err(_) => return Ret(-EFAULT),
                    };
                    let len = match self.mem.ld(a[1] + i * 16 + 8) {
                        Ok(v) => v,
                        Err(_) => return Ret(-EFAULT),
                    };
                    if len == 0 {
                        continue;
                    }
                    let r = if n == 65 {
                        self.sys_read(fd, base, len as usize)
                    } else {
                        self.sys_write(fd, base, len as usize)
                    };
                    match r {
                        Ret(v) if v >= 0 => {
                            total += v;
                            if (v as u64) < len {
                                break;
                            }
                        }
                        Ret(e) => {
                            if total > 0 {
                                break;
                            }
                            return Ret(e);
                        }
                        other => return other,
                    }
                }
                Ret(total)
            }
            67 => {
                // pread64
                let fd = a[0] as i64;
                match self.fdt.get(fd).map(|f| f.kind.clone()) {
                    Some(FdKind::File { path, .. }) => {
                        let data = match self.fs.get(&path) {
                            Some(Node::File { data, .. }) => data.snapshot(),
                            _ => return Ret(-ENOENT),
                        };
                        let off = a[3] as usize;
                        if off >= data.len() {
                            return Ret(0);
                        }
                        let nread = core::cmp::min(a[2] as usize, data.len() - off);
                        if self.mem.write_bytes(a[1], &data[off..off + nread]).is_err() {
                            return Ret(-EFAULT);
                        }
                        Ret(nread as i64)
                    }
                    Some(_) => Ret(-ESPIPE),
                    None => Ret(-EBADF),
                }
            }
            68 => {
                // pwrite64
                let fd = a[0] as i64;
                match self.fdt.get(fd).map(|f| f.kind.clone()) {
                    Some(FdKind::File { path, .. }) => {
                        let buf = match self.mem.read_bytes(a[1], a[2] as usize) {
                            Ok(b) => b,
                            Err(_) => return Ret(-EFAULT),
                        };
                        match self.fs.write_at(&path, a[3], &buf) {
                            Ok(w) => Ret(w as i64),
                            Err(e) => Ret(-e),
                        }
                    }
                    Some(_) => Ret(-ESPIPE),
                    None => Ret(-EBADF),
                }
            }
            71 => {
                // sendfile(out, in, offset_ptr, count)
                let (in_path, in_pos) = match self.fdt.get(a[1] as i64).map(|f| f.kind.clone()) {
                    Some(FdKind::File { path, pos, .. }) => (path, pos),
                    _ => return Ret(-EINVAL),
                };
                let data = match self.fs.get(&in_path) {
                    Some(Node::File { data, .. }) => data.snapshot(),
                    _ => return Ret(-ENOENT),
                };
                let mut off = if a[2] != 0 {
                    match self.mem.ld(a[2]) {
                        Ok(v) => v,
                        Err(_) => return Ret(-EFAULT),
                    }
                } else {
                    in_pos
                };
                let count = core::cmp::min(a[3] as usize, data.len().saturating_sub(off as usize));
                let chunk = data[off as usize..off as usize + count].to_vec();
                let written = match self.write_to_fd(a[0] as i64, &chunk) {
                    Ok(w) => w,
                    Err(e) => return Ret(-e),
                };
                off += written as u64;
                if a[2] != 0 {
                    if self.mem.sd(a[2], off).is_err() {
                        return Ret(-EFAULT);
                    }
                } else if let Some(f) = self.fdt.get_mut(a[1] as i64) {
                    if let FdKind::File { pos, .. } = &mut f.kind {
                        *pos = off;
                    }
                }
                Ret(written as i64)
            }
            72 => Ret(1), // pselect6: pretend ready
            73 => {
                // ppoll
                let nfds = a[1] as usize;
                let mut ready = 0i64;
                for i in 0..nfds {
                    let base = a[0] + (i as u64) * 8;
                    let fd = match self.mem.lw(base) {
                        Ok(v) => v as i32 as i64,
                        Err(_) => return Ret(-EFAULT),
                    };
                    let events = match self.mem.lhu(base + 4) {
                        Ok(v) => v as u16,
                        Err(_) => return Ret(-EFAULT),
                    };
                    let revents = self.poll_fd(fd, events);
                    if self.mem.sh(base + 6, revents).is_err() {
                        return Ret(-EFAULT);
                    }
                    if revents != 0 {
                        ready += 1;
                    }
                }
                if ready > 0 {
                    return Ret(ready);
                }
                // timeout == 0 -> return immediately
                if a[2] != 0 {
                    let sec = self.mem.ld(a[2]).unwrap_or(0);
                    let nsec = self.mem.ld(a[2] + 8).unwrap_or(0);
                    if sec == 0 && nsec == 0 {
                        return Ret(0);
                    }
                }
                Block(BlockOn::Poll {
                    pfds_addr: a[0],
                    nfds,
                    timeout: if a[2] != 0 {
                        TimeoutPolicy::Finite
                    } else {
                        TimeoutPolicy::Infinite
                    },
                })
            }
            78 => {
                // readlinkat
                let path = match self.at_path(a[0] as i64, a[1]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                let resolved = match self.fs.resolve(&path, false) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                match self.fs.get(&resolved).cloned() {
                    Some(Node::Symlink(t)) => {
                        let bytes = t.as_bytes();
                        let nwrite = core::cmp::min(bytes.len(), a[3] as usize);
                        if self.mem.write_bytes(a[2], &bytes[..nwrite]).is_err() {
                            return Ret(-EFAULT);
                        }
                        Ret(nwrite as i64)
                    }
                    Some(_) => Ret(-EINVAL),
                    None => Ret(-ENOENT),
                }
            }
            79 => {
                // newfstatat
                const AT_EMPTY_PATH: u64 = 0x1000;
                const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
                if a[3] & AT_EMPTY_PATH != 0 {
                    let kind = match self.fdt.get(a[0] as i64) {
                        Some(f) => f.kind.clone(),
                        None => return Ret(-EBADF),
                    };
                    return match self.write_stat(a[2], None, &kind) {
                        Ok(()) => Ret(0),
                        Err(e) => Ret(-e),
                    };
                }
                let path = match self.at_path(a[0] as i64, a[1]) {
                    Ok(p) => p,
                    Err(e) => return Ret(-e),
                };
                match self.stat_path(&path, a[3] & AT_SYMLINK_NOFOLLOW == 0, a[2]) {
                    Ok(()) => Ret(0),
                    Err(e) => Ret(-e),
                }
            }
            80 => {
                // fstat
                let kind = match self.fdt.get(a[0] as i64) {
                    Some(f) => f.kind.clone(),
                    None => return Ret(-EBADF),
                };
                match self.write_stat(a[1], None, &kind) {
                    Ok(()) => Ret(0),
                    Err(e) => Ret(-e),
                }
            }
            81 | 82 | 83 => Ret(0), // sync/fsync/fdatasync
            88 => Ret(0),           // utimensat
            93 => ExitThread(a[0] as i32),
            94 => ExitGroup(a[0] as i32),
            95 => Ret(-ECHILD), // waitid
            96 => {
                // set_tid_address
                let tid = self.cur_tid();
                self.cur_hart_mut().clear_child_tid = a[0];
                Ret(tid as i64)
            }
            98 => self.sys_futex(a),
            99 => Ret(-ENOSYS), // set_robust_list
            101 | 115 => Ret(0), // nanosleep / clock_nanosleep
            113 => {
                // clock_gettime
                let ns = self.time_ns();
                if self.mem.sd(a[1], ns / 1_000_000_000).is_err() {
                    return Ret(-EFAULT);
                }
                if self.mem.sd(a[1] + 8, ns % 1_000_000_000).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(0)
            }
            114 => {
                // clock_getres
                let _ = self.mem.sd(a[1], 0);
                let _ = self.mem.sd(a[1] + 8, 1);
                Ret(0)
            }
            122 => Ret(0), // sched_setaffinity
            123 => {
                // sched_getaffinity: one CPU
                let len = core::cmp::min(a[1] as usize, 8);
                let mask = 1u64.to_le_bytes();
                if self.mem.write_bytes(a[2], &mask[..len]).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(8)
            }
            124 => {
                // sched_yield: handled as reschedule point by machine
                Ret(0)
            }
            129 | 130 | 131 => {
                // kill / tkill / tgkill
                let sig = if n == 131 { a[2] } else { a[1] };
                if sig == 6 {
                    // SIGABRT
                    return ExitGroup(134);
                }
                Ret(0)
            }
            132 => {
                // sigaltstack
                if a[1] != 0 {
                    // write old: disabled
                    let mut old = [0u8; 24];
                    old[8..12].copy_from_slice(&2u32.to_le_bytes()); // SS_DISABLE
                    if self.mem.write_bytes(a[1], &old).is_err() {
                        return Ret(-EFAULT);
                    }
                }
                Ret(0)
            }
            134 => {
                // rt_sigaction
                if a[2] != 0 {
                    let zeros = [0u8; 32];
                    if self.mem.write_bytes(a[2], &zeros).is_err() {
                        return Ret(-EFAULT);
                    }
                }
                Ret(0)
            }
            135 => {
                // rt_sigprocmask
                if a[2] != 0 {
                    let zeros = [0u8; 8];
                    if self.mem.write_bytes(a[2], &zeros).is_err() {
                        return Ret(-EFAULT);
                    }
                }
                Ret(0)
            }
            153 => {
                // times
                let t = self.instret / 10_000_000;
                for i in 0..4 {
                    let _ = self.mem.sd(a[0] + i * 8, t);
                }
                Ret(t as i64)
            }
            154 | 155 => Ret(if n == 155 { 1 } else { 0 }), // setpgid / getpgid
            157 => Ret(1),                                   // setsid
            160 => {
                // uname
                let mut buf = [0u8; 65 * 6];
                let fields: [&[u8]; 6] = [b"Linux", b"zkvm", b"6.6.0-zk", b"#1 SMP", b"riscv64", b""];
                for (i, f) in fields.iter().enumerate() {
                    buf[i * 65..i * 65 + f.len()].copy_from_slice(f);
                }
                if self.mem.write_bytes(a[0], &buf).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(0)
            }
            163 | 164 => Ret(0), // getrlimit / setrlimit (legacy; glibc uses prlimit64)
            165 => {
                // getrusage
                let zeros = [0u8; 144];
                if self.mem.write_bytes(a[1], &zeros).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(0)
            }
            166 => Ret(0o22), // umask
            167 => Ret(0),    // prctl
            168 => {
                // getcpu
                if a[0] != 0 {
                    let _ = self.mem.sw(a[0], 0);
                }
                if a[1] != 0 {
                    let _ = self.mem.sw(a[1], 0);
                }
                Ret(0)
            }
            169 => {
                // gettimeofday
                let ns = self.time_ns();
                let _ = self.mem.sd(a[0], ns / 1_000_000_000);
                let _ = self.mem.sd(a[0] + 8, (ns % 1_000_000_000) / 1000);
                Ret(0)
            }
            172 => Ret(1), // getpid
            173 => Ret(0), // getppid
            174..=177 => Ret(0), // getuid/geteuid/getgid/getegid
            178 => Ret(self.cur_tid() as i64),
            179 => {
                // sysinfo
                let mut buf = [0u8; 112];
                buf[0..8].copy_from_slice(&(self.instret / 1_000_000_000 + 1).to_le_bytes()); // uptime
                let totalram: u64 = 8 << 30;
                let freeram: u64 = 6 << 30;
                buf[32..40].copy_from_slice(&totalram.to_le_bytes());
                buf[40..48].copy_from_slice(&freeram.to_le_bytes());
                buf[96..100].copy_from_slice(&1u32.to_le_bytes()); // mem_unit
                if self.mem.write_bytes(a[0], &buf).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(0)
            }
            198 => Ret(-EAFNOSUPPORT), // socket
            203 => Ret(-EBADF),        // connect
            214 => {
                // brk
                let cur = self.mem.brk;
                if a[0] == 0 {
                    return Ret(cur as i64);
                }
                let new = a[0];
                if new < self.mem.brk_base {
                    return Ret(cur as i64);
                }
                if new > cur {
                    self.mem.map(cur, new - cur, 7, Backing::Zero);
                }
                self.mem.brk = new;
                Ret(new as i64)
            }
            215 => {
                // munmap
                self.flush_shared(a[0], a[1]);
                if self.mem.overlaps_file(a[0], a[1]) {
                    // Code may be going away; drop decoded cache.
                    self.code_cache.clear();
                }
                self.mem.unmap(a[0], a[1]);
                Ret(0)
            }
            216 => {
                // mremap(old, oldsz, newsz, flags, newaddr)
                let old = a[0];
                let oldsz = a[1];
                let newsz = a[2];
                if newsz <= oldsz {
                    if oldsz > newsz {
                        self.mem.unmap(old + newsz, oldsz - newsz);
                    }
                    return Ret(old as i64);
                }
                // move: allocate fresh, copy, unmap old
                let newaddr = self.mem.alloc_mmap(newsz);
                self.mem.map(newaddr, newsz, 7, Backing::Zero);
                match self.mem.read_bytes(old, oldsz as usize) {
                    Ok(data) => {
                        if self.mem.write_bytes(newaddr, &data).is_err() {
                            return Ret(-EFAULT);
                        }
                    }
                    Err(_) => return Ret(-EFAULT),
                }
                self.mem.unmap(old, oldsz);
                Ret(newaddr as i64)
            }
            220 => self.sys_clone(a),
            221 => Ret(-ENOSYS), // execve
            222 => {
                // mmap
                const MAP_SHARED: u64 = 0x01;
                const MAP_FIXED: u64 = 0x10;
                const MAP_ANON: u64 = 0x20;
                let len = a[1];
                if len == 0 {
                    return Ret(-EINVAL);
                }
                let addr = if a[3] & MAP_FIXED != 0 {
                    a[0]
                } else {
                    self.mem.alloc_mmap(len)
                };
                let backing = if a[3] & MAP_ANON != 0 {
                    Backing::Zero
                } else {
                    // New file-backed mapping may introduce (or replace) code.
                    self.code_cache.clear();
                    let fd = a[4] as i64;
                    match self.fdt.get(fd).map(|f| f.kind.clone()) {
                        Some(FdKind::File { path, .. }) => match self.fs.get(&path) {
                            Some(Node::File { data, .. }) => {
                                if a[3] & MAP_SHARED != 0 && a[2] & 2 != 0 {
                                    // PROT_WRITE shared mapping: needs write-back
                                    self.shared_maps.push(crate::SharedMap {
                                        addr,
                                        len,
                                        path: path.clone(),
                                        offset: a[5],
                                    });
                                }
                                Backing::File {
                                    data: data.snapshot(),
                                    offset: a[5],
                                }
                            }
                            _ => return Ret(-ENOENT),
                        },
                        _ => return Ret(-EBADF),
                    }
                };
                self.mem.map(addr, len, a[2] as u32, backing);
                Ret(addr as i64)
            }
            223 => Ret(0), // fadvise64
            226 => {
                self.mem.protect(a[0], a[1], a[2] as u32);
                Ret(0)
            }
            227 => {
                // msync
                self.flush_shared(a[0], a[1]);
                Ret(0)
            }
            233 => {
                // madvise: honor MADV_DONTNEED/MADV_FREE by dropping pages
                const MADV_DONTNEED: u64 = 4;
                const MADV_FREE: u64 = 8;
                if a[2] == MADV_DONTNEED || a[2] == MADV_FREE {
                    self.mem.discard(a[0], a[1]);
                }
                Ret(0)
            }
            258 => {
                // riscv_hwprobe(pairs, count, cpusetsize, cpus, flags)
                for i in 0..a[1] {
                    let base = a[0] + i * 16;
                    let key = match self.mem.ld(base) {
                        Ok(k) => k as i64,
                        Err(_) => return Ret(-EFAULT),
                    };
                    let value: u64 = match key {
                        0 | 1 | 2 => 0,   // mvendorid/marchid/mimpid
                        3 => 1,           // BASE_BEHAVIOR_IMA
                        4 => 0b11,        // IMA_EXT_0: FD | C
                        5 => 0,           // CPUPERF_0: misaligned unknown
                        _ => {
                            let _ = self.mem.sd(base, -1i64 as u64);
                            let _ = self.mem.sd(base + 8, 0);
                            continue;
                        }
                    };
                    if self.mem.sd(base + 8, value).is_err() {
                        return Ret(-EFAULT);
                    }
                }
                Ret(0)
            }
            260 => Ret(-ECHILD), // wait4
            261 => {
                // prlimit64(pid, res, new, old)
                if a[3] != 0 {
                    const RLIM_INFINITY: u64 = u64::MAX;
                    let (cur, max) = match a[1] {
                        3 => (8 << 20, RLIM_INFINITY),      // RLIMIT_STACK
                        7 => (1024, 1024 * 1024),           // RLIMIT_NOFILE
                        _ => (RLIM_INFINITY, RLIM_INFINITY),
                    };
                    if self.mem.sd(a[3], cur).is_err() {
                        return Ret(-EFAULT);
                    }
                    if self.mem.sd(a[3] + 8, max).is_err() {
                        return Ret(-EFAULT);
                    }
                }
                Ret(0)
            }
            278 => {
                // getrandom: deterministic stream
                let mut buf = alloc::vec![0u8; a[1] as usize];
                for chunk in buf.chunks_mut(8) {
                    let v = self.next_random();
                    let bytes = v.to_le_bytes();
                    chunk.copy_from_slice(&bytes[..chunk.len()]);
                }
                if self.mem.write_bytes(a[0], &buf).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(a[1] as i64)
            }
            279 => {
                // memfd_create
                let name = match self.mem.read_cstr(a[0], 249) {
                    Ok(nm) => String::from_utf8_lossy(&nm).into_owned(),
                    Err(_) => return Ret(-EFAULT),
                };
                let path = alloc::format!("/dev/shm/memfd-{}-{}", self.memfd_seq, name);
                self.memfd_seq += 1;
                self.fs.add_file(&path, Vec::new(), 0o600);
                // make it writable
                let _ = self.fs.truncate(&path, 0);
                let fd = Fd {
                    kind: FdKind::File {
                        path,
                        pos: 0,
                        append: false,
                    },
                    cloexec: true,
                    nonblock: false,
                };
                Ret(self.fdt.alloc(fd, 0))
            }
            283 => Ret(0), // membarrier
            285 => {
                // copy_file_range(in, inoff*, out, outoff*, len, flags)
                let in_fd = a[0] as i64;
                let out_fd = a[2] as i64;
                let (in_path, in_pos) = match self.fdt.get(in_fd).map(|f| f.kind.clone()) {
                    Some(FdKind::File { path, pos, .. }) => (path, pos),
                    _ => return Ret(-EBADF),
                };
                let data = match self.fs.get(&in_path) {
                    Some(Node::File { data, .. }) => data.snapshot(),
                    _ => return Ret(-ENOENT),
                };
                let mut ioff = if a[1] != 0 {
                    match self.mem.ld(a[1]) {
                        Ok(v) => v,
                        Err(_) => return Ret(-EFAULT),
                    }
                } else {
                    in_pos
                };
                let count = core::cmp::min(a[4] as usize, data.len().saturating_sub(ioff as usize));
                let chunk = data[ioff as usize..ioff as usize + count].to_vec();

                let (out_path, out_pos) = match self.fdt.get(out_fd).map(|f| f.kind.clone()) {
                    Some(FdKind::File { path, pos, .. }) => (path, pos),
                    _ => return Ret(-EBADF),
                };
                let mut ooff = if a[3] != 0 {
                    match self.mem.ld(a[3]) {
                        Ok(v) => v,
                        Err(_) => return Ret(-EFAULT),
                    }
                } else {
                    out_pos
                };
                match self.fs.write_at(&out_path, ooff, &chunk) {
                    Ok(w) => {
                        ioff += w as u64;
                        ooff += w as u64;
                        if a[1] != 0 {
                            let _ = self.mem.sd(a[1], ioff);
                        } else if let Some(f) = self.fdt.get_mut(in_fd) {
                            if let FdKind::File { pos, .. } = &mut f.kind {
                                *pos = ioff;
                            }
                        }
                        if a[3] != 0 {
                            let _ = self.mem.sd(a[3], ooff);
                        } else if let Some(f) = self.fdt.get_mut(out_fd) {
                            if let FdKind::File { pos, .. } = &mut f.kind {
                                *pos = ooff;
                            }
                        }
                        Ret(w as i64)
                    }
                    Err(e) => Ret(-e),
                }
            }
            291 => {
                // statx(dirfd, path, flags, mask, buf)
                const AT_EMPTY_PATH: u64 = 0x1000;
                const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
                let kind = if a[2] & AT_EMPTY_PATH != 0 {
                    match self.fdt.get(a[0] as i64) {
                        Some(f) => f.kind.clone(),
                        None => return Ret(-EBADF),
                    }
                } else {
                    let path = match self.at_path(a[0] as i64, a[1]) {
                        Ok(p) => p,
                        Err(e) => return Ret(-e),
                    };
                    let resolved = match self.fs.resolve(&path, a[2] & AT_SYMLINK_NOFOLLOW == 0) {
                        Ok(p) => p,
                        Err(e) => return Ret(-e),
                    };
                    if self.fs.get(&resolved).is_none() {
                        return Ret(-ENOENT);
                    }
                    FdKind::File {
                        path: resolved,
                        pos: 0,
                        append: false,
                    }
                };
                // Build from the same data as stat.
                let mut statbuf = [0u8; 128];
                {
                    // reuse write_stat into a scratch mapping is awkward; compute inline
                    let (mode, size, ino) = match &kind {
                        FdKind::Stdin | FdKind::Stdout | FdKind::Stderr => (S_IFCHR | 0o620, 0u64, 10u64),
                        FdKind::PipeR { id } | FdKind::PipeW { id } => (S_IFIFO | 0o600, 0, 50 + *id as u64),
                        FdKind::Dir { path, .. } => {
                            let p = path.clone();
                            (S_IFDIR | 0o755, 4096, self.fs.ino(&p))
                        }
                        FdKind::File { path, .. } => {
                            let p = path.clone();
                            match self.fs.get(&p) {
                                Some(Node::File { data, mode }) => {
                                    let sz = data.len();
                                    let m = *mode;
                                    (S_IFREG | (m & 0o7777), sz, self.fs.ino(&p))
                                }
                                Some(Node::Dir) => (S_IFDIR | 0o755, 4096, self.fs.ino(&p)),
                                Some(Node::Symlink(t)) => {
                                    let l = t.len() as u64;
                                    (S_IFLNK | 0o777, l, self.fs.ino(&p))
                                }
                                None => return Ret(-ENOENT),
                            }
                        }
                    };
                    statbuf[0..4].copy_from_slice(&(mode as u32).to_le_bytes());
                    statbuf[8..16].copy_from_slice(&size.to_le_bytes());
                    statbuf[16..24].copy_from_slice(&ino.to_le_bytes());
                }
                let mode = u32::from_le_bytes(statbuf[0..4].try_into().unwrap());
                let size = u64::from_le_bytes(statbuf[8..16].try_into().unwrap());
                let ino = u64::from_le_bytes(statbuf[16..24].try_into().unwrap());

                let mut buf = [0u8; 256];
                buf[0..4].copy_from_slice(&0x7ffu32.to_le_bytes()); // stx_mask = BASIC_STATS
                buf[4..8].copy_from_slice(&4096u32.to_le_bytes()); // blksize
                buf[16..20].copy_from_slice(&1u32.to_le_bytes()); // nlink
                buf[28..30].copy_from_slice(&(mode as u16).to_le_bytes());
                buf[32..40].copy_from_slice(&ino.to_le_bytes());
                buf[40..48].copy_from_slice(&size.to_le_bytes());
                buf[48..56].copy_from_slice(&((size + 511) / 512).to_le_bytes());
                for off in [64usize, 96, 112] {
                    buf[off..off + 8].copy_from_slice(&1_700_000_000u64.to_le_bytes());
                }
                if self.mem.write_bytes(a[4], &buf).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(0)
            }
            293 => Ret(-ENOSYS), // rseq
            435 => Ret(-ENOSYS), // clone3 -> glibc falls back to clone
            436 => {
                // close_range
                let first = a[0] as usize;
                let last = core::cmp::min(a[1] as usize, self.fdt.fds.len().saturating_sub(1));
                for fd in first..=last {
                    let _ = self.fdt.close(fd as i64);
                }
                Ret(0)
            }
            _ => Unhandled(n),
        }
    }

    fn poll_fd(&self, fd: i64, events: u16) -> u16 {
        const POLLIN: u16 = 1;
        const POLLOUT: u16 = 4;
        const POLLHUP: u16 = 0x10;
        match self.fdt.get(fd).map(|f| &f.kind) {
            Some(FdKind::PipeR { id }) => {
                let p = &self.fdt.pipes[*id];
                let mut r = 0;
                if !p.buf.is_empty() {
                    r |= POLLIN & events;
                }
                if p.writers == 0 {
                    r |= POLLHUP;
                }
                r
            }
            Some(FdKind::PipeW { id }) => {
                let p = &self.fdt.pipes[*id];
                let mut r = POLLOUT & events;
                if p.readers == 0 {
                    r |= POLLHUP;
                }
                r
            }
            Some(FdKind::Stdin) => 0,
            Some(_) => (POLLIN | POLLOUT) & events,
            None => 0x20, // POLLNVAL
        }
    }

    fn write_to_fd(&mut self, fd: i64, data: &[u8]) -> Result<usize, i64> {
        match self.fdt.get(fd).map(|f| f.kind.clone()) {
            Some(FdKind::Stdout) => {
                self.stdout.extend_from_slice(data);
                Ok(data.len())
            }
            Some(FdKind::Stderr) => {
                self.stderr.extend_from_slice(data);
                Ok(data.len())
            }
            Some(FdKind::PipeW { id }) => {
                self.fdt.pipes[id].buf.extend(data.iter().copied());
                Ok(data.len())
            }
            Some(FdKind::PipeR { .. }) => Err(EBADF),
            Some(FdKind::File { path, pos, append }) => {
                let at = if append {
                    match self.fs.get(&path) {
                        Some(Node::File { data, .. }) => data.len(),
                        _ => 0,
                    }
                } else {
                    pos
                };
                let w = self.fs.write_at(&path, at, data)?;
                if let Some(f) = self.fdt.get_mut(fd) {
                    if let FdKind::File { pos, .. } = &mut f.kind {
                        *pos = at + w as u64;
                    }
                }
                Ok(w)
            }
            Some(FdKind::Dir { .. }) => Err(EISDIR),
            Some(FdKind::Stdin) => Err(EBADF),
            None => Err(EBADF),
        }
    }

    fn sys_write(&mut self, fd: i64, buf: u64, len: usize) -> SysResult {
        let data = match self.mem.read_bytes(buf, len) {
            Ok(d) => d,
            Err(_) => return SysResult::Ret(-EFAULT),
        };
        match self.write_to_fd(fd, &data) {
            Ok(w) => SysResult::Ret(w as i64),
            Err(e) => SysResult::Ret(-e),
        }
    }

    fn sys_read(&mut self, fd: i64, buf: u64, len: usize) -> SysResult {
        use SysResult::*;
        match self.fdt.get(fd).map(|f| (f.kind.clone(), f.nonblock)) {
            Some((FdKind::Stdin, _)) => Ret(0), // EOF
            Some((FdKind::File { path, pos, append }, _)) => {
                let data = match self.fs.get(&path) {
                    Some(Node::File { data, .. }) => data.snapshot(),
                    Some(Node::Dir) => return Ret(-EISDIR),
                    _ => return Ret(-ENOENT),
                };
                if pos as usize >= data.len() {
                    return Ret(0);
                }
                let n = core::cmp::min(len, data.len() - pos as usize);
                if self.mem.write_bytes(buf, &data[pos as usize..pos as usize + n]).is_err() {
                    return Ret(-EFAULT);
                }
                if let Some(f) = self.fdt.get_mut(fd) {
                    f.kind = FdKind::File {
                        path,
                        pos: pos + n as u64,
                        append,
                    };
                }
                Ret(n as i64)
            }
            Some((FdKind::PipeR { id }, nonblock)) => {
                let p = &mut self.fdt.pipes[id];
                if p.buf.is_empty() {
                    if p.writers == 0 {
                        return Ret(0); // EOF
                    }
                    if nonblock {
                        return Ret(-EAGAIN);
                    }
                    return Block(BlockOn::PipeRead { id, buf, len });
                }
                let n = core::cmp::min(len, p.buf.len());
                let chunk: Vec<u8> = p.buf.drain(..n).collect();
                if self.mem.write_bytes(buf, &chunk).is_err() {
                    return Ret(-EFAULT);
                }
                Ret(n as i64)
            }
            Some((FdKind::Dir { .. }, _)) => Ret(-EISDIR),
            Some(_) => Ret(-EBADF),
            None => Ret(-EBADF),
        }
    }

    fn sys_futex(&mut self, a: [u64; 6]) -> SysResult {
        use SysResult::*;
        const FUTEX_WAIT: u64 = 0;
        const FUTEX_WAKE: u64 = 1;
        const FUTEX_REQUEUE: u64 = 3;
        const FUTEX_CMP_REQUEUE: u64 = 4;
        const FUTEX_WAIT_BITSET: u64 = 9;
        const FUTEX_WAKE_BITSET: u64 = 10;
        let op = a[1] & 0x7F;
        match op {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                let cur = match self.mem.lwu(a[0]) {
                    Ok(v) => v as u32,
                    Err(_) => return Ret(-EFAULT),
                };
                if cur != a[2] as u32 {
                    return Ret(-EAGAIN);
                }
                let bitset = if op == FUTEX_WAIT_BITSET {
                    a[5] as u32
                } else {
                    u32::MAX
                };
                let timeout = if a[3] != 0 {
                    TimeoutPolicy::Finite
                } else {
                    TimeoutPolicy::Infinite
                };
                Block(BlockOn::Futex {
                    addr: a[0],
                    bitset,
                    timeout,
                })
            }
            FUTEX_WAKE | FUTEX_WAKE_BITSET => {
                let bitset = if op == FUTEX_WAKE_BITSET {
                    a[5] as u32
                } else {
                    u32::MAX
                };
                let n = self.futex_wake(a[0], a[2] as usize, bitset);
                Ret(n as i64)
            }
            FUTEX_REQUEUE | FUTEX_CMP_REQUEUE => {
                if op == FUTEX_CMP_REQUEUE {
                    let cur = match self.mem.lwu(a[0]) {
                        Ok(v) => v as u32,
                        Err(_) => return Ret(-EFAULT),
                    };
                    if cur != a[5] as u32 {
                        return Ret(-EAGAIN);
                    }
                }
                let woken = self.futex_wake(a[0], a[2] as usize, u32::MAX);
                let moved = self.futex_requeue(a[0], a[4], a[3] as usize);
                Ret((woken + moved) as i64)
            }
            _ => Ret(-ENOSYS),
        }
    }

    fn sys_clone(&mut self, a: [u64; 6]) -> SysResult {
        const CLONE_VM: u64 = 0x100;
        const CLONE_SETTLS: u64 = 0x80000;
        const CLONE_PARENT_SETTID: u64 = 0x100000;
        const CLONE_CHILD_CLEARTID: u64 = 0x200000;
        const CLONE_CHILD_SETTID: u64 = 0x1000000;
        let flags = a[0];
        if flags & CLONE_VM == 0 {
            // fork(): unsupported
            return SysResult::Ret(-(ENOSYS));
        }
        let child_stack = a[1];
        let parent_tid_ptr = a[2];
        let tls = a[3];
        let child_tid_ptr = a[4];

        let tid = self.spawn_thread(child_stack, tls, flags & CLONE_SETTLS != 0);
        if flags & CLONE_PARENT_SETTID != 0 {
            let _ = self.mem.sw(parent_tid_ptr, tid as u32);
        }
        if flags & CLONE_CHILD_SETTID != 0 {
            let _ = self.mem.sw(child_tid_ptr, tid as u32);
        }
        if flags & CLONE_CHILD_CLEARTID != 0 {
            self.set_clear_child_tid(tid, child_tid_ptr);
        }
        SysResult::Ret(tid as i64)
    }
}
