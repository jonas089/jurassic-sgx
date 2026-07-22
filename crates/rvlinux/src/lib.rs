//! rvlinux: a deterministic RV64GC + Zicsr usermode Linux emulator.
//!
//! Runs unmodified riscv64-linux binaries (including rustc) against an
//! in-memory filesystem with cooperative threading. no_std + alloc so the
//! same code runs on the host and inside the SP1 zkVM guest.
//!
//! **Auditors start here: [`../SPEC.md`](../SPEC.md)** — instruction set /
//! syscall coverage tables against the RISC-V and Linux specs, and every
//! place this interpreter's behavior deliberately deviates from real
//! hardware or a real kernel (determinism substitutions, `execve`/`fork`
//! being unsupported, unenforced page protection, partial CSR support,
//! ...). This module (`Machine`) owns the piece SPEC.md calls out as the
//! core determinism guarantee: exactly one hart runs at a time, so
//! scheduling is a pure function of instruction counts, never of
//! wall-clock/host timing.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod bundle;
pub mod cpu;
pub mod fs;
pub mod loader;
pub mod mem;
pub mod sys;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use cpu::{Hart, Stop};
use fs::{Fs, FdTable};
use mem::Memory;

/// Deterministic hasher (FxHash) so behavior never depends on random state.
#[derive(Default, Clone)]
pub struct FxHasher {
    hash: u64,
}

impl core::hash::Hasher for FxHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.hash
    }
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u8(b);
        }
    }
    #[inline]
    fn write_u8(&mut self, b: u8) {
        self.hash = (self.hash.rotate_left(5) ^ b as u64).wrapping_mul(0x517cc1b727220a95);
    }
    #[inline]
    fn write_u64(&mut self, v: u64) {
        self.hash = (self.hash.rotate_left(5) ^ v).wrapping_mul(0x517cc1b727220a95);
    }
    #[inline]
    fn write_u32(&mut self, v: u32) {
        self.write_u64(v as u64);
    }
    #[inline]
    fn write_usize(&mut self, v: usize) {
        self.write_u64(v as u64);
    }
}

pub type FxMap<K, V> =
    hashbrown::HashMap<K, V, core::hash::BuildHasherDefault<FxHasher>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutPolicy {
    Infinite,
    Finite,
}

#[derive(Debug, Clone)]
pub enum BlockOn {
    Futex {
        addr: u64,
        bitset: u32,
        timeout: TimeoutPolicy,
    },
    Poll {
        pfds_addr: u64,
        nfds: usize,
        timeout: TimeoutPolicy,
    },
    PipeRead {
        id: usize,
        buf: u64,
        len: usize,
    },
}

enum HartState {
    Runnable,
    Blocked(BlockOn),
    Exited,
}

struct HartSlot {
    hart: Hart,
    state: HartState,
}

pub struct Machine {
    pub mem: Memory,
    pub fs: Fs,
    pub fdt: FdTable,
    pub(crate) code_cache: cpu::CodeCache,
    harts: Vec<HartSlot>,
    cur: usize,
    pub cwd: String,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub instret: u64,
    pub exit_code: Option<i32>,
    rng_state: u64,
    pub(crate) memfd_seq: u64,
    next_tid: u64,
    /// Syscall counter for diagnostics.
    pub syscall_count: u64,
    /// MAP_SHARED file mappings needing write-back: (addr, len, path, offset).
    pub(crate) shared_maps: Vec<SharedMap>,
}

#[derive(Clone)]
pub(crate) struct SharedMap {
    pub addr: u64,
    pub len: u64,
    pub path: String,
    pub offset: u64,
}

#[derive(Debug)]
pub enum RunError {
    Loader(loader::LoadError),
    Fault { pc: u64, addr: u64, tid: u64 },
    Illegal { pc: u64, word: u32, tid: u64 },
    Ebreak { pc: u64, tid: u64 },
    UnhandledSyscall { n: u64, pc: u64 },
    Deadlock,
    BudgetExhausted,
}

pub struct RunOutcome {
    pub exit_code: i32,
    pub instret: u64,
}

const TIMESLICE: u64 = 500_000;

impl Machine {
    /// A process with no harts yet (added by `load_program`) and empty
    /// per-process state. `rng_state`'s seed is a fixed constant, not real
    /// entropy — see `next_random`'s doc and SPEC.md's "deterministic
    /// randomness" note; this is not spec-mandated behavior, it's this
    /// interpreter's determinism guarantee.
    pub fn new(fs: Fs, cwd: &str) -> Self {
        Machine {
            mem: Memory::new(),
            fs,
            fdt: FdTable::new(),
            code_cache: cpu::CodeCache::new(),
            harts: Vec::new(),
            cur: 0,
            cwd: cwd.to_string(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            instret: 0,
            exit_code: None,
            rng_state: 0x5A6B_564D_7275_7363, // "ZkVMrusc"
            memfd_seq: 0,
            next_tid: 1,
            syscall_count: 0,
            shared_maps: Vec::new(),
        }
    }

    /// Write back MAP_SHARED regions overlapping [start, start+len) to their
    /// files; len == u64::MAX flushes (and drops) everything. This is the
    /// Linux `mmap(MAP_SHARED)`/`msync` write-back contract, implemented at
    /// the syscall layer rather than as a real shared page-table mapping:
    /// `sys.rs`'s `mmap`/`munmap`/`msync` handlers call this at exactly the
    /// points real Linux would flush dirty shared pages.
    pub(crate) fn flush_shared(&mut self, start: u64, len: u64) {
        let end = start.saturating_add(len);
        let mut remaining = Vec::new();
        for sm in core::mem::take(&mut self.shared_maps) {
            let overlaps = sm.addr < end && start < sm.addr + sm.len;
            if overlaps {
                if let Ok(data) = self.mem.read_bytes(sm.addr, sm.len as usize) {
                    let _ = self.fs.write_at(&sm.path, sm.offset, &data);
                }
                // Dropped if fully covered by the unmap; kept otherwise (it
                // may be written again before a later flush).
                if !(start <= sm.addr && sm.addr + sm.len <= end) {
                    remaining.push(sm);
                }
            } else {
                remaining.push(sm);
            }
        }
        self.shared_maps = remaining;
    }

    /// Resolve and read `exe_path` from the in-memory fs, hand it to
    /// `loader::setup_process` (ELF mapping + argv/envp/auxv stack layout
    /// per the psABI, see `loader.rs`'s doc), then create hart 0 with `pc`/
    /// `sp` at the values the loader computed — this is the RISC-V/Linux
    /// equivalent of what the kernel's `execve` does when starting a fresh
    /// process image, done once here since this emulator has no `execve`
    /// syscall of its own (see SPEC.md).
    pub fn load_program(
        &mut self,
        exe_path: &str,
        argv: &[String],
        envp: &[String],
    ) -> Result<(), RunError> {
        let resolved = self
            .fs
            .resolve(&fs::normalize(&self.cwd, exe_path), true)
            .map_err(|_| RunError::Loader(loader::LoadError::BadElf("exe not found")))?;
        let data = match self.fs.get(&resolved) {
            Some(fs::Node::File { data, .. }) => data.snapshot(),
            _ => return Err(RunError::Loader(loader::LoadError::BadElf("exe not found"))),
        };
        let fs_ref = &self.fs;
        let mut lookup = |p: &str| -> Option<Arc<Vec<u8>>> {
            let r = fs_ref.resolve(&fs::normalize("/", p), true).ok()?;
            match fs_ref.get(&r) {
                Some(fs::Node::File { data, .. }) => Some(data.snapshot()),
                _ => None,
            }
        };
        let start = loader::setup_process(&mut self.mem, data, exe_path, argv, envp, &mut lookup)
            .map_err(RunError::Loader)?;
        self.mem.brk_base = start.brk_base;
        self.mem.brk = start.brk_base;
        let mut hart = Hart::new(self.next_tid);
        self.next_tid += 1;
        hart.pc = start.pc;
        hart.regs[2] = start.sp;
        self.harts.push(HartSlot {
            hart,
            state: HartState::Runnable,
        });
        Ok(())
    }

    /// Consume the machine, returning the (possibly modified) filesystem —
    /// how the pipeline in `compilation/rustc` chains multiple `Machine`
    /// runs (rustc, then rust-lld) over the same evolving fs without
    /// re-parsing the toolchain bundle each time.
    pub fn into_fs(self) -> Fs {
        self.fs
    }

    /// The Linux thread ID of whichever hart the scheduler last selected
    /// (`self.cur`) — backs the `gettid`/`set_tid_address` syscalls.
    pub(crate) fn cur_tid(&self) -> u64 {
        self.harts[self.cur].hart.tid
    }

    /// Mutable access to the currently-scheduled hart's architectural state
    /// — used by syscall handlers that need to read/write registers
    /// (e.g. `set_tid_address` writing `clear_child_tid`).
    pub(crate) fn cur_hart_mut(&mut self) -> &mut Hart {
        &mut self.harts[self.cur].hart
    }

    /// Deterministic stand-in for the wall clock (`clock_gettime`,
    /// `gettimeofday`, ...): a fixed epoch plus 2ns per instruction retired,
    /// never real time. See SPEC.md's "Deterministic time" note.
    pub(crate) fn time_ns(&self) -> u64 {
        1_784_720_659_000_000_000 + self.instret.wrapping_mul(2)
    }

    /// Deterministic stand-in for `getrandom`/`AT_RANDOM`: xorshift64* from a
    /// fixed seed, never real entropy. See SPEC.md's "Deterministic
    /// randomness" note — nothing that reads this should be treated as
    /// unpredictable.
    pub(crate) fn next_random(&mut self) -> u64 {
        let mut x = self.rng_state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng_state = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    /// Backs `clone(CLONE_VM, ...)` (thread creation, as opposed to `fork`
    /// — see `sys_clone`'s doc for why only the `CLONE_VM` case is
    /// supported at all). Copies the parent hart's full register file —
    /// per the Linux thread-creation contract, a new thread starts with
    /// the same general/float registers as its creator, just after the
    /// `clone` ecall — then overrides only what the clone flags say to
    /// change: the new stack pointer (always), `a0`=0 (the child's return
    /// value from `clone`, matching every other `fork`-family syscall's
    /// "0 in the child" convention), and TLS (`tp`, RISC-V's thread-pointer
    /// register) if `CLONE_SETTLS` was requested.
    pub(crate) fn spawn_thread(&mut self, sp: u64, tls: u64, set_tls: bool) -> u64 {
        let parent = &self.harts[self.cur].hart;
        let mut child = Hart::new(self.next_tid);
        self.next_tid += 1;
        child.pc = parent.pc; // parent pc is already past the ecall
        child.regs = parent.regs;
        child.fregs = parent.fregs;
        child.fcsr = parent.fcsr;
        child.regs[2] = sp;
        child.regs[10] = 0; // a0 = 0 in child
        if set_tls {
            child.regs[4] = tls; // tp
        }
        let tid = child.tid;
        self.harts.push(HartSlot {
            hart: child,
            state: HartState::Runnable,
        });
        tid
    }

    /// Records where to zero + futex-wake on thread exit (glibc's
    /// `pthread_join` implementation relies on `CLONE_CHILD_CLEARTID`
    /// doing exactly this — see `thread_exit` below, which is where it's
    /// consumed).
    pub(crate) fn set_clear_child_tid(&mut self, tid: u64, addr: u64) {
        for slot in &mut self.harts {
            if slot.hart.tid == tid {
                slot.hart.clear_child_tid = addr;
            }
        }
    }

    /// `FUTEX_WAKE`/`FUTEX_WAKE_BITSET` (Linux futex(2), not a RISC-V ISA
    /// concept — `futex` is a syscall-level primitive glibc's mutex/condvar
    /// implementation is built on): scans blocked harts for a
    /// bitset-intersecting match on `addr`, resumes up to `max` of them
    /// with a `0` return value (the real `FUTEX_WAIT` success return).
    pub(crate) fn futex_wake(&mut self, addr: u64, max: usize, bitset: u32) -> usize {
        let mut n = 0;
        for slot in &mut self.harts {
            if n >= max {
                break;
            }
            if let HartState::Blocked(BlockOn::Futex {
                addr: a,
                bitset: b,
                ..
            }) = &slot.state
            {
                if *a == addr && b & bitset != 0 {
                    slot.hart.regs[10] = 0; // futex_wait returns 0
                    slot.state = HartState::Runnable;
                    n += 1;
                }
            }
        }
        n
    }

    /// `FUTEX_REQUEUE`/`FUTEX_CMP_REQUEUE`: moves up to `max` harts blocked
    /// on futex `from` to instead wait on futex `to`, without waking them —
    /// the standard glibc condvar-implementation optimization (move waiters
    /// to the mutex's futex on `pthread_cond_signal` instead of waking them
    /// all just to immediately re-block on the mutex).
    pub(crate) fn futex_requeue(&mut self, from: u64, to: u64, max: usize) -> usize {
        let mut n = 0;
        for slot in &mut self.harts {
            if n >= max {
                break;
            }
            if let HartState::Blocked(BlockOn::Futex { addr, .. }) = &mut slot.state {
                if *addr == from {
                    *addr = to;
                    n += 1;
                }
            }
        }
        n
    }

    /// Backs `exit`/`exit_group` for one thread: marks it exited and, per
    /// the `CLONE_CHILD_CLEARTID` contract (see `set_clear_child_tid`),
    /// zeroes `clear_child_tid` in guest memory and futex-wakes anyone
    /// joining on it (this is precisely the kernel behavior glibc's
    /// `pthread_join` depends on). If that was the last runnable thread,
    /// the whole process is now done — sets `exit_code`, which
    /// `run_reporting`'s main loop checks every iteration.
    fn thread_exit(&mut self, code: i32) {
        let idx = self.cur;
        let ctid = self.harts[idx].hart.clear_child_tid;
        self.harts[idx].state = HartState::Exited;
        if ctid != 0 {
            let _ = self.mem.sw(ctid, 0);
            self.futex_wake(ctid, usize::MAX, u32::MAX);
        }
        // If every thread has exited, the process is done.
        if self
            .harts
            .iter()
            .all(|s| matches!(s.state, HartState::Exited))
        {
            self.exit_code = Some(code);
        }
    }

    /// Re-check whether a blocked hart can make progress — called from the
    /// scheduler (`run_reporting`) only once *every* hart is blocked, to
    /// decide whether any of them can actually be resumed (a pipe with data
    /// now available, a poll whose fd became ready) versus a genuine
    /// deadlock. Futex waits never resolve here (`false`, with a comment
    /// explaining why) — only `futex_wake`/`futex_requeue`, triggered by
    /// another hart's syscall, can unblock those; if every hart is
    /// simultaneously futex-blocked with none of them a waker, that's a
    /// real deadlock and `run_reporting` reports it as one.
    fn try_unblock(&mut self, idx: usize) -> bool {
        let block = match &self.harts[idx].state {
            HartState::Blocked(b) => b.clone(),
            _ => return false,
        };
        match block {
            BlockOn::Futex { .. } => false, // only futex_wake unblocks
            BlockOn::PipeRead { id, buf, len } => {
                let (empty, writers) = {
                    let p = &self.fdt.pipes[id];
                    (p.buf.is_empty(), p.writers)
                };
                if empty && writers > 0 {
                    return false;
                }
                if empty {
                    self.harts[idx].hart.regs[10] = 0; // EOF
                    self.harts[idx].state = HartState::Runnable;
                    return true;
                }
                let n = {
                    let p = &mut self.fdt.pipes[id];
                    let n = core::cmp::min(len, p.buf.len());
                    let chunk: Vec<u8> = p.buf.drain(..n).collect();
                    if self.mem.write_bytes(buf, &chunk).is_err() {
                        self.harts[idx].hart.regs[10] = (-fs::EFAULT) as u64;
                        self.harts[idx].state = HartState::Runnable;
                        return true;
                    }
                    n
                };
                self.harts[idx].hart.regs[10] = n as u64;
                self.harts[idx].state = HartState::Runnable;
                true
            }
            BlockOn::Poll {
                pfds_addr, nfds, ..
            } => {
                let mut ready = 0i64;
                for i in 0..nfds {
                    let base = pfds_addr + (i as u64) * 8;
                    let fd = match self.mem.lw(base) {
                        Ok(v) => v as i32 as i64,
                        Err(_) => continue,
                    };
                    let events = self.mem.lhu(base + 4).unwrap_or(0) as u16;
                    let revents = self.poll_fd_pub(fd, events);
                    let _ = self.mem.sh(base + 6, revents);
                    if revents != 0 {
                        ready += 1;
                    }
                }
                if ready > 0 {
                    self.harts[idx].hart.regs[10] = ready as u64;
                    self.harts[idx].state = HartState::Runnable;
                    return true;
                }
                false
            }
        }
    }

    /// `poll(2)`'s per-fd "which requested events are currently ready"
    /// check (`POLLIN`/`POLLOUT`/`POLLHUP` bits) — duplicated from `sys.rs`
    /// (which has its own private `poll_fd` for the direct `ppoll` syscall
    /// path) purely because `try_unblock` needs it too and `sys.rs`'s
    /// version isn't visible outside that module's `impl` block. No spec
    /// content beyond the standard POSIX poll-event semantics.
    fn poll_fd_pub(&self, fd: i64, events: u16) -> u16 {
        const POLLIN: u16 = 1;
        const POLLOUT: u16 = 4;
        const POLLHUP: u16 = 0x10;
        match self.fdt.get(fd).map(|f| &f.kind) {
            Some(fs::FdKind::PipeR { id }) => {
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
            Some(fs::FdKind::PipeW { id }) => {
                let p = &self.fdt.pipes[*id];
                let mut r = POLLOUT & events;
                if p.readers == 0 {
                    r |= POLLHUP;
                }
                r
            }
            Some(fs::FdKind::Stdin) => 0,
            Some(_) => (POLLIN | POLLOUT) & events,
            None => 0x20,
        }
    }

    /// Run until exit or error. `max_instret` bounds total executed
    /// instructions (0 = unlimited).
    pub fn run(&mut self, max_instret: u64) -> Result<RunOutcome, RunError> {
        self.run_reporting(max_instret, 0, &mut |_| {})
    }

    /// The process-level scheduler: round-robins runnable harts in fixed
    /// `TIMESLICE`-instruction chunks (`cpu::run` executes one chunk, then
    /// returns why it stopped), dispatches `Stop::Ecall` to `syscall`, and
    /// keeps going until every thread has exited (`exit_code` set) or
    /// nothing can make progress (`RunError::Deadlock`). This — not
    /// anything in the ISA — is the actual source of this interpreter's
    /// determinism: which hart runs next, and for how long, is a pure
    /// function of instruction counts and syscall results, never of
    /// wall-clock/host scheduling, so the exact same interleaving happens
    /// on every run of the exact same program (see SPEC.md's "Memory model
    /// & concurrency" section for why that also means no real hart
    /// interleaving/races are possible in the first place).
    ///
    /// Like [`Self::run`], but call `on_progress(instret)` roughly every
    /// `report_every` executed instructions (`0` disables it). Reporting is
    /// checked at the top of the scheduler loop and never alters budgeting or
    /// scheduling, so results are byte-identical to [`Self::run`].
    pub fn run_reporting(
        &mut self,
        max_instret: u64,
        report_every: u64,
        on_progress: &mut dyn FnMut(u64),
    ) -> Result<RunOutcome, RunError> {
        let mut last_report = 0u64;
        loop {
            if report_every != 0 && self.instret.wrapping_sub(last_report) >= report_every {
                on_progress(self.instret);
                last_report = self.instret;
            }
            if let Some(code) = self.exit_code {
                self.flush_shared(0, u64::MAX);
                return Ok(RunOutcome {
                    exit_code: code,
                    instret: self.instret,
                });
            }
            if max_instret != 0 && self.instret >= max_instret {
                return Err(RunError::BudgetExhausted);
            }

            // Pick next runnable hart (round-robin from cur+1).
            let n = self.harts.len();
            let mut picked = None;
            for off in 0..n {
                let idx = (self.cur + off) % n;
                if matches!(self.harts[idx].state, HartState::Runnable) {
                    picked = Some(idx);
                    break;
                }
            }
            let idx = match picked {
                Some(i) => i,
                None => {
                    // Everyone blocked: try unblocking pollers/pipe readers.
                    let mut progressed = false;
                    for i in 0..n {
                        if self.try_unblock(i) {
                            progressed = true;
                        }
                    }
                    if progressed {
                        continue;
                    }
                    // Wake one timed-out futex waiter deterministically.
                    let mut woke = false;
                    for i in 0..n {
                        if let HartState::Blocked(BlockOn::Futex {
                            timeout: TimeoutPolicy::Finite,
                            ..
                        })
                        | HartState::Blocked(BlockOn::Poll {
                            timeout: TimeoutPolicy::Finite,
                            ..
                        }) = &self.harts[i].state
                        {
                            let is_poll =
                                matches!(&self.harts[i].state, HartState::Blocked(BlockOn::Poll { .. }));
                            self.harts[i].hart.regs[10] = if is_poll {
                                0
                            } else {
                                (-fs::ETIMEDOUT) as u64
                            };
                            self.harts[i].state = HartState::Runnable;
                            woke = true;
                            break;
                        }
                    }
                    if woke {
                        continue;
                    }
                    return Err(RunError::Deadlock);
                }
            };
            self.cur = idx;

            // Run a timeslice. Invalidate LR/SC reservation across switches.
            let budget = if max_instret == 0 {
                TIMESLICE
            } else {
                core::cmp::min(TIMESLICE, max_instret - self.instret)
            };
            let (stop, executed) = {
                let slot = &mut self.harts[idx];
                cpu::run(&mut slot.hart, &mut self.mem, &mut self.code_cache, budget)
            };
            self.instret += executed;

            match stop {
                Stop::Budget => {
                    // Timeslice over; rotate.
                    self.harts[idx].hart.reservation = None;
                    self.cur = (idx + 1) % n;
                }
                Stop::Ecall => {
                    let (num, args) = {
                        let h = &self.harts[idx].hart;
                        (
                            h.regs[17],
                            [h.regs[10], h.regs[11], h.regs[12], h.regs[13], h.regs[14], h.regs[15]],
                        )
                    };
                    self.syscall_count += 1;
                    #[cfg(feature = "strace")]
                    let tid_dbg = self.harts[idx].hart.tid;
                    let res = self.syscall(num, args);
                    match res {
                        sys::SysResult::Ret(v) => {
                            #[cfg(feature = "strace")]
                            std::eprintln!("[{}] syscall {} ({:x?}) = {}", tid_dbg, num, args, v);
                            self.harts[idx].hart.regs[10] = v as u64;
                            if num == 124 {
                                // sched_yield rotates
                                self.cur = (idx + 1) % self.harts.len();
                            }
                        }
                        sys::SysResult::Block(b) => {
                            #[cfg(feature = "strace")]
                            std::eprintln!("[{}] syscall {} ({:x?}) = <blocked {:?}>", tid_dbg, num, args, b);
                            self.harts[idx].state = HartState::Blocked(b);
                            self.cur = (idx + 1) % self.harts.len();
                        }
                        sys::SysResult::ExitThread(code) => {
                            #[cfg(feature = "strace")]
                            std::eprintln!("[{}] exit({})", tid_dbg, code);
                            self.thread_exit(code);
                            self.cur = (idx + 1) % self.harts.len();
                        }
                        sys::SysResult::ExitGroup(code) => {
                            #[cfg(feature = "strace")]
                            std::eprintln!("[{}] exit_group({})", tid_dbg, code);
                            self.exit_code = Some(code);
                        }
                        sys::SysResult::Unhandled(num) => {
                            return Err(RunError::UnhandledSyscall {
                                n: num,
                                pc: self.harts[idx].hart.pc,
                            });
                        }
                    }
                }
                Stop::Fault { pc, addr } => {
                    return Err(RunError::Fault {
                        pc,
                        addr,
                        tid: self.harts[idx].hart.tid,
                    })
                }
                Stop::Illegal { pc, word } => {
                    return Err(RunError::Illegal {
                        pc,
                        word,
                        tid: self.harts[idx].hart.tid,
                    })
                }
                Stop::Ebreak { pc } => {
                    return Err(RunError::Ebreak {
                        pc,
                        tid: self.harts[idx].hart.tid,
                    })
                }
            }
        }
    }
}
