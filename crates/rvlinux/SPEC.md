# rvlinux — specification coverage & audit notes

`rvlinux` is a from-scratch, deterministic RV64GC + Zicsr interpreter and
usermode-Linux-syscall layer. It runs unmodified `riscv64-linux-gnu` ELF
binaries (in this repo: the real `rustc`/`rust-lld`, and whatever the guest
program itself does) against an in-memory filesystem, inside an SGX enclave.

This document exists for a security reviewer auditing the emulator: what
part of the RISC-V/Linux spec each module implements, and — more
importantly — every place its behavior *intentionally* diverges from real
hardware or a real kernel. Those deviations are the primary attack surface
and the primary source of "could the attested behavior differ from what a
real machine would have done."

## Reference specifications

- **Unprivileged ISA** — RISC-V Instruction Set Manual, Volume I. Canonical
  source: <https://github.com/riscv/riscv-isa-manual>. Rendered:
  <https://riscv.github.io/riscv-isa-manual/snapshot/spec/#vol:unpriv>.
  Ratified releases indexed at <https://riscv.org/specifications/>.
- **ELF calling convention / ABI** — RISC-V ELF psABI:
  <https://github.com/riscv-non-isa/riscv-elf-psabi-doc> (rendered:
  <https://riscv-non-isa.github.io/riscv-elf-psabi-doc/>).
- **Linux syscall ABI** — the generic syscall number table riscv64 uses
  unmodified: <https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/unistd.h>.

## Why pure user-mode only

Only the *unprivileged* ISA is implemented. There is no privileged spec
(S-mode/M-mode CSRs, `mret`/`sret`/`wfi`, PMP), no interrupt/trap delivery,
no vector (V) or bit-manipulation (B) extension — none of it is reachable
from a normal Linux userspace program, which is all this ever runs. Illegal
instructions and memory faults are surfaced directly to the Rust host
embedding the interpreter (`RunError::Illegal` / `RunError::Fault` in
`lib.rs`) rather than vectored to a RISC-V trap handler, because there is no
guest kernel here to vector them to.

## Instruction set coverage (`src/cpu.rs`)

| Extension | Spec chapter | Coverage | Notes |
|---|---|---|---|
| RV64I (base) | "RV32I Base Instruction Set" + "RV64I Base Instruction Set" | Full | `LUI`/`AUIPC`/`JAL`/`JALR`, all six branches, all loads/stores (byte/half/word/dword, signed+unsigned), all reg-imm/reg-reg ALU ops including the `*W` 32-bit-result forms |
| M | "M" Standard Extension | Full | `MUL`/`MULH`/`MULHSU`/`MULHU`/`DIV`/`DIVU`/`REM`/`REMU` + `*W` forms. Division-by-zero and `INT_MIN / -1` overflow return the spec-defined results (`-1`/dividend, no trap) |
| A | "A" Standard Extension | Full — `LR`/`SC` + all 9 AMO ops (swap/add/xor/or/and/min/max/minu/maxu), word and doubleword | Correctness doesn't depend on real atomicity: exactly one hart executes at a time (see Concurrency below), so these can never actually race |
| F | "F" Standard Extension | Arithmetic, compare, convert (int↔float, float↔float), classify, sign-injection, min/max, fused multiply-add family | See the floating-point caveat below |
| D | "D" Standard Extension | Same operation coverage as F, for f64 | ditto |
| C | "C" Standard Extension | Full 16-bit compressed decode | Every compressed form expands to the same execution core as its 32-bit equivalent; reserved/illegal compressed encodings fall through to `Stop::Illegal` |
| Zicsr | "Zicsr" Standard Extension | Partial | See CSR caveat below |

**Not implemented at all** (never reachable from U-mode Linux code): privileged
ISA, PMP, interrupts/traps, V (vector), B (bit-manipulation), hypervisor
extension.

**Floating point caveat**: `fcsr`/`frm`/`fflags` are stored and readable via
the CSR instructions, but **arithmetic never updates `fflags`**, and the
rounding-mode field is only honored for `FCVT.*` (int↔float conversions) —
add/sub/mul/div/sqrt always round-to-nearest-even regardless of `frm`. This
matches what LLVM/rustc actually emit (they never change `frm` away from the
default and don't rely on `fflags`), but a hand-written or exotic guest
program that depends on dynamic rounding modes or sticky exception flags for
arithmetic will observe different results than real hardware.

**CSR caveat**: only three groups are implemented — `fflags` (0x001),
`frm` (0x002), `fcsr` (0x003, the combined register), and the three
read-only performance counters `cycle`/`time`/`instret` (0xC00/0xC01/0xC02,
all aliased to the same "instructions retired" counter). **Every other CSR
read returns 0 and every other CSR write is silently ignored** — it is
*not* trapped as an illegal instruction the way real hardware traps on
access to an absent/inaccessible CSR. This is the single most notable ISA
deviation in the interpreter; if the audited guest program does anything
with CSRs beyond `fcsr`, this is where to look first.

## Memory model & concurrency (`src/mem.rs`, `src/lib.rs`)

RVWMO (the RISC-V weak memory consistency model, unprivileged spec ch.
"Memory Consistency Model") is not modeled — deliberately, and it doesn't
need to be. `Machine::run_reporting` executes **exactly one hart at a
time**, switching only at a syscall boundary or after a fixed
instruction-count timeslice (`TIMESLICE = 500_000`), via host-controlled
round robin (`lib.rs`). Two harts' instructions are never interleaved below
whole-timeslice granularity, so there is no reordering to model and no real
data race can occur — this is exactly what makes the whole pipeline's
determinism guarantee possible: given the same guest program and the same
inputs, scheduling is a pure function of instruction counts, never of
wall-clock/host timing, so the same run always produces the same result.

Memory is flat, sparse, and page-granular (4 KiB), copy-on-first-touch from
a VMA's backing (`Backing::Zero` or `Backing::File`). **Page protection
(`Vma.prot`, i.e. the `mmap`/`mprotect` `PROT_*` bits) is recorded but never
enforced** — the interpreter will fetch, load, or store through a mapping
regardless of its declared permissions. This is a genuine, ISA-visible
deviation from real hardware (which page-faults on a protection violation).
It does not weaken the SGX/attestation trust model on its own — there is no
JIT here, so "executing" non-executable memory just means the software
interpreter decodes whatever bytes live there as instructions, exactly as it
would for legitimate code; it can't let guest code escape into the host's
real instruction stream. But it does mean a guest program that depends on
W^X enforcement, or on a SIGSEGV/trap for a protection violation, will not
see one.

Misaligned loads/stores are handled transparently (split across the two
backing pages, see `Memory::load`/`store`) rather than faulting. This
matches ordinary Linux/glibc userspace expectations — the kernel traps and
emulates misaligned access for RV64 transparently by default — rather than
bare, un-trapped hardware behavior.

## Syscall coverage (`src/sys.rs`)

Numbers and calling convention follow the generic Linux syscall ABI that
riscv64 uses unmodified (see the syscall table link above): arguments
arrive in `a0..a5`, the syscall number in `a7`, the return value in `a0`.

**Implemented** (grouped by purpose): process/thread lifecycle (`exit`,
`exit_group`, `clone` — `CLONE_VM` only, i.e. threads, never processes —
`set_tid_address`, `gettid`); file I/O (`openat`, `read`/`write`/`readv`/
`writev`, `pread64`/`pwrite64`, `lseek`, `close`, `dup`/`dup3`, `fcntl`,
`ftruncate`, `getdents64`, `sendfile`, `copy_file_range`); filesystem
metadata/namespace (`fstat`/`newfstatat`/`statx`, `mkdirat`, `unlinkat`,
`renameat`/`renameat2`, `symlinkat`, `linkat`, `readlinkat`, `faccessat`/
`faccessat2`, `chdir`/`getcwd`, `statfs`/`fstatfs`); memory (`brk`, `mmap`,
`munmap`, `mremap`, `mprotect`, `madvise` — `MADV_DONTNEED`/`MADV_FREE` only
— `msync`); synchronization (`futex` — `WAIT`/`WAKE`/`REQUEUE`/
`CMP_REQUEUE`, bitset variants); polling (`ppoll`, `pselect6` stub); time
(`clock_gettime`, `clock_getres`, `gettimeofday`, `times`); misc info
(`uname`, `getpid`/`getppid`/`getuid`-family, `getrandom`, `sysinfo`,
`getrusage`, `sched_getaffinity`, `riscv_hwprobe`); signals (stubs only —
see below); `prlimit64`/`getrlimit`/`setrlimit`; `memfd_create`;
`close_range`.

**Deliberately unimplemented or hard-stubbed** — this is the primary audit
surface for "could attested behavior differ from a real Linux/RISC-V
machine":

- **`execve` (syscall 221) always returns `-ENOSYS`.** A guest program can
  never replace its own image or spawn another program via exec. `clone`
  without `CLONE_VM` (i.e. `fork`) is rejected the same way. This is a hard
  architectural constraint, not an oversight: it's why the verifiable
  compilation pipeline built on this emulator runs `rustc` and `rust-lld` as
  two *separate*, host-orchestrated `Machine` instances instead of letting
  `rustc` invoke its own linker subprocess (see
  `compilation/rustc/src/pipeline.rs`'s module doc for the consequences).
- **No real process tree.** `wait4`/`waitid` always return `-ECHILD` —
  there are never child processes to reap, since neither `fork` nor
  `execve` exist.
- **No real signal delivery.** `rt_sigaction`/`rt_sigprocmask`/
  `sigaltstack` are no-ops reporting "nothing installed/blocked"; `kill`/
  `tkill`/`tgkill` special-case only signal 6 (`SIGABRT`), translated to
  `exit_group(134)` (matching the shell-visible exit code for an uncaught
  `SIGABRT` on real Linux) — every other signal number is silently accepted
  and does nothing. A guest program that installs and depends on a signal
  handler (e.g. catching `SIGSEGV`) behaves differently than on real Linux.
- **No real network.** `socket` → `-EAFNOSUPPORT`, `connect` → `-EBADF`;
  no address family is supported at all.
- **Deterministic time.** `clock_gettime`/`gettimeofday`/`times` derive a
  synthetic clock as `1_784_720_659_000_000_000 + instret * 2` (a fixed
  epoch plus two nanoseconds per instruction retired), never real
  wall-clock time. Two runs of the same program retire the same
  instructions in the same order and therefore observe identical
  timestamps, by construction.
- **Deterministic "randomness".** `getrandom` is backed by a fixed-seed
  xorshift64\* PRNG (`Machine::next_random`, seeded from the constant
  `0x5A6B_564D_7275_7363` — ASCII "ZkVMrusc" — a name that gives away this
  interpreter's prior life as an SP1 zkVM guest before this project's SGX
  reuse), not a real entropy source. `AT_RANDOM` in the initial auxv
  (`loader.rs`) is likewise a hardcoded 16-byte constant, not per-run
  randomness. This is deliberate — reproducibility is the entire point —
  but it means nothing that touches `getrandom`/`AT_RANDOM` should be
  treated as unpredictable, by the guest program or by anyone reasoning
  about what the guest program will do.
- **Filesystem timestamps are a fixed constant** (`1_700_000_000`), never
  real mtimes.
- **`riscv_hwprobe`** reports a fixed IMAFDC feature set (matching exactly
  what `cpu.rs` implements) regardless of what host CPU is actually running
  the interpreter.

## ELF loading (`src/loader.rs`)

Loads `ET_EXEC` and `ET_DYN` (following `PT_INTERP`) RV64 ELF binaries per
the standard Linux `binfmt_elf` convention: `PT_LOAD` segments mapped with
file-backed pages plus a zero-filled BSS tail, and an initial stack built
with argv/envp/auxv matching what glibc's/musl's C runtime startup code
expects (`AT_PHDR`/`AT_PHENT`/`AT_PHNUM`/`AT_BASE`/`AT_ENTRY`/`AT_HWCAP`/
`AT_RANDOM`/`AT_EXECFN`/`AT_PLATFORM`, `AT_SECURE=0`). See the psABI
document (link above) for the calling-convention details this depends on
downstream (e.g. `a0`=argc at `_start`), which the CRT startup code sets up
from this stack layout — the loader itself only builds the layout, not the
convention.

`AT_HWCAP` is hardcoded to `0x112d` — bits for extensions I, M, A, F, D, C —
matching exactly the instruction set implemented in `cpu.rs`.

## Determinism summary

Every source of real-world non-determinism a Linux program can normally
observe has been replaced with a value that is a pure function of
already-executed instruction count and/or a fixed constant: wall-clock time,
"randomness", filesystem timestamps, and thread scheduling order
(deterministic round-robin over a fixed timeslice) are all covered above;
the toolchain/rootfs bundle content is verified by hash before the emulator
ever sees it (`bundle.rs`, and `compilation/rustc`'s use of it). This is
what lets the enclave's signed attestation mean "this exact input produced
this exact output," rather than "probably, modulo whatever the host felt
like doing that day" — and it is exactly the property an audit should be
checking for regressions against: any new syscall, instruction, or code path
that reads real time, real randomness, or real host state would break it.
