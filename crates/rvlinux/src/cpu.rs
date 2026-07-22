//! RV64IMAFDC + Zicsr interpreter with a predecoded instruction cache.
//!
//! Hot path: instructions are decoded once into a compact `Decoded` form
//! (per-page arrays, absolute branch targets precomputed) and executed from
//! the cache. Rare ops (AMO, FP, CSR, fences) fall back to `exec_slow`, which
//! interprets the raw instruction word stored in the cache entry.
//!
//! Floating point uses host f32/f64 (both the Apple Silicon host and the SP1
//! guest are IEEE-754); rounding modes are honored for conversions (where
//! compilers emit RTZ) and ignored for arithmetic (rustc never changes frm).
//!
//! Implements the unprivileged ISA only (RV32I/RV64I base, M, A, F, D, C,
//! partial Zicsr) — see `../SPEC.md` for the exact coverage table, the
//! floating-point and CSR caveats, and why no privileged-mode state exists
//! here at all. Spec: <https://github.com/riscv/riscv-isa-manual>
//! (rendered: <https://riscv.github.io/riscv-isa-manual/snapshot/spec/#vol:unpriv>).

use crate::mem::{MemFault, Memory, PAGE_SHIFT};
use crate::FxMap;
use alloc::boxed::Box;
use alloc::vec::Vec;

pub struct Hart {
    pub regs: [u64; 32],
    pub fregs: [u64; 32],
    pub pc: u64,
    pub fcsr: u64,
    pub tid: u64,
    /// LR/SC reservation address.
    pub reservation: Option<u64>,
    pub clear_child_tid: u64,
}

impl Hart {
    /// Fresh architectural state for one hart: all 32 GPRs zeroed (`x0` stays
    /// hardwired zero for the hart's lifetime — see `wr!` in `run` below),
    /// all 32 FPRs holding a NaN-boxed f32 NaN (the spec-defined power-on
    /// value for an implementation with no reset-defined FP state), `pc` and
    /// `fcsr` zeroed. The loader overwrites `pc`/`regs[2]` (sp) after this.
    pub fn new(tid: u64) -> Self {
        Hart {
            regs: [0; 32],
            fregs: [0xFFFF_FFFF_7FC0_0000; 32], // NaN-boxed f32 NaN
            pc: 0,
            fcsr: 0,
            tid,
            reservation: None,
            clear_child_tid: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {
    Budget,
    Ecall,
    Ebreak { pc: u64 },
    Fault { pc: u64, addr: u64 },
    Illegal { pc: u64, word: u32 },
}

// ---- decoded representation ----

#[derive(Clone, Copy)]
pub struct Decoded {
    op: u16,
    rd: u8,
    rs1: u8,
    rs2: u8,
    len: u8,
    imm: u64,
}

const INVALID: Decoded = Decoded {
    op: op::INVALID,
    rd: 0,
    rs1: 0,
    rs2: 0,
    len: 0,
    imm: 0,
};

#[allow(non_upper_case_globals)]
mod op {
    pub const INVALID: u16 = 0;
    pub const LUI: u16 = 1; // rd = imm (also AUIPC, resolved)
    pub const JAL: u16 = 2; // rd = pc+len; pc = imm
    pub const JALR: u16 = 3;
    pub const BEQ: u16 = 4;
    pub const BNE: u16 = 5;
    pub const BLT: u16 = 6;
    pub const BGE: u16 = 7;
    pub const BLTU: u16 = 8;
    pub const BGEU: u16 = 9;
    pub const LB: u16 = 10;
    pub const LH: u16 = 11;
    pub const LW: u16 = 12;
    pub const LD: u16 = 13;
    pub const LBU: u16 = 14;
    pub const LHU: u16 = 15;
    pub const LWU: u16 = 16;
    pub const SB: u16 = 17;
    pub const SH: u16 = 18;
    pub const SW: u16 = 19;
    pub const SD: u16 = 20;
    pub const ADDI: u16 = 21;
    pub const SLTI: u16 = 22;
    pub const SLTIU: u16 = 23;
    pub const XORI: u16 = 24;
    pub const ORI: u16 = 25;
    pub const ANDI: u16 = 26;
    pub const SLLI: u16 = 27;
    pub const SRLI: u16 = 28;
    pub const SRAI: u16 = 29;
    pub const ADDIW: u16 = 30;
    pub const SLLIW: u16 = 31;
    pub const SRLIW: u16 = 32;
    pub const SRAIW: u16 = 33;
    pub const ADD: u16 = 34;
    pub const SUB: u16 = 35;
    pub const SLL: u16 = 36;
    pub const SLT: u16 = 37;
    pub const SLTU: u16 = 38;
    pub const XOR: u16 = 39;
    pub const SRL: u16 = 40;
    pub const SRA: u16 = 41;
    pub const OR: u16 = 42;
    pub const AND: u16 = 43;
    pub const ADDW: u16 = 44;
    pub const SUBW: u16 = 45;
    pub const SLLW: u16 = 46;
    pub const SRLW: u16 = 47;
    pub const SRAW: u16 = 48;
    pub const MUL: u16 = 49;
    pub const MULH: u16 = 50;
    pub const MULHSU: u16 = 51;
    pub const MULHU: u16 = 52;
    pub const DIV: u16 = 53;
    pub const DIVU: u16 = 54;
    pub const REM: u16 = 55;
    pub const REMU: u16 = 56;
    pub const MULW: u16 = 57;
    pub const DIVW: u16 = 58;
    pub const DIVUW: u16 = 59;
    pub const REMW: u16 = 60;
    pub const REMUW: u16 = 61;
    pub const FLW: u16 = 62;
    pub const FLD: u16 = 63;
    pub const FSW: u16 = 64;
    pub const FSD: u16 = 65;
    pub const ECALL: u16 = 66;
    pub const EBREAK: u16 = 67;
    pub const NOP: u16 = 68; // fences
    /// Everything else: raw 32-bit word in `imm`, executed by exec_slow.
    pub const SLOW: u16 = 69;
}

const ENTRIES_PER_PAGE: usize = 2048; // one per halfword

pub struct CodeCache {
    map: FxMap<u64, u32>,
    arena: Vec<Box<[Decoded; ENTRIES_PER_PAGE]>>,
    tlb: [(u64, u32); 64],
}

impl CodeCache {
    /// Empty cache: no pages decoded yet, TLB slots all tagged `u64::MAX`
    /// (never a valid page index) so the first lookup for any page is
    /// guaranteed to miss and fall through to `slot`'s slow path.
    pub fn new() -> Self {
        CodeCache {
            map: FxMap::default(),
            arena: Vec::new(),
            tlb: [(u64::MAX, 0); 64],
        }
    }

    /// Discard every decoded instruction. Not spec behavior per se — this is
    /// the correctness fix for a purely emulator-internal optimization: if
    /// the guest `munmap`s or `mmap`s over a file-backed (i.e. possibly
    /// executable) region, any previously cached decode of that address
    /// range is stale and must not be reused (see the `munmap`/`mmap`
    /// syscall handlers in `sys.rs`, which call this exactly when that can
    /// happen).
    pub fn clear(&mut self) {
        self.map.clear();
        self.arena.clear();
        self.tlb = [(u64::MAX, 0); 64];
    }

    /// Map a 4 KiB page index to its arena slot of predecoded instructions,
    /// allocating a fresh (all-`INVALID`) slot on first sight. A tiny
    /// direct-mapped TLB (`tlb`) short-circuits the common case of staying
    /// on the same page across consecutive instructions — pure performance,
    /// no ISA meaning; the page itself is not part of any RISC-V structure.
    #[inline]
    fn slot(&mut self, page: u64) -> u32 {
        let t = (page as usize) & 63;
        let (tag, slot) = self.tlb[t];
        if tag == page {
            return slot;
        }
        let slot = match self.map.get(&page) {
            Some(&s) => s,
            None => {
                let s = self.arena.len() as u32;
                self.arena.push(Box::new([INVALID; ENTRIES_PER_PAGE]));
                self.map.insert(page, s);
                s
            }
        };
        self.tlb[t] = (page, slot);
        slot
    }
}

/// Sign-extend the low `bits` bits of `v` to a full 64-bit value. Used for
/// every immediate field the spec defines as sign-extended (I/S/B/U/J-type
/// immediates in ch. "RV32I", and the compressed-immediate formats in ch.
/// "C") — shift-left-then-arithmetic-shift-right is the standard trick.
#[inline]
fn sext(v: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift) as u64
}

// ---- decoding ----

/// Decode the instruction at `pc`. Per spec ("Base Instruction-Length
/// Encoding"), the low 2 bits of the first halfword distinguish a 16-bit
/// compressed instruction (`!= 0b11`) from a 32-bit one, which is why only
/// one halfword is fetched before that check — the second halfword is only
/// read (and combined little-endian) once we know we need it. Returns Err
/// on a fetch fault (unmapped page — surfaced to the caller as `Stop::Fault`).
fn decode(mem: &mut Memory, pc: u64) -> Result<Decoded, MemFault> {
    let lo = u16::from_le_bytes(mem.load::<2>(pc)?);
    if lo & 3 != 3 {
        return Ok(decode_compressed(lo, pc));
    }
    let hi = u16::from_le_bytes(mem.load::<2>(pc + 2)?);
    let inst = (lo as u32) | ((hi as u32) << 16);
    Ok(decode32(inst, pc))
}

/// Plain struct literal helper — exists only so every `decode32`/
/// `decode_compressed` arm below reads as one line instead of a multi-line
/// struct expression. No spec meaning of its own.
fn dec(op_: u16, rd: usize, rs1: usize, rs2: usize, len: u8, imm: u64) -> Decoded {
    Decoded {
        op: op_,
        rd: rd as u8,
        rs1: rs1 as u8,
        rs2: rs2 as u8,
        len,
        imm,
    }
}

/// Mark a decoded instruction as "not one of the fast-dispatch cases" —
/// stashes the raw word for `exec_slow` to re-decode. Used both for
/// genuinely rare-but-legal encodings (AMO, FP, CSR, fences) and for
/// anything the fast decoder doesn't recognize at all, which `exec_slow`
/// then rejects as `Stop::Illegal` if it isn't legal either.
fn slow(word: u32) -> Decoded {
    dec(op::SLOW, 0, 0, 0, 4, word as u64)
}

/// Decode one 32-bit instruction word per the RV32I/RV64I base opcode map
/// (spec ch. "RV32/64G Instruction Set Listings") plus the M extension
/// (opcodes 0x33/0x3B with `funct7 == 1`) and F/D loads/stores/CSR/ecall
/// (opcodes 0x07/0x27/0x73). Every arm below picks out exactly the
/// `opcode`/`funct3`/`funct7` combination the spec assigns to that
/// instruction; anything not matched falls through to `slow` for `exec_slow`
/// (AMO/FMADD/other FP ops) or is genuinely illegal.
fn decode32(inst: u32, pc: u64) -> Decoded {
    let opcode = inst & 0x7F;
    let rd = ((inst >> 7) & 31) as usize;
    let rs1 = ((inst >> 15) & 31) as usize;
    let rs2 = ((inst >> 20) & 31) as usize;
    let funct3 = (inst >> 12) & 7;
    let funct7 = inst >> 25;
    let imm_i = sext((inst >> 20) as u64, 12);
    let shamt6 = ((inst >> 20) & 63) as u64;
    let shamt5 = ((inst >> 20) & 31) as u64;

    match opcode {
        0x37 => dec(op::LUI, rd, 0, 0, 4, sext((inst & 0xFFFF_F000) as u64, 32)),
        0x17 => dec(
            op::LUI,
            rd,
            0,
            0,
            4,
            pc.wrapping_add(sext((inst & 0xFFFF_F000) as u64, 32)),
        ),
        0x6F => {
            let imm = ((inst >> 31) as u64) << 20
                | (((inst >> 12) & 0xFF) as u64) << 12
                | (((inst >> 20) & 1) as u64) << 11
                | (((inst >> 21) & 0x3FF) as u64) << 1;
            dec(op::JAL, rd, 0, 0, 4, pc.wrapping_add(sext(imm, 21)))
        }
        0x67 => dec(op::JALR, rd, rs1, 0, 4, imm_i),
        0x63 => {
            let imm = ((inst >> 31) as u64) << 12
                | (((inst >> 7) & 1) as u64) << 11
                | (((inst >> 25) & 0x3F) as u64) << 5
                | (((inst >> 8) & 0xF) as u64) << 1;
            let target = pc.wrapping_add(sext(imm, 13));
            let o = match funct3 {
                0 => op::BEQ,
                1 => op::BNE,
                4 => op::BLT,
                5 => op::BGE,
                6 => op::BLTU,
                7 => op::BGEU,
                _ => return slow(inst),
            };
            dec(o, 0, rs1, rs2, 4, target)
        }
        0x03 => {
            let o = match funct3 {
                0 => op::LB,
                1 => op::LH,
                2 => op::LW,
                3 => op::LD,
                4 => op::LBU,
                5 => op::LHU,
                6 => op::LWU,
                _ => return slow(inst),
            };
            dec(o, rd, rs1, 0, 4, imm_i)
        }
        0x23 => {
            let imm = sext((((inst >> 25) as u64) << 5) | ((inst >> 7) & 31) as u64, 12);
            let o = match funct3 {
                0 => op::SB,
                1 => op::SH,
                2 => op::SW,
                3 => op::SD,
                _ => return slow(inst),
            };
            dec(o, 0, rs1, rs2, 4, imm)
        }
        0x13 => match funct3 {
            0 => dec(op::ADDI, rd, rs1, 0, 4, imm_i),
            1 => dec(op::SLLI, rd, rs1, 0, 4, shamt6),
            2 => dec(op::SLTI, rd, rs1, 0, 4, imm_i),
            3 => dec(op::SLTIU, rd, rs1, 0, 4, imm_i),
            4 => dec(op::XORI, rd, rs1, 0, 4, imm_i),
            5 => {
                if funct7 >> 1 == 0x10 {
                    dec(op::SRAI, rd, rs1, 0, 4, shamt6)
                } else {
                    dec(op::SRLI, rd, rs1, 0, 4, shamt6)
                }
            }
            6 => dec(op::ORI, rd, rs1, 0, 4, imm_i),
            7 => dec(op::ANDI, rd, rs1, 0, 4, imm_i),
            _ => slow(inst),
        },
        0x1B => match funct3 {
            0 => dec(op::ADDIW, rd, rs1, 0, 4, imm_i),
            1 => dec(op::SLLIW, rd, rs1, 0, 4, shamt5),
            5 => {
                if funct7 == 0x20 {
                    dec(op::SRAIW, rd, rs1, 0, 4, shamt5)
                } else {
                    dec(op::SRLIW, rd, rs1, 0, 4, shamt5)
                }
            }
            _ => slow(inst),
        },
        0x33 => {
            if funct7 == 1 {
                let o = match funct3 {
                    0 => op::MUL,
                    1 => op::MULH,
                    2 => op::MULHSU,
                    3 => op::MULHU,
                    4 => op::DIV,
                    5 => op::DIVU,
                    6 => op::REM,
                    7 => op::REMU,
                    _ => return slow(inst),
                };
                dec(o, rd, rs1, rs2, 4, 0)
            } else {
                let o = match (funct3, funct7) {
                    (0, 0x00) => op::ADD,
                    (0, 0x20) => op::SUB,
                    (1, 0x00) => op::SLL,
                    (2, 0x00) => op::SLT,
                    (3, 0x00) => op::SLTU,
                    (4, 0x00) => op::XOR,
                    (5, 0x00) => op::SRL,
                    (5, 0x20) => op::SRA,
                    (6, 0x00) => op::OR,
                    (7, 0x00) => op::AND,
                    _ => return slow(inst),
                };
                dec(o, rd, rs1, rs2, 4, 0)
            }
        }
        0x3B => {
            if funct7 == 1 {
                let o = match funct3 {
                    0 => op::MULW,
                    4 => op::DIVW,
                    5 => op::DIVUW,
                    6 => op::REMW,
                    7 => op::REMUW,
                    _ => return slow(inst),
                };
                dec(o, rd, rs1, rs2, 4, 0)
            } else {
                let o = match (funct3, funct7) {
                    (0, 0x00) => op::ADDW,
                    (0, 0x20) => op::SUBW,
                    (1, 0x00) => op::SLLW,
                    (5, 0x00) => op::SRLW,
                    (5, 0x20) => op::SRAW,
                    _ => return slow(inst),
                };
                dec(o, rd, rs1, rs2, 4, 0)
            }
        }
        0x07 => match funct3 {
            2 => dec(op::FLW, rd, rs1, 0, 4, imm_i),
            3 => dec(op::FLD, rd, rs1, 0, 4, imm_i),
            _ => slow(inst),
        },
        0x27 => {
            let imm = sext((((inst >> 25) as u64) << 5) | ((inst >> 7) & 31) as u64, 12);
            match funct3 {
                2 => dec(op::FSW, 0, rs1, rs2, 4, imm),
                3 => dec(op::FSD, 0, rs1, rs2, 4, imm),
                _ => slow(inst),
            }
        }
        0x0F => dec(op::NOP, 0, 0, 0, 4, 0),
        0x73 => {
            if funct3 == 0 {
                match inst >> 20 {
                    0 => dec(op::ECALL, 0, 0, 0, 4, 0),
                    1 => dec(op::EBREAK, 0, 0, 0, 4, 0),
                    _ => slow(inst),
                }
            } else {
                slow(inst)
            }
        }
        _ => slow(inst),
    }
}

/// Decode one 16-bit compressed instruction per the C extension's quadrant
/// table (spec ch. "C", `funct3`/quadrant `op` determine the format exactly
/// as the three `CIW`/`CL`/`CS`/`CI`/`CR`/`CB`/`CJ` tables lay out). Every
/// arm expands its compressed form to the *same* `op::` opcode its 32-bit
/// equivalent decodes to (e.g. `c.addi` becomes plain `ADDI`), so `run`'s
/// execution core never needs to know compressed forms exist at all — this
/// is exactly how the spec defines C: as a lossless encoding of a subset of
/// the base+M+F+D instructions, not a distinct instruction semantics.
/// Reserved/all-zero encodings (illegal per spec) fall through to `slow`.
fn decode_compressed(inst: u16, _pc: u64) -> Decoded {
    let o = inst & 3;
    let funct3 = (inst >> 13) & 7;
    let i = inst as u64;
    let rd_full = ((inst >> 7) & 31) as usize;
    let rs2_full = ((inst >> 2) & 31) as usize;
    let rc1 = 8 + ((inst >> 7) & 7) as usize;
    let rc2 = 8 + ((inst >> 2) & 7) as usize;

    match (o, funct3) {
        (0, 0) => {
            let imm = ((i >> 7) & 0x30) | ((i >> 1) & 0x3C0) | ((i >> 4) & 4) | ((i >> 2) & 8);
            if imm == 0 {
                return dec(op::SLOW, 0, 0, 0, 2, inst as u64); // illegal
            }
            dec(op::ADDI, rc2, 2, 0, 2, imm)
        }
        (0, 1) => {
            let imm = ((i >> 7) & 0x38) | ((i << 1) & 0xC0);
            dec(op::FLD, rc2, rc1, 0, 2, imm)
        }
        (0, 2) => {
            let imm = ((i >> 7) & 0x38) | ((i >> 4) & 4) | ((i << 1) & 0x40);
            dec(op::LW, rc2, rc1, 0, 2, imm)
        }
        (0, 3) => {
            let imm = ((i >> 7) & 0x38) | ((i << 1) & 0xC0);
            dec(op::LD, rc2, rc1, 0, 2, imm)
        }
        (0, 5) => {
            let imm = ((i >> 7) & 0x38) | ((i << 1) & 0xC0);
            dec(op::FSD, 0, rc1, rc2, 2, imm)
        }
        (0, 6) => {
            let imm = ((i >> 7) & 0x38) | ((i >> 4) & 4) | ((i << 1) & 0x40);
            dec(op::SW, 0, rc1, rc2, 2, imm)
        }
        (0, 7) => {
            let imm = ((i >> 7) & 0x38) | ((i << 1) & 0xC0);
            dec(op::SD, 0, rc1, rc2, 2, imm)
        }
        (1, 0) => {
            let imm = sext(((i >> 7) & 0x20) | ((i >> 2) & 0x1F), 6);
            dec(op::ADDI, rd_full, rd_full, 0, 2, imm)
        }
        (1, 1) => {
            let imm = sext(((i >> 7) & 0x20) | ((i >> 2) & 0x1F), 6);
            dec(op::ADDIW, rd_full, rd_full, 0, 2, imm)
        }
        (1, 2) => {
            let imm = sext(((i >> 7) & 0x20) | ((i >> 2) & 0x1F), 6);
            dec(op::ADDI, rd_full, 0, 0, 2, imm)
        }
        (1, 3) => {
            if rd_full == 2 {
                let imm = sext(
                    ((i >> 3) & 0x200)
                        | ((i >> 2) & 0x10)
                        | ((i << 1) & 0x40)
                        | ((i << 4) & 0x180)
                        | ((i << 3) & 0x20),
                    10,
                );
                dec(op::ADDI, 2, 2, 0, 2, imm)
            } else {
                let imm = sext((((i >> 7) & 0x20) | ((i >> 2) & 0x1F)) << 12, 18);
                if imm == 0 {
                    return dec(op::SLOW, 0, 0, 0, 2, inst as u64);
                }
                dec(op::LUI, rd_full, 0, 0, 2, imm)
            }
        }
        (1, 4) => {
            let f2 = (inst >> 10) & 3;
            match f2 {
                0 => {
                    let shamt = ((i >> 7) & 0x20) | ((i >> 2) & 0x1F);
                    dec(op::SRLI, rc1, rc1, 0, 2, shamt)
                }
                1 => {
                    let shamt = ((i >> 7) & 0x20) | ((i >> 2) & 0x1F);
                    dec(op::SRAI, rc1, rc1, 0, 2, shamt)
                }
                2 => {
                    let imm = sext(((i >> 7) & 0x20) | ((i >> 2) & 0x1F), 6);
                    dec(op::ANDI, rc1, rc1, 0, 2, imm)
                }
                _ => {
                    let bit12 = (inst >> 12) & 1;
                    let f2b = (inst >> 5) & 3;
                    let o2 = match (bit12, f2b) {
                        (0, 0) => op::SUB,
                        (0, 1) => op::XOR,
                        (0, 2) => op::OR,
                        (0, 3) => op::AND,
                        (1, 0) => op::SUBW,
                        (1, 1) => op::ADDW,
                        _ => return dec(op::SLOW, 0, 0, 0, 2, inst as u64),
                    };
                    dec(o2, rc1, rc1, rc2, 2, 0)
                }
            }
        }
        (1, 5) => {
            let imm = sext(
                ((i >> 1) & 0x800)
                    | ((i << 2) & 0x400)
                    | ((i >> 1) & 0x300)
                    | ((i << 1) & 0x80)
                    | ((i >> 1) & 0x40)
                    | ((i << 3) & 0x20)
                    | ((i >> 7) & 0x10)
                    | ((i >> 2) & 0xE),
                12,
            );
            dec(op::JAL, 0, 0, 0, 2, _pc.wrapping_add(imm))
        }
        (1, 6) | (1, 7) => {
            let imm = sext(
                ((i >> 4) & 0x100)
                    | ((i << 1) & 0xC0)
                    | ((i << 3) & 0x20)
                    | ((i >> 7) & 0x18)
                    | ((i >> 2) & 0x6),
                9,
            );
            let o2 = if funct3 == 6 { op::BEQ } else { op::BNE };
            dec(o2, 0, rc1, 0, 2, _pc.wrapping_add(imm)) // rs2 = x0
        }
        (2, 0) => {
            let shamt = ((i >> 7) & 0x20) | ((i >> 2) & 0x1F);
            dec(op::SLLI, rd_full, rd_full, 0, 2, shamt)
        }
        (2, 1) => {
            let imm = ((i >> 7) & 0x20) | ((i >> 2) & 0x18) | ((i << 4) & 0x1C0);
            dec(op::FLD, rd_full, 2, 0, 2, imm)
        }
        (2, 2) => {
            let imm = ((i >> 7) & 0x20) | ((i >> 2) & 0x1C) | ((i << 4) & 0xC0);
            dec(op::LW, rd_full, 2, 0, 2, imm)
        }
        (2, 3) => {
            let imm = ((i >> 7) & 0x20) | ((i >> 2) & 0x18) | ((i << 4) & 0x1C0);
            dec(op::LD, rd_full, 2, 0, 2, imm)
        }
        (2, 4) => {
            let bit12 = (inst >> 12) & 1;
            if bit12 == 0 {
                if rs2_full == 0 {
                    // c.jr
                    dec(op::JALR, 0, rd_full, 0, 2, 0)
                } else {
                    // c.mv -> add rd, x0, rs2
                    dec(op::ADD, rd_full, 0, rs2_full, 2, 0)
                }
            } else if rs2_full == 0 {
                if rd_full == 0 {
                    dec(op::EBREAK, 0, 0, 0, 2, 0)
                } else {
                    // c.jalr
                    dec(op::JALR, 1, rd_full, 0, 2, 0)
                }
            } else {
                dec(op::ADD, rd_full, rd_full, rs2_full, 2, 0)
            }
        }
        (2, 5) => {
            let imm = ((i >> 7) & 0x38) | ((i >> 1) & 0x1C0);
            dec(op::FSD, 0, 2, rs2_full, 2, imm)
        }
        (2, 6) => {
            let imm = ((i >> 7) & 0x3C) | ((i >> 1) & 0xC0);
            dec(op::SW, 0, 2, rs2_full, 2, imm)
        }
        (2, 7) => {
            let imm = ((i >> 7) & 0x38) | ((i >> 1) & 0x1C0);
            dec(op::SD, 0, 2, rs2_full, 2, imm)
        }
        _ => dec(op::SLOW, 0, 0, 0, 2, inst as u64),
    }
}

// ---- float helpers (slow path) ----

/// Un-NaN-box a 64-bit FP register into an f32 (spec ch. "F" /
/// "NaN Boxing of Narrower Values", also required when D is present per ch.
/// "D"): a legally-produced f32 value always has all upper 32 bits set to
/// 1; anything else means a wider (or garbage) value was left there, which
/// per spec must be treated as the canonical quiet NaN rather than
/// reinterpreted as a float.
#[inline]
fn unbox_f32(v: u64) -> f32 {
    if v >> 32 == 0xFFFF_FFFF {
        f32::from_bits(v as u32)
    } else {
        f32::from_bits(0x7FC0_0000)
    }
}
/// NaN-box an f32 result into the 64-bit register file, per the same
/// spec rule `unbox_f32` reads back: upper 32 bits all-1s marks "this is a
/// single-precision value," so a later D-extension op reading the same
/// register can tell it's not a valid double.
#[inline]
fn box_f32(f: f32) -> u64 {
    0xFFFF_FFFF_0000_0000 | f.to_bits() as u64
}

/// `FMIN.D`: spec-defined min, which differs from IEEE-754/Rust's `f64::min`
/// on two points the spec is explicit about — two NaNs produce the
/// canonical quiet NaN (not either input), and `-0.0`/`+0.0` compare as
/// `-0.0 < +0.0` (unlike default IEEE min, which treats them as equal).
fn f_min64(a: f64, b: f64) -> f64 {
    if a.is_nan() && b.is_nan() {
        return f64::from_bits(0x7FF8_0000_0000_0000);
    }
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a == 0.0 && b == 0.0 {
        return if a.is_sign_negative() { a } else { b };
    }
    if a < b { a } else { b }
}
/// `FMAX.D`: same spec rule as `f_min64`, mirrored — signed zero picks
/// `+0.0` over `-0.0`, both-NaN produces the canonical quiet NaN.
fn f_max64(a: f64, b: f64) -> f64 {
    if a.is_nan() && b.is_nan() {
        return f64::from_bits(0x7FF8_0000_0000_0000);
    }
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a == 0.0 && b == 0.0 {
        return if a.is_sign_positive() { a } else { b };
    }
    if a > b { a } else { b }
}
/// `FMIN.S`: same spec rule as `f_min64`, at single precision.
fn f_min32(a: f32, b: f32) -> f32 {
    if a.is_nan() && b.is_nan() {
        return f32::from_bits(0x7FC0_0000);
    }
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a == 0.0 && b == 0.0 {
        return if a.is_sign_negative() { a } else { b };
    }
    if a < b { a } else { b }
}
/// `FMAX.S`: same spec rule as `f_max64`, at single precision.
fn f_max32(a: f32, b: f32) -> f32 {
    if a.is_nan() && b.is_nan() {
        return f32::from_bits(0x7FC0_0000);
    }
    if a.is_nan() {
        return b;
    }
    if b.is_nan() {
        return a;
    }
    if a == 0.0 && b == 0.0 {
        return if a.is_sign_positive() { a } else { b };
    }
    if a > b { a } else { b }
}

/// Apply an `FCVT.*` rounding mode (spec ch. "F", "Rounding Modes" — RNE/
/// RTZ/RDN/RUP/RMM, encoding 7 = "use `frm`" instead of an explicit static
/// mode). Only conversions honor this field at all — see the module doc's
/// floating-point caveat for why arithmetic doesn't.
fn round_f64(v: f64, rm: u32, frm: u32) -> f64 {
    let mode = if rm == 7 { frm } else { rm };
    match mode {
        0 => libm::rint(v),
        1 => libm::trunc(v),
        2 => libm::floor(v),
        3 => libm::ceil(v),
        4 => libm::round(v),
        _ => libm::rint(v),
    }
}
/// Single-precision counterpart of `round_f64`.
fn round_f32(v: f32, rm: u32, frm: u32) -> f32 {
    let mode = if rm == 7 { frm } else { rm };
    match mode {
        0 => libm::rintf(v),
        1 => libm::truncf(v),
        2 => libm::floorf(v),
        3 => libm::ceilf(v),
        4 => libm::roundf(v),
        _ => libm::rintf(v),
    }
}

/// `FCVT.*.{S,D}` float→int saturating conversion (spec ch. "F", the
/// `FCVT` int-conversion rule): out-of-range and NaN inputs saturate to the
/// destination type's max (NaN treated as "positive out of range" per
/// spec), rather than wrapping or trapping.
macro_rules! fcvt_to_int {
    ($v:expr, $ty:ty, $min:expr, $max:expr) => {{
        let v = $v;
        if v.is_nan() {
            $max as u64
        } else if v < $min as f64 {
            $min as u64
        } else if v > $max as f64 {
            $max as u64
        } else {
            (v as $ty) as u64
        }
    }};
}

/// `FCLASS.D`: the spec's 10-category bitmask (ch. "F", "FCLASS
/// Instruction" table — bit 0 -inf .. bit 9 quiet NaN). The mantissa MSB
/// distinguishes quiet (bit set) from signaling (bit clear) NaN, which is
/// the one category IEEE-754 alone doesn't give you directly.
fn fclass64(v: f64) -> u64 {
    let bits = v.to_bits();
    let sign = bits >> 63 == 1;
    if v.is_nan() {
        if bits & (1 << 51) != 0 {
            1 << 9
        } else {
            1 << 8
        }
    } else if v.is_infinite() {
        if sign { 1 << 0 } else { 1 << 7 }
    } else if v == 0.0 {
        if sign { 1 << 3 } else { 1 << 4 }
    } else if v.is_subnormal() {
        if sign { 1 << 2 } else { 1 << 5 }
    } else if sign {
        1 << 1
    } else {
        1 << 6
    }
}
/// `FCLASS.S`: same spec table as `fclass64`, single precision (mantissa
/// MSB at bit 22 instead of bit 51 distinguishes quiet/signaling NaN).
fn fclass32(v: f32) -> u64 {
    let bits = v.to_bits();
    let sign = bits >> 31 == 1;
    if v.is_nan() {
        if bits & (1 << 22) != 0 {
            1 << 9
        } else {
            1 << 8
        }
    } else if v.is_infinite() {
        if sign { 1 << 0 } else { 1 << 7 }
    } else if v == 0.0 {
        if sign { 1 << 3 } else { 1 << 4 }
    } else if v.is_subnormal() {
        if sign { 1 << 2 } else { 1 << 5 }
    } else if sign {
        1 << 1
    } else {
        1 << 6
    }
}

// ---- main interpreter ----

/// The instruction-retirement loop: fetch (from `cache`, decoding on a
/// cache miss), execute, repeat, until `budget` instructions have retired or
/// a trap-equivalent condition (`ecall`/`ebreak`/illegal/fault) stops
/// early — this function *is* "hart execution" per the unprivileged spec's
/// operational model of fetch-decode-execute-retire, minus the M-mode/S-mode
/// trap vectoring a real CPU would do (there is nowhere to vector to; see
/// the crate doc's note on why this interpreter has no privileged state).
/// Arms below are grouped by spec chapter with `----` divider comments; the
/// grouping is purely for a reader — Rust's `match` doesn't care about arm
/// order, and correctness never depends on it. Every arm ends by writing
/// `hart.pc` explicitly (either `pc + len` for fallthrough, or a computed
/// target for control flow), which is deliberate: it makes "did this
/// instruction advance the PC correctly" a local, per-arm property to
/// audit rather than something threaded implicitly through the loop.
pub fn run(hart: &mut Hart, mem: &mut Memory, cache: &mut CodeCache, budget: u64) -> (Stop, u64) {
    let mut executed: u64 = 0;

    macro_rules! fault {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(MemFault(a)) => {
                    return (
                        Stop::Fault {
                            pc: hart.pc,
                            addr: a,
                        },
                        executed,
                    )
                }
            }
        };
    }

    // Page-local dispatch: skip the cache TLB while pc stays in one page.
    let mut cur_page: u64 = u64::MAX;
    let mut cur_slot: u32 = 0;

    while executed < budget {
        let pc = hart.pc;
        let page = pc >> PAGE_SHIFT;
        if page != cur_page {
            cur_slot = cache.slot(page);
            cur_page = page;
        }
        let idx = ((pc & 4095) >> 1) as usize & 2047;
        let mut d = cache.arena[cur_slot as usize][idx];
        if d.op == op::INVALID {
            d = fault!(decode(mem, pc));
            cache.arena[cur_slot as usize][idx] = d;
        }
        executed += 1;

        let rd = d.rd as usize;
        let rs1 = d.rs1 as usize;
        let rs2 = d.rs2 as usize;
        let x1 = hart.regs[rs1];
        let x2 = hart.regs[rs2];
        let imm = d.imm;

        macro_rules! wr {
            ($v:expr) => {{
                let v = $v;
                if rd != 0 {
                    hart.regs[rd] = v;
                }
            }};
        }

        match d.op {
            // ---- RV64I base (spec ch. "RV32I"/"RV64I"): ADDI plus the
            // doubleword/word load-store pair. The remaining RV64I
            // loads/stores, ALU-immediate, and register-register ops are
            // further down — arm order here is arbitrary, not grouped by
            // category throughout (see the `run` doc above). ----
            op::ADDI => {
                wr!(x1.wrapping_add(imm));
                hart.pc = pc + d.len as u64;
            }
            op::LD => {
                let v = fault!(mem.ld(x1.wrapping_add(imm)));
                wr!(v);
                hart.pc = pc + d.len as u64;
            }
            op::SD => {
                fault!(mem.sd(x1.wrapping_add(imm), x2));
                hart.pc = pc + d.len as u64;
            }
            op::LW => {
                let v = fault!(mem.lw(x1.wrapping_add(imm)));
                wr!(v as u64);
                hart.pc = pc + d.len as u64;
            }
            op::SW => {
                fault!(mem.sw(x1.wrapping_add(imm), x2 as u32));
                hart.pc = pc + d.len as u64;
            }
            // ---- RV64I: conditional branches. `imm` was resolved to an
            // absolute target address at decode time (`decode32`/
            // `decode_compressed`), so execution is just "pick target or
            // fallthrough" — no relative-offset arithmetic happens here. ----
            op::BEQ => {
                hart.pc = if x1 == x2 { imm } else { pc + d.len as u64 };
            }
            op::BNE => {
                hart.pc = if x1 != x2 { imm } else { pc + d.len as u64 };
            }
            op::BLT => {
                hart.pc = if (x1 as i64) < (x2 as i64) {
                    imm
                } else {
                    pc + d.len as u64
                };
            }
            op::BGE => {
                hart.pc = if (x1 as i64) >= (x2 as i64) {
                    imm
                } else {
                    pc + d.len as u64
                };
            }
            op::BLTU => {
                hart.pc = if x1 < x2 { imm } else { pc + d.len as u64 };
            }
            op::BGEU => {
                hart.pc = if x1 >= x2 { imm } else { pc + d.len as u64 };
            }
            // ---- RV64I: unconditional jumps. Both write the link register
            // (return address) before changing `pc`, matching the spec's
            // "rd = pc+len" definition for JAL/JALR; JALR additionally
            // clears bit 0 of the target per spec (the LSB of the computed
            // address is ignored, not an alignment requirement violation). ----
            op::JAL => {
                wr!(pc + d.len as u64);
                hart.pc = imm;
            }
            op::JALR => {
                let target = x1.wrapping_add(imm) & !1;
                wr!(pc + d.len as u64);
                hart.pc = target;
            }
            // LUI: `imm` already holds the final value at decode time — for
            // `LUI` that's `imm << 12` sign-extended, and `decode32` also
            // resolves AUIPC (opcode 0x17) into this same op by
            // precomputing `pc + (imm << 12)`, since both instructions are
            // "write a computed 64-bit constant to rd."
            op::LUI => {
                wr!(imm);
                hart.pc = pc + d.len as u64;
            }
            // ---- RV64I: register-register ADD/SUB (the rest of this
            // group — SLL..AND — is further down, after the immediate-ALU
            // and shift groups). ----
            op::ADD => {
                wr!(x1.wrapping_add(x2));
                hart.pc = pc + d.len as u64;
            }
            op::SUB => {
                wr!(x1.wrapping_sub(x2));
                hart.pc = pc + d.len as u64;
            }
            // ---- RV64I: the remaining loads/stores (byte/halfword, plus
            // LWU) not covered in the first group above. ----
            op::LB => {
                let v = fault!(mem.lb(x1.wrapping_add(imm)));
                wr!(v as u64);
                hart.pc = pc + d.len as u64;
            }
            op::LH => {
                let v = fault!(mem.lh(x1.wrapping_add(imm)));
                wr!(v as u64);
                hart.pc = pc + d.len as u64;
            }
            op::LBU => {
                let v = fault!(mem.lbu(x1.wrapping_add(imm)));
                wr!(v);
                hart.pc = pc + d.len as u64;
            }
            op::LHU => {
                let v = fault!(mem.lhu(x1.wrapping_add(imm)));
                wr!(v);
                hart.pc = pc + d.len as u64;
            }
            op::LWU => {
                let v = fault!(mem.lwu(x1.wrapping_add(imm)));
                wr!(v);
                hart.pc = pc + d.len as u64;
            }
            op::SB => {
                fault!(mem.sb(x1.wrapping_add(imm), x2 as u8));
                hart.pc = pc + d.len as u64;
            }
            op::SH => {
                fault!(mem.sh(x1.wrapping_add(imm), x2 as u16));
                hart.pc = pc + d.len as u64;
            }
            // ---- RV64I: register-immediate ALU (SLTI..ANDI). SLTI/SLTIU
            // compare as signed/unsigned per spec; note SLTIU's immediate
            // is still sign-extended at decode before the unsigned compare,
            // matching the spec's explicit "SLTIU" rule (compare unsigned,
            // but the 12-bit immediate is still sign-extended to XLEN
            // first). ----
            op::SLTI => {
                wr!(((x1 as i64) < (imm as i64)) as u64);
                hart.pc = pc + d.len as u64;
            }
            op::SLTIU => {
                wr!((x1 < imm) as u64);
                hart.pc = pc + d.len as u64;
            }
            op::XORI => {
                wr!(x1 ^ imm);
                hart.pc = pc + d.len as u64;
            }
            op::ORI => {
                wr!(x1 | imm);
                hart.pc = pc + d.len as u64;
            }
            op::ANDI => {
                wr!(x1 & imm);
                hart.pc = pc + d.len as u64;
            }
            // ---- RV64I: immediate shifts. `imm` already holds the
            // 6-bit shift amount extracted at decode time (`shamt6` in
            // `decode32`) — RV64I widens the shift-amount field to 6 bits
            // (vs RV32I's 5) precisely to allow shifting a full 64-bit
            // register, which is why SLLI/SRLI/SRAI need no masking here
            // (decode already bounded it to 0..63). ----
            op::SLLI => {
                wr!(x1 << imm);
                hart.pc = pc + d.len as u64;
            }
            op::SRLI => {
                wr!(x1 >> imm);
                hart.pc = pc + d.len as u64;
            }
            op::SRAI => {
                wr!(((x1 as i64) >> imm) as u64);
                hart.pc = pc + d.len as u64;
            }
            // ---- RV64I "*W" forms (spec ch. "RV64I", "Word" instructions):
            // RV64-only ops that compute a 32-bit result and sign-extend it
            // to 64 bits, letting 32-bit C/Rust code run correctly on a
            // 64-bit register file. `sext(..., 32)` here is exactly that
            // sign-extension step. ----
            op::ADDIW => {
                wr!(sext(x1.wrapping_add(imm) & 0xFFFF_FFFF, 32));
                hart.pc = pc + d.len as u64;
            }
            op::SLLIW => {
                wr!(sext(((x1 as u32) << imm) as u64, 32));
                hart.pc = pc + d.len as u64;
            }
            op::SRLIW => {
                wr!(sext(((x1 as u32) >> imm) as u64, 32));
                hart.pc = pc + d.len as u64;
            }
            op::SRAIW => {
                wr!(((x1 as i32) >> imm) as i64 as u64);
                hart.pc = pc + d.len as u64;
            }
            // ---- RV64I: the rest of register-register ALU (ADD/SUB were
            // above, near LUI). Shift amounts mask to 6 bits (`x2 & 63`)
            // per spec — only the low log2(XLEN) bits of rs2 are used as
            // the shift amount, the rest is architecturally ignored. ----
            op::SLL => {
                wr!(x1 << (x2 & 63));
                hart.pc = pc + d.len as u64;
            }
            op::SLT => {
                wr!(((x1 as i64) < (x2 as i64)) as u64);
                hart.pc = pc + d.len as u64;
            }
            op::SLTU => {
                wr!((x1 < x2) as u64);
                hart.pc = pc + d.len as u64;
            }
            op::XOR => {
                wr!(x1 ^ x2);
                hart.pc = pc + d.len as u64;
            }
            op::SRL => {
                wr!(x1 >> (x2 & 63));
                hart.pc = pc + d.len as u64;
            }
            op::SRA => {
                wr!(((x1 as i64) >> (x2 & 63)) as u64);
                hart.pc = pc + d.len as u64;
            }
            op::OR => {
                wr!(x1 | x2);
                hart.pc = pc + d.len as u64;
            }
            op::AND => {
                wr!(x1 & x2);
                hart.pc = pc + d.len as u64;
            }
            // ---- RV64I: register-register "*W" forms — same 32-bit-then-
            // sign-extend rule as the immediate "*W" group above, and same
            // 5-bit (not 6-bit) shift mask as real RV64I SLLW/SRLW/SRAW
            // (`x2 & 31`, since the result is only 32 bits wide). ----
            op::ADDW => {
                wr!(sext((x1 as u32).wrapping_add(x2 as u32) as u64, 32));
                hart.pc = pc + d.len as u64;
            }
            op::SUBW => {
                wr!(sext((x1 as u32).wrapping_sub(x2 as u32) as u64, 32));
                hart.pc = pc + d.len as u64;
            }
            op::SLLW => {
                wr!(sext(((x1 as u32) << (x2 & 31)) as u64, 32));
                hart.pc = pc + d.len as u64;
            }
            op::SRLW => {
                wr!(sext(((x1 as u32) >> (x2 & 31)) as u64, 32));
                hart.pc = pc + d.len as u64;
            }
            op::SRAW => {
                wr!(((x1 as i32) >> (x2 & 31)) as i64 as u64);
                hart.pc = pc + d.len as u64;
            }
            // ---- M extension (spec ch. "M"): multiply/divide/remainder,
            // full XLEN and the "*W" 32-bit forms. `MULH*` computes the
            // upper 64 bits of a full 128-bit product via i128/u128
            // widening — the only way to get the spec-defined high half
            // without a real widening multiplier. Division-by-zero and
            // signed-overflow (`MIN / -1`) each follow the spec's explicit
            // defined results below, never a trap: division by zero
            // returns all-ones (`DIV`/`DIVU`) or the dividend unchanged
            // (`REM`/`REMU`); `MIN / -1` returns the dividend (`DIV`) or
            // zero (`REM`), since the true quotient doesn't fit. ----
            op::MUL => {
                wr!(x1.wrapping_mul(x2));
                hart.pc = pc + d.len as u64;
            }
            op::MULH => {
                wr!((((x1 as i64 as i128) * (x2 as i64 as i128)) >> 64) as u64);
                hart.pc = pc + d.len as u64;
            }
            op::MULHSU => {
                wr!((((x1 as i64 as i128) * (x2 as u128 as i128)) >> 64) as u64);
                hart.pc = pc + d.len as u64;
            }
            op::MULHU => {
                wr!((((x1 as u128) * (x2 as u128)) >> 64) as u64);
                hart.pc = pc + d.len as u64;
            }
            op::DIV => {
                let v = if x2 == 0 {
                    u64::MAX
                } else if x1 as i64 == i64::MIN && x2 as i64 == -1 {
                    x1
                } else {
                    ((x1 as i64) / (x2 as i64)) as u64
                };
                wr!(v);
                hart.pc = pc + d.len as u64;
            }
            op::DIVU => {
                wr!(if x2 == 0 { u64::MAX } else { x1 / x2 });
                hart.pc = pc + d.len as u64;
            }
            op::REM => {
                let v = if x2 == 0 {
                    x1
                } else if x1 as i64 == i64::MIN && x2 as i64 == -1 {
                    0
                } else {
                    ((x1 as i64) % (x2 as i64)) as u64
                };
                wr!(v);
                hart.pc = pc + d.len as u64;
            }
            op::REMU => {
                wr!(if x2 == 0 { x1 } else { x1 % x2 });
                hart.pc = pc + d.len as u64;
            }
            // M extension "*W" forms: same defined-not-trapped zero/overflow
            // rules as above, computed at 32 bits then sign-extended.
            op::MULW => {
                wr!(sext((x1 as u32).wrapping_mul(x2 as u32) as u64, 32));
                hart.pc = pc + d.len as u64;
            }
            op::DIVW => {
                let a = x1 as i32;
                let b = x2 as i32;
                let r = if b == 0 {
                    -1i32
                } else if a == i32::MIN && b == -1 {
                    a
                } else {
                    a / b
                };
                wr!(r as i64 as u64);
                hart.pc = pc + d.len as u64;
            }
            op::DIVUW => {
                let a = x1 as u32;
                let b = x2 as u32;
                let r = if b == 0 { u32::MAX } else { a / b };
                wr!(r as i32 as i64 as u64);
                hart.pc = pc + d.len as u64;
            }
            op::REMW => {
                let a = x1 as i32;
                let b = x2 as i32;
                let r = if b == 0 {
                    a
                } else if a == i32::MIN && b == -1 {
                    0
                } else {
                    a % b
                };
                wr!(r as i64 as u64);
                hart.pc = pc + d.len as u64;
            }
            op::REMUW => {
                let a = x1 as u32;
                let b = x2 as u32;
                let r = if b == 0 { a } else { a % b };
                wr!(r as i32 as i64 as u64);
                hart.pc = pc + d.len as u64;
            }
            // ---- F/D extensions: floating-point loads/stores (spec ch.
            // "F"/"D"). `FLW` NaN-boxes the loaded 32 bits into the 64-bit
            // FP register file on the way in (see `unbox_f32`'s doc for why
            // that convention exists); `FLD` and the stores move the full
            // 64 bits untouched, since a register already holding a NaN-
            // boxed f32 stores back out exactly the bit pattern a real FSD
            // would produce. ----
            op::FLW => {
                let v = fault!(mem.lwu(x1.wrapping_add(imm)));
                hart.fregs[rd] = 0xFFFF_FFFF_0000_0000 | v;
                hart.pc = pc + d.len as u64;
            }
            op::FLD => {
                hart.fregs[rd] = fault!(mem.ld(x1.wrapping_add(imm)));
                hart.pc = pc + d.len as u64;
            }
            op::FSW => {
                fault!(mem.sw(x1.wrapping_add(imm), hart.fregs[rs2] as u32));
                hart.pc = pc + d.len as u64;
            }
            op::FSD => {
                fault!(mem.sd(x1.wrapping_add(imm), hart.fregs[rs2]));
                hart.pc = pc + d.len as u64;
            }
            // FENCE/FENCE.I (opcode 0x0F, decoded to NOP in `decode32`):
            // correct as a no-op specifically because there is only ever
            // one hart executing at once and no separate instruction cache
            // to invalidate beyond `CodeCache` (which the syscall layer
            // clears explicitly whenever memory content could change under
            // it — see `CodeCache::clear`'s doc) — so there is nothing for
            // an ordering/sync fence to actually order here.
            op::NOP => {
                hart.pc = pc + d.len as u64;
            }
            // ECALL: the sole way a guest requests a Linux syscall (spec
            // ch. "Zicsr/environment calls" — riscv64 has no separate
            // "syscall" instruction). Advances `pc` *before* returning so
            // the syscall layer resumes just after the ecall, matching the
            // real ABI convention that a syscall doesn't restart itself.
            op::ECALL => {
                hart.pc = pc + d.len as u64;
                return (Stop::Ecall, executed);
            }
            // EBREAK: spec-defined breakpoint trap. This interpreter has no
            // debugger to trap to, so it's surfaced to the host as a hard
            // stop rather than silently ignored or advancing past it.
            op::EBREAK => {
                return (Stop::Ebreak { pc }, executed);
            }
            // Anything `decode` couldn't fast-path (AMO, CSR, FP arithmetic/
            // FMADD, or truly unrecognized bits) — re-decode the raw word
            // in `exec_slow`, which is also where genuinely illegal
            // encodings finally get rejected.
            op::SLOW => {
                let word = imm as u32;
                match exec_slow(hart, mem, word, executed) {
                    Ok(()) => {}
                    Err(stop) => return (stop, executed),
                }
            }
            // Reserved/never-produced-by-decode opcode value: unreachable
            // in practice (every `op::` constant above is handled), kept as
            // a safety net rather than `unreachable!()` so a future decoder
            // bug surfaces as a clean `Stop::Illegal` instead of a panic.
            _ => {
                return (
                    Stop::Illegal {
                        pc,
                        word: imm as u32,
                    },
                    executed,
                )
            }
        }
        // x0 is never written: every rd write is guarded by `wr!`.
    }
    (Stop::Budget, executed)
}

/// Re-decodes and executes one instruction the fast path couldn't handle:
/// AMO (A extension, opcode 0x2F), CSR access (Zicsr, opcode 0x73),
/// fused-multiply-add (F/D, opcodes 0x43/0x47/0x4B/0x4F), and the rest of
/// F/D arithmetic (opcode 0x53). Dispatch is by raw `opcode` here rather
/// than the pretokenized `Decoded` form `run` uses, because these need more
/// decode fields (funct7, rs3, rounding mode) than `Decoded` has room for —
/// a deliberate trade-off of decode cost against memory footprint, since
/// these opcodes are rare in practice (real programs are overwhelmingly
/// base-ALU/load-store/branch instructions). Always advances `pc` by 4 on
/// success (none of these have a compressed 2-byte form) or returns the
/// `Stop` a fault/illegal encoding should produce.
fn exec_slow(hart: &mut Hart, mem: &mut Memory, inst: u32, executed: u64) -> Result<(), Stop> {
    let pc = hart.pc;
    let opcode = inst & 0x7F;
    let rd = ((inst >> 7) & 31) as usize;
    let rs1 = ((inst >> 15) & 31) as usize;
    let rs2 = ((inst >> 20) & 31) as usize;
    let funct3 = (inst >> 12) & 7;
    let funct7 = inst >> 25;
    let x1 = hart.regs[rs1];
    let x2 = hart.regs[rs2];

    macro_rules! fault {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(MemFault(a)) => return Err(Stop::Fault { pc, addr: a }),
            }
        };
    }
    macro_rules! wr {
        ($v:expr) => {{
            let v = $v;
            if rd != 0 {
                hart.regs[rd] = v;
            }
        }};
    }
    macro_rules! illegal {
        () => {
            return Err(Stop::Illegal { pc, word: inst })
        };
    }

    match opcode {
        // A extension (spec ch. "A"): LR/SC (aop 0x02/0x03) plus the 9 AMO
        // read-modify-write ops, word (`width == 2`) or doubleword. The
        // LR/SC reservation (`hart.reservation`) is a single `Option<u64>`
        // rather than a real reservation-set data structure because only
        // one hart ever executes at a time (see the crate/lib.rs docs on
        // concurrency) — nothing can invalidate a reservation "behind its
        // back" except this hart's own next SC or a timeslice rotation,
        // and `Machine::run_reporting` clears it on every rotation
        // (`Stop::Budget` arm in `lib.rs`), which is exactly the spec's
        // permitted "invalidate on any event that might indicate progress
        // by another hart" rule, applied conservatively.
        0x2F => {
            let width = funct3;
            let aop = funct7 >> 2;
            let addr = x1;
            match aop {
                0x02 => {
                    let v = if width == 2 {
                        fault!(mem.lw(addr)) as u64
                    } else {
                        fault!(mem.ld(addr))
                    };
                    hart.reservation = Some(addr);
                    wr!(v);
                }
                0x03 => {
                    if hart.reservation == Some(addr) {
                        if width == 2 {
                            fault!(mem.sw(addr, x2 as u32));
                        } else {
                            fault!(mem.sd(addr, x2));
                        }
                        wr!(0);
                    } else {
                        wr!(1);
                    }
                    hart.reservation = None;
                }
                _ => {
                    let old = if width == 2 {
                        fault!(mem.lw(addr)) as u64
                    } else {
                        fault!(mem.ld(addr))
                    };
                    let newv = if width == 2 {
                        let o = old as u32;
                        let b = x2 as u32;
                        let r: u32 = match aop {
                            0x01 => b,
                            0x00 => o.wrapping_add(b),
                            0x04 => o ^ b,
                            0x08 => o | b,
                            0x0C => o & b,
                            0x10 => core::cmp::min(o as i32, b as i32) as u32,
                            0x14 => core::cmp::max(o as i32, b as i32) as u32,
                            0x18 => core::cmp::min(o, b),
                            0x1C => core::cmp::max(o, b),
                            _ => illegal!(),
                        };
                        r as u64
                    } else {
                        match aop {
                            0x01 => x2,
                            0x00 => old.wrapping_add(x2),
                            0x04 => old ^ x2,
                            0x08 => old | x2,
                            0x0C => old & x2,
                            0x10 => core::cmp::min(old as i64, x2 as i64) as u64,
                            0x14 => core::cmp::max(old as i64, x2 as i64) as u64,
                            0x18 => core::cmp::min(old, x2),
                            0x1C => core::cmp::max(old, x2),
                            _ => illegal!(),
                        }
                    };
                    if width == 2 {
                        fault!(mem.sw(addr, newv as u32));
                    } else {
                        fault!(mem.sd(addr, newv));
                    }
                    wr!(old);
                }
            }
            hart.pc += 4;
        }
        // Zicsr (spec ch. "Zicsr"; ecall/ebreak share this opcode but are
        // handled in the fast path via `funct3 == 0`, never reaching here).
        // `funct3` selects CSRRW/CSRRS/CSRRC (register source) vs their `I`
        // immediate-source variants (`funct3 >= 5` uses `rs1` itself as a
        // 5-bit zero-extended immediate, per spec) — bit 0 of `funct3 & 3`
        // distinguishes "write" (RW) from "set/clear against old value"
        // (RS/RC), and RS/RC additionally skip the write entirely when
        // `rs1 == x0` (spec: "shall not cause any side effects" when the
        // source is x0, since ORing/ANDing with an all-zero mask changes
        // nothing to set/clear anyway). Only `fflags`/`frm`/`fcsr` and the
        // three read-only counters are backed by real state — every other
        // CSR number reads as 0 and silently no-ops on write rather than
        // trapping (see SPEC.md's CSR caveat: this is the most significant
        // ISA deviation in this interpreter).
        0x73 => {
            let csr = (inst >> 20) as u16;
            let zimm = rs1 as u64;
            let old = match csr {
                0x001 => hart.fcsr & 0x1F,
                0x002 => (hart.fcsr >> 5) & 7,
                0x003 => hart.fcsr,
                0xC00 | 0xC01 | 0xC02 => executed,
                _ => 0,
            };
            let src = if funct3 >= 5 { zimm } else { x1 };
            let new = match funct3 & 3 {
                1 => src,
                2 => old | src,
                3 => old & !src,
                _ => old,
            };
            let write = match funct3 & 3 {
                1 => true,
                2 | 3 => rs1 != 0,
                _ => false,
            };
            if write {
                match csr {
                    0x001 => hart.fcsr = (hart.fcsr & !0x1F) | (new & 0x1F),
                    0x002 => hart.fcsr = (hart.fcsr & !0xE0) | ((new & 7) << 5),
                    0x003 => hart.fcsr = new & 0xFF,
                    _ => {}
                }
            }
            wr!(old);
            hart.pc += 4;
        }
        // F/D fused multiply-add family (spec ch. "F"/"D": FMADD/FMSUB/
        // FNMSUB/FNMADD, one opcode per sign combination on the product and
        // addend — the four opcodes here map 1:1 to those four spec
        // mnemonics). `fmt` (bits 25-26 of the instruction, the spec's
        // `fmt` field) selects single (0) vs double precision; `rs3` is the
        // three-operand form's third source register, a field that only
        // exists for this instruction family (hence needing `exec_slow`'s
        // raw-word re-decode rather than the fast path's fixed rd/rs1/rs2
        // shape). `libm::fma[f]` gives the single correctly-rounded
        // (intermediate not rounded twice) result the spec requires, rather
        // than a separate multiply-then-add.
        0x43 | 0x47 | 0x4B | 0x4F => {
            let rs3 = (inst >> 27) as usize;
            let fmt = (inst >> 25) & 3;
            if fmt == 0 {
                let a = unbox_f32(hart.fregs[rs1]);
                let b = unbox_f32(hart.fregs[rs2]);
                let c = unbox_f32(hart.fregs[rs3]);
                let r = match opcode {
                    0x43 => libm::fmaf(a, b, c),
                    0x47 => libm::fmaf(a, b, -c),
                    0x4B => libm::fmaf(-a, b, c),
                    0x4F => libm::fmaf(-a, b, -c),
                    _ => unreachable!(),
                };
                hart.fregs[rd] = box_f32(r);
            } else {
                let a = f64::from_bits(hart.fregs[rs1]);
                let b = f64::from_bits(hart.fregs[rs2]);
                let c = f64::from_bits(hart.fregs[rs3]);
                let r = match opcode {
                    0x43 => libm::fma(a, b, c),
                    0x47 => libm::fma(a, b, -c),
                    0x4B => libm::fma(-a, b, c),
                    0x4F => libm::fma(-a, b, -c),
                    _ => unreachable!(),
                };
                hart.fregs[rd] = r.to_bits();
            }
            hart.pc += 4;
        }
        // The rest of F/D (spec ch. "F"/"D"): `funct7` alone (per the
        // spec's opcode-map table) picks both the operation *and* precision
        // — odd values (…01, …05, …09, …0D, …15, …21, …51, …61, …69, …71)
        // are the double-precision twin of the even value right before it.
        // Covers: arithmetic (add/sub/mul/div/sqrt, 0x00-0x2D), sign-inject
        // FSGNJ/FSGNJN/FSGNJX (0x10/0x11, `rm` selects which of the three),
        // FMIN/FMAX (0x14/0x15, `rm==0` picks min), single↔double FCVT
        // (0x20/0x21), compare FEQ/FLT/FLE (0x50/0x51, `rm` selects which),
        // float→int and int→float FCVT (0x60/0x61/0x68/0x69, `rs2` selects
        // the integer type per spec — it's a static field here, not a real
        // register), FCLASS/FMV.X.W (0x70/0x71, `rm` disambiguates since
        // they share an opcode+funct7 and differ only in `rm`), and
        // FMV.W.X/FMV.D.X (0x78/0x79, raw bit-pattern move, no conversion).
        0x53 => {
            let rm = funct3;
            let frm = ((hart.fcsr >> 5) & 7) as u32;
            match funct7 {
                0x00 => {
                    let r = unbox_f32(hart.fregs[rs1]) + unbox_f32(hart.fregs[rs2]);
                    hart.fregs[rd] = box_f32(r);
                }
                0x01 => {
                    let r = f64::from_bits(hart.fregs[rs1]) + f64::from_bits(hart.fregs[rs2]);
                    hart.fregs[rd] = r.to_bits();
                }
                0x04 => {
                    let r = unbox_f32(hart.fregs[rs1]) - unbox_f32(hart.fregs[rs2]);
                    hart.fregs[rd] = box_f32(r);
                }
                0x05 => {
                    let r = f64::from_bits(hart.fregs[rs1]) - f64::from_bits(hart.fregs[rs2]);
                    hart.fregs[rd] = r.to_bits();
                }
                0x08 => {
                    let r = unbox_f32(hart.fregs[rs1]) * unbox_f32(hart.fregs[rs2]);
                    hart.fregs[rd] = box_f32(r);
                }
                0x09 => {
                    let r = f64::from_bits(hart.fregs[rs1]) * f64::from_bits(hart.fregs[rs2]);
                    hart.fregs[rd] = r.to_bits();
                }
                0x0C => {
                    let r = unbox_f32(hart.fregs[rs1]) / unbox_f32(hart.fregs[rs2]);
                    hart.fregs[rd] = box_f32(r);
                }
                0x0D => {
                    let r = f64::from_bits(hart.fregs[rs1]) / f64::from_bits(hart.fregs[rs2]);
                    hart.fregs[rd] = r.to_bits();
                }
                0x2C => {
                    let r = libm::sqrtf(unbox_f32(hart.fregs[rs1]));
                    hart.fregs[rd] = box_f32(r);
                }
                0x2D => {
                    let r = libm::sqrt(f64::from_bits(hart.fregs[rs1]));
                    hart.fregs[rd] = r.to_bits();
                }
                0x10 => {
                    let a = if hart.fregs[rs1] >> 32 == 0xFFFF_FFFF {
                        hart.fregs[rs1] as u32
                    } else {
                        0x7FC0_0000
                    };
                    let b = if hart.fregs[rs2] >> 32 == 0xFFFF_FFFF {
                        hart.fregs[rs2] as u32
                    } else {
                        0x7FC0_0000
                    };
                    let r = match rm {
                        0 => (a & 0x7FFF_FFFF) | (b & 0x8000_0000),
                        1 => (a & 0x7FFF_FFFF) | (!b & 0x8000_0000),
                        2 => a ^ (b & 0x8000_0000),
                        _ => illegal!(),
                    };
                    hart.fregs[rd] = 0xFFFF_FFFF_0000_0000 | r as u64;
                }
                0x11 => {
                    let a = hart.fregs[rs1];
                    let b = hart.fregs[rs2];
                    const SIGN: u64 = 1 << 63;
                    let r = match rm {
                        0 => (a & !SIGN) | (b & SIGN),
                        1 => (a & !SIGN) | (!b & SIGN),
                        2 => a ^ (b & SIGN),
                        _ => illegal!(),
                    };
                    hart.fregs[rd] = r;
                }
                0x14 => {
                    let a = unbox_f32(hart.fregs[rs1]);
                    let b = unbox_f32(hart.fregs[rs2]);
                    let r = if rm == 0 { f_min32(a, b) } else { f_max32(a, b) };
                    hart.fregs[rd] = box_f32(r);
                }
                0x15 => {
                    let a = f64::from_bits(hart.fregs[rs1]);
                    let b = f64::from_bits(hart.fregs[rs2]);
                    let r = if rm == 0 { f_min64(a, b) } else { f_max64(a, b) };
                    hart.fregs[rd] = r.to_bits();
                }
                0x20 => {
                    let r = f64::from_bits(hart.fregs[rs1]) as f32;
                    hart.fregs[rd] = box_f32(r);
                }
                0x21 => {
                    let r = unbox_f32(hart.fregs[rs1]) as f64;
                    hart.fregs[rd] = r.to_bits();
                }
                0x50 => {
                    let a = unbox_f32(hart.fregs[rs1]);
                    let b = unbox_f32(hart.fregs[rs2]);
                    let v = match rm {
                        2 => (a == b) as u64,
                        1 => (a < b) as u64,
                        0 => (a <= b) as u64,
                        _ => illegal!(),
                    };
                    wr!(v);
                }
                0x51 => {
                    let a = f64::from_bits(hart.fregs[rs1]);
                    let b = f64::from_bits(hart.fregs[rs2]);
                    let v = match rm {
                        2 => (a == b) as u64,
                        1 => (a < b) as u64,
                        0 => (a <= b) as u64,
                        _ => illegal!(),
                    };
                    wr!(v);
                }
                0x60 => {
                    let v = round_f32(unbox_f32(hart.fregs[rs1]), rm, frm) as f64;
                    let r = match rs2 {
                        0 => sext(fcvt_to_int!(v, i32, i32::MIN, i32::MAX), 32),
                        1 => sext(fcvt_to_int!(v, u32, 0u32, u32::MAX), 32),
                        2 => fcvt_to_int!(v, i64, i64::MIN, i64::MAX),
                        3 => fcvt_to_int!(v, u64, 0u64, u64::MAX),
                        _ => illegal!(),
                    };
                    wr!(r);
                }
                0x61 => {
                    let v = round_f64(f64::from_bits(hart.fregs[rs1]), rm, frm);
                    let r = match rs2 {
                        0 => sext(fcvt_to_int!(v, i32, i32::MIN, i32::MAX), 32),
                        1 => sext(fcvt_to_int!(v, u32, 0u32, u32::MAX), 32),
                        2 => fcvt_to_int!(v, i64, i64::MIN, i64::MAX),
                        3 => fcvt_to_int!(v, u64, 0u64, u64::MAX),
                        _ => illegal!(),
                    };
                    wr!(r);
                }
                0x68 => {
                    let r = match rs2 {
                        0 => (x1 as i32) as f32,
                        1 => (x1 as u32) as f32,
                        2 => (x1 as i64) as f32,
                        3 => x1 as f32,
                        _ => illegal!(),
                    };
                    hart.fregs[rd] = box_f32(r);
                }
                0x69 => {
                    let r = match rs2 {
                        0 => (x1 as i32) as f64,
                        1 => (x1 as u32) as f64,
                        2 => (x1 as i64) as f64,
                        3 => x1 as f64,
                        _ => illegal!(),
                    };
                    hart.fregs[rd] = r.to_bits();
                }
                0x70 => {
                    if rm == 0 {
                        wr!(sext((hart.fregs[rs1] as u32) as u64, 32));
                    } else {
                        wr!(fclass32(unbox_f32(hart.fregs[rs1])));
                    }
                }
                0x71 => {
                    if rm == 0 {
                        wr!(hart.fregs[rs1]);
                    } else {
                        wr!(fclass64(f64::from_bits(hart.fregs[rs1])));
                    }
                }
                0x78 => {
                    hart.fregs[rd] = 0xFFFF_FFFF_0000_0000 | (x1 & 0xFFFF_FFFF);
                }
                0x79 => {
                    hart.fregs[rd] = x1;
                }
                _ => illegal!(),
            }
            hart.pc += 4;
        }
        _ => illegal!(),
    }
    Ok(())
}
