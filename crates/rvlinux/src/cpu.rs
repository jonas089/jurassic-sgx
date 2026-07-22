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
    pub fn new() -> Self {
        CodeCache {
            map: FxMap::default(),
            arena: Vec::new(),
            tlb: [(u64::MAX, 0); 64],
        }
    }

    pub fn clear(&mut self) {
        self.map.clear();
        self.arena.clear();
        self.tlb = [(u64::MAX, 0); 64];
    }

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

#[inline]
fn sext(v: u64, bits: u32) -> u64 {
    let shift = 64 - bits;
    (((v << shift) as i64) >> shift) as u64
}

// ---- decoding ----

/// Decode the instruction at `pc`. Returns None on fetch fault.
fn decode(mem: &mut Memory, pc: u64) -> Result<Decoded, MemFault> {
    let lo = u16::from_le_bytes(mem.load::<2>(pc)?);
    if lo & 3 != 3 {
        return Ok(decode_compressed(lo, pc));
    }
    let hi = u16::from_le_bytes(mem.load::<2>(pc + 2)?);
    let inst = (lo as u32) | ((hi as u32) << 16);
    Ok(decode32(inst, pc))
}

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

fn slow(word: u32) -> Decoded {
    dec(op::SLOW, 0, 0, 0, 4, word as u64)
}

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

#[inline]
fn unbox_f32(v: u64) -> f32 {
    if v >> 32 == 0xFFFF_FFFF {
        f32::from_bits(v as u32)
    } else {
        f32::from_bits(0x7FC0_0000)
    }
}
#[inline]
fn box_f32(f: f32) -> u64 {
    0xFFFF_FFFF_0000_0000 | f.to_bits() as u64
}

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

/// Run `hart` until budget exhausted or a trap. Returns (stop, executed).
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
            op::JAL => {
                wr!(pc + d.len as u64);
                hart.pc = imm;
            }
            op::JALR => {
                let target = x1.wrapping_add(imm) & !1;
                wr!(pc + d.len as u64);
                hart.pc = target;
            }
            op::LUI => {
                wr!(imm);
                hart.pc = pc + d.len as u64;
            }
            op::ADD => {
                wr!(x1.wrapping_add(x2));
                hart.pc = pc + d.len as u64;
            }
            op::SUB => {
                wr!(x1.wrapping_sub(x2));
                hart.pc = pc + d.len as u64;
            }
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
            op::NOP => {
                hart.pc = pc + d.len as u64;
            }
            op::ECALL => {
                hart.pc = pc + d.len as u64;
                return (Stop::Ecall, executed);
            }
            op::EBREAK => {
                return (Stop::Ebreak { pc }, executed);
            }
            op::SLOW => {
                let word = imm as u32;
                match exec_slow(hart, mem, word, executed) {
                    Ok(()) => {}
                    Err(stop) => return (stop, executed),
                }
            }
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

/// Execute a rare instruction from its raw 32-bit word. Advances pc.
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
        0x2F => {
            // AMO
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
        0x73 => {
            // CSR (ecall/ebreak handled in fast path)
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
        0x43 | 0x47 | 0x4B | 0x4F => {
            // FMADD family
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
