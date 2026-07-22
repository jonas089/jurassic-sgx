//! ELF64 loading (static + PT_INTERP dynamic) and initial stack construction.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::mem::{align_up, Backing, Memory, PAGE_SIZE};

pub const EXE_BASE: u64 = 0x10_0000_0000;
pub const INTERP_BASE: u64 = 0x20_0000_0000;
pub const STACK_TOP: u64 = 0x3F_FFFF_F000;
pub const STACK_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum LoadError {
    BadElf(&'static str),
    NeedsInterp(String),
}

pub struct LoadedElf {
    pub entry: u64,
    pub phdr_addr: u64,
    pub phent: u64,
    pub phnum: u64,
    pub base: u64,
    /// PT_INTERP path if present.
    pub interp: Option<String>,
    pub load_end: u64,
}

fn rd16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn rd32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn rd64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

/// Map one ELF's PT_LOAD segments at `base` (0 for ET_EXEC).
pub fn load_elf(
    mem: &mut Memory,
    data: &Arc<Vec<u8>>,
    base_hint: u64,
) -> Result<LoadedElf, LoadError> {
    let b: &[u8] = data;
    if b.len() < 64 || &b[..4] != b"\x7fELF" {
        return Err(LoadError::BadElf("magic"));
    }
    if b[4] != 2 || b[5] != 1 {
        return Err(LoadError::BadElf("not ELF64 LE"));
    }
    let e_type = rd16(b, 16);
    let e_machine = rd16(b, 18);
    if e_machine != 243 {
        return Err(LoadError::BadElf("not RISC-V"));
    }
    let e_entry = rd64(b, 24);
    let e_phoff = rd64(b, 32);
    let e_phentsize = rd16(b, 54) as u64;
    let e_phnum = rd16(b, 56) as u64;

    let base = if e_type == 3 { base_hint } else { 0 };

    let mut interp = None;
    let mut phdr_vaddr: Option<u64> = None;
    let mut load_end = 0u64;

    for i in 0..e_phnum {
        let off = (e_phoff + i * e_phentsize) as usize;
        if off + 56 > b.len() {
            return Err(LoadError::BadElf("phdr out of range"));
        }
        let p_type = rd32(b, off);
        let p_offset = rd64(b, off + 8);
        let p_vaddr = rd64(b, off + 16);
        let p_filesz = rd64(b, off + 32);
        let p_memsz = rd64(b, off + 40);
        match p_type {
            3 => {
                // PT_INTERP
                let s = &b[p_offset as usize..(p_offset + p_filesz) as usize];
                let s = s.split(|&c| c == 0).next().unwrap_or(&[]);
                interp = Some(String::from_utf8_lossy(s).into_owned());
            }
            6 => {
                // PT_PHDR
                phdr_vaddr = Some(p_vaddr);
            }
            1 => {
                // PT_LOAD
                let vstart = base + p_vaddr;
                let file_end = vstart + p_filesz;
                let mem_end = vstart + p_memsz;
                if p_filesz > 0 {
                    let map_start = vstart & !(PAGE_SIZE - 1);
                    let back_off = p_offset & !(PAGE_SIZE - 1);
                    mem.map(
                        map_start,
                        align_up(file_end) - map_start,
                        7,
                        Backing::File {
                            data: data.clone(),
                            offset: back_off,
                        },
                    );
                    // Zero the tail of the last file page (bss overlap).
                    let tail = align_up(file_end) - file_end;
                    if tail > 0 {
                        let zeros = alloc::vec![0u8; tail as usize];
                        mem.write_bytes(file_end, &zeros).map_err(|_| LoadError::BadElf("tail"))?;
                    }
                }
                if align_up(mem_end) > align_up(file_end) {
                    mem.map(
                        align_up(file_end),
                        align_up(mem_end) - align_up(file_end),
                        7,
                        Backing::Zero,
                    );
                }
                load_end = core::cmp::max(load_end, align_up(mem_end));
            }
            _ => {}
        }
    }

    // Compute AT_PHDR: prefer PT_PHDR, else base + phoff (valid when the
    // first page (containing the ELF header + phdrs) is loaded, the norm).
    let phdr_addr = base + phdr_vaddr.unwrap_or(e_phoff);

    Ok(LoadedElf {
        entry: base + e_entry,
        phdr_addr,
        phent: e_phentsize,
        phnum: e_phnum,
        base,
        interp,
        load_end,
    })
}

pub struct StartInfo {
    pub pc: u64,
    pub sp: u64,
    pub brk_base: u64,
}

/// Load exe (+ its interpreter if dynamic), build the initial stack.
/// `lookup` resolves an absolute path to file bytes (for the interpreter).
pub fn setup_process(
    mem: &mut Memory,
    exe_data: Arc<Vec<u8>>,
    exe_path: &str,
    argv: &[String],
    envp: &[String],
    lookup: &mut dyn FnMut(&str) -> Option<Arc<Vec<u8>>>,
) -> Result<StartInfo, LoadError> {
    let exe = load_elf(mem, &exe_data, EXE_BASE)?;
    let (entry_pc, at_base) = if let Some(ipath) = &exe.interp {
        let idata = lookup(ipath).ok_or(LoadError::NeedsInterp(ipath.clone()))?;
        let interp = load_elf(mem, &idata, INTERP_BASE)?;
        (interp.entry, interp.base)
    } else {
        (exe.entry, 0)
    };

    // Stack.
    mem.map(STACK_TOP - STACK_SIZE, STACK_SIZE, 7, Backing::Zero);

    // Strings at top of the stack.
    let mut cursor = STACK_TOP;
    let push_bytes = |mem: &mut Memory, cursor: &mut u64, bytes: &[u8]| -> u64 {
        *cursor -= bytes.len() as u64;
        mem.write_bytes(*cursor, bytes).unwrap();
        *cursor
    };

    let platform_ptr = push_bytes(mem, &mut cursor, b"riscv64\0");
    let mut execfn = Vec::from(exe_path.as_bytes());
    execfn.push(0);
    let execfn_ptr = push_bytes(mem, &mut cursor, &execfn);
    // 16 deterministic "random" bytes for AT_RANDOM.
    let random_ptr = push_bytes(
        mem,
        &mut cursor,
        &[
            0x5a, 0x6b, 0x56, 0x4d, 0x2d, 0x72, 0x75, 0x73, 0x74, 0x63, 0x2d, 0x70, 0x6f, 0x63,
            0x21, 0x21,
        ],
    );

    let mut argv_ptrs = Vec::new();
    for a in argv {
        let mut v = Vec::from(a.as_bytes());
        v.push(0);
        argv_ptrs.push(push_bytes(mem, &mut cursor, &v));
    }
    let mut env_ptrs = Vec::new();
    for e in envp {
        let mut v = Vec::from(e.as_bytes());
        v.push(0);
        env_ptrs.push(push_bytes(mem, &mut cursor, &v));
    }

    // auxv
    let auxv: Vec<(u64, u64)> = alloc::vec![
        (3, exe.phdr_addr),           // AT_PHDR
        (4, exe.phent),               // AT_PHENT
        (5, exe.phnum),               // AT_PHNUM
        (6, PAGE_SIZE),               // AT_PAGESZ
        (7, at_base),                 // AT_BASE
        (8, 0),                       // AT_FLAGS
        (9, exe.entry),               // AT_ENTRY
        (11, 0),                      // AT_UID
        (12, 0),                      // AT_EUID
        (13, 0),                      // AT_GID
        (14, 0),                      // AT_EGID
        (15, platform_ptr),           // AT_PLATFORM
        (16, 0x112d),                 // AT_HWCAP (imafdc)
        (17, 100),                    // AT_CLKTCK
        (23, 0),                      // AT_SECURE
        (25, random_ptr),             // AT_RANDOM
        (31, execfn_ptr),             // AT_EXECFN
        (0, 0),                       // AT_NULL
    ];

    // Compute total pointer-area size to keep sp 16-byte aligned.
    let n_ptr_words = 1 + (argv_ptrs.len() + 1) + (env_ptrs.len() + 1) + auxv.len() * 2;
    cursor &= !15;
    if n_ptr_words % 2 == 1 {
        cursor -= 8;
    }
    let mut sp = cursor - (n_ptr_words as u64) * 8;
    debug_assert_eq!(sp % 16, 0);

    let mut w = sp;
    mem.sd(w, argv_ptrs.len() as u64).unwrap(); // argc
    w += 8;
    for p in &argv_ptrs {
        mem.sd(w, *p).unwrap();
        w += 8;
    }
    mem.sd(w, 0).unwrap();
    w += 8;
    for p in &env_ptrs {
        mem.sd(w, *p).unwrap();
        w += 8;
    }
    mem.sd(w, 0).unwrap();
    w += 8;
    for (k, v) in &auxv {
        mem.sd(w, *k).unwrap();
        w += 8;
        mem.sd(w, *v).unwrap();
        w += 8;
    }

    sp &= !15;
    let _ = &mut sp;

    // brk starts after the exe image.
    let brk_base = align_up(exe.load_end) + PAGE_SIZE;

    Ok(StartInfo {
        pc: entry_pc,
        sp,
        brk_base,
    })
}
