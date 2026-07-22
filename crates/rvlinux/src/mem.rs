//! Sparse paged memory with VMA tracking and lazy materialization.
//!
//! All guest addresses are kept below 1<<38 (sv39 userspace) by the loader and
//! the mmap allocator; the memory model itself is agnostic.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

use crate::FxMap;

pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SHIFT: u32 = 12;

pub type Page = Box<[u8; PAGE_SIZE as usize]>;

#[derive(Clone)]
pub enum Backing {
    Zero,
    /// File contents + offset into it corresponding to VMA start.
    File { data: Arc<Vec<u8>>, offset: u64 },
}

#[derive(Clone)]
pub struct Vma {
    pub end: u64, // exclusive
    pub prot: u32,
    pub backing: Backing,
}

const TLB_SIZE: usize = 256;

pub struct Memory {
    /// page index -> arena slot
    pages: FxMap<u64, u32>,
    arena: Vec<Option<Page>>,
    free_slots: Vec<u32>,
    /// VMAs keyed by start address.
    pub vmas: BTreeMap<u64, Vma>,
    /// direct-mapped TLB: (page_idx, arena slot)
    tlb: [(u64, u32); TLB_SIZE],
    pub brk_base: u64,
    pub brk: u64,
    pub mmap_cursor: u64,
    /// Total pages materialized (peak tracking).
    pub pages_touched: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemFault(pub u64);

impl Memory {
    pub fn new() -> Self {
        Memory {
            pages: FxMap::default(),
            arena: Vec::new(),
            free_slots: Vec::new(),
            vmas: BTreeMap::new(),
            tlb: [(u64::MAX, 0); TLB_SIZE],
            brk_base: 0,
            brk: 0,
            mmap_cursor: 0x28_0000_0000,
            pages_touched: 0,
        }
    }

    #[inline]
    fn tlb_idx(page: u64) -> usize {
        (page as usize) & (TLB_SIZE - 1)
    }

    /// Look up (or materialize) the page containing `addr`. Returns arena slot.
    #[inline]
    fn slot_for(&mut self, addr: u64) -> Result<u32, MemFault> {
        let page = addr >> PAGE_SHIFT;
        let (tag, slot) = self.tlb[Self::tlb_idx(page)];
        if tag == page {
            return Ok(slot);
        }
        self.slot_slow(addr, page)
    }

    #[inline(never)]
    fn slot_slow(&mut self, addr: u64, page: u64) -> Result<u32, MemFault> {
        if let Some(&slot) = self.pages.get(&page) {
            self.tlb[Self::tlb_idx(page)] = (page, slot);
            return Ok(slot);
        }
        // Fault: consult VMAs.
        let page_base = page << PAGE_SHIFT;
        let vma = match self.vmas.range(..=page_base).next_back() {
            Some((&start, v)) if page_base < v.end => (start, v.clone()),
            _ => return Err(MemFault(addr)),
        };
        let mut p: Page = Box::new([0u8; PAGE_SIZE as usize]);
        if let Backing::File { data, offset } = &vma.1.backing {
            let file_off = offset + (page_base - vma.0);
            if file_off < data.len() as u64 {
                let n = core::cmp::min(PAGE_SIZE, data.len() as u64 - file_off) as usize;
                p[..n].copy_from_slice(&data[file_off as usize..file_off as usize + n]);
            }
        }
        let slot = match self.free_slots.pop() {
            Some(s) => {
                self.arena[s as usize] = Some(p);
                s
            }
            None => {
                self.arena.push(Some(p));
                (self.arena.len() - 1) as u32
            }
        };
        self.pages.insert(page, slot);
        self.pages_touched = core::cmp::max(self.pages_touched, self.pages.len() as u64);
        self.tlb[Self::tlb_idx(page)] = (page, slot);
        Ok(slot)
    }

    #[inline]
    fn page_bytes(&mut self, addr: u64) -> Result<(&mut [u8; PAGE_SIZE as usize], usize), MemFault> {
        let slot = self.slot_for(addr)?;
        let off = (addr & (PAGE_SIZE - 1)) as usize;
        Ok((self.arena[slot as usize].as_mut().unwrap(), off))
    }

    // ---- typed accessors (little endian) ----

    #[inline]
    pub fn load<const N: usize>(&mut self, addr: u64) -> Result<[u8; N], MemFault> {
        let off = (addr & (PAGE_SIZE - 1)) as usize;
        if off + N <= PAGE_SIZE as usize {
            let (p, o) = self.page_bytes(addr)?;
            let mut out = [0u8; N];
            out.copy_from_slice(&p[o..o + N]);
            Ok(out)
        } else {
            let mut out = [0u8; N];
            for i in 0..N {
                let (p, o) = self.page_bytes(addr + i as u64)?;
                out[i] = p[o];
            }
            Ok(out)
        }
    }

    #[inline]
    pub fn store<const N: usize>(&mut self, addr: u64, val: [u8; N]) -> Result<(), MemFault> {
        let off = (addr & (PAGE_SIZE - 1)) as usize;
        if off + N <= PAGE_SIZE as usize {
            let (p, o) = self.page_bytes(addr)?;
            p[o..o + N].copy_from_slice(&val);
            Ok(())
        } else {
            for i in 0..N {
                let (p, o) = self.page_bytes(addr + i as u64)?;
                p[o] = val[i];
            }
            Ok(())
        }
    }

    #[inline]
    pub fn lb(&mut self, a: u64) -> Result<i64, MemFault> { Ok(self.load::<1>(a)?[0] as i8 as i64) }
    #[inline]
    pub fn lbu(&mut self, a: u64) -> Result<u64, MemFault> { Ok(self.load::<1>(a)?[0] as u64) }
    #[inline]
    pub fn lh(&mut self, a: u64) -> Result<i64, MemFault> { Ok(i16::from_le_bytes(self.load::<2>(a)?) as i64) }
    #[inline]
    pub fn lhu(&mut self, a: u64) -> Result<u64, MemFault> { Ok(u16::from_le_bytes(self.load::<2>(a)?) as u64) }
    #[inline]
    pub fn lw(&mut self, a: u64) -> Result<i64, MemFault> { Ok(i32::from_le_bytes(self.load::<4>(a)?) as i64) }
    #[inline]
    pub fn lwu(&mut self, a: u64) -> Result<u64, MemFault> { Ok(u32::from_le_bytes(self.load::<4>(a)?) as u64) }
    #[inline]
    pub fn ld(&mut self, a: u64) -> Result<u64, MemFault> { Ok(u64::from_le_bytes(self.load::<8>(a)?)) }
    #[inline]
    pub fn sb(&mut self, a: u64, v: u8) -> Result<(), MemFault> { self.store::<1>(a, [v]) }
    #[inline]
    pub fn sh(&mut self, a: u64, v: u16) -> Result<(), MemFault> { self.store::<2>(a, v.to_le_bytes()) }
    #[inline]
    pub fn sw(&mut self, a: u64, v: u32) -> Result<(), MemFault> { self.store::<4>(a, v.to_le_bytes()) }
    #[inline]
    pub fn sd(&mut self, a: u64, v: u64) -> Result<(), MemFault> { self.store::<8>(a, v.to_le_bytes()) }

    /// Fetch 16 bits for instruction decode.
    #[inline]
    pub fn fetch16(&mut self, a: u64) -> Result<u16, MemFault> {
        Ok(u16::from_le_bytes(self.load::<2>(a)?))
    }

    // ---- bulk helpers ----

    pub fn read_bytes(&mut self, addr: u64, len: usize) -> Result<Vec<u8>, MemFault> {
        let mut out = Vec::with_capacity(len);
        let mut a = addr;
        let mut remaining = len;
        while remaining > 0 {
            let (p, o) = self.page_bytes(a)?;
            let n = core::cmp::min(PAGE_SIZE as usize - o, remaining);
            out.extend_from_slice(&p[o..o + n]);
            a += n as u64;
            remaining -= n;
        }
        Ok(out)
    }

    pub fn write_bytes(&mut self, addr: u64, data: &[u8]) -> Result<(), MemFault> {
        let mut a = addr;
        let mut src = data;
        while !src.is_empty() {
            let (p, o) = self.page_bytes(a)?;
            let n = core::cmp::min(PAGE_SIZE as usize - o, src.len());
            p[o..o + n].copy_from_slice(&src[..n]);
            a += n as u64;
            src = &src[n..];
        }
        Ok(())
    }

    /// Read a NUL-terminated C string (bounded).
    pub fn read_cstr(&mut self, addr: u64, max: usize) -> Result<Vec<u8>, MemFault> {
        let mut out = Vec::new();
        let mut a = addr;
        loop {
            let (p, o) = self.page_bytes(a)?;
            for i in o..PAGE_SIZE as usize {
                if p[i] == 0 {
                    return Ok(out);
                }
                out.push(p[i]);
                if out.len() >= max {
                    return Ok(out);
                }
            }
            a = (a & !(PAGE_SIZE - 1)) + PAGE_SIZE;
        }
    }

    // ---- mapping management ----

    fn drop_pages(&mut self, start: u64, end: u64) {
        let first = start >> PAGE_SHIFT;
        let last = (end + PAGE_SIZE - 1) >> PAGE_SHIFT;
        // Collect to avoid borrow issues; ranges are small in practice except
        // giant unmaps, which are rare.
        let keys: Vec<u64> = self
            .pages
            .keys()
            .filter(|&&p| p >= first && p < last)
            .copied()
            .collect();
        for p in keys {
            if let Some(slot) = self.pages.remove(&p) {
                self.arena[slot as usize] = None;
                self.free_slots.push(slot);
            }
            self.tlb[Self::tlb_idx(p)] = (u64::MAX, 0);
        }
    }

    /// Remove/split VMAs overlapping [start, end).
    fn carve(&mut self, start: u64, end: u64) {
        let mut to_add: Vec<(u64, Vma)> = Vec::new();
        let mut to_remove: Vec<u64> = Vec::new();
        let overlapping: Vec<(u64, Vma)> = self
            .vmas
            .range(..end)
            .filter(|(_, v)| v.end > start)
            .map(|(&s, v)| (s, v.clone()))
            .collect();
        for (s, v) in overlapping {
            if v.end <= start || s >= end {
                continue;
            }
            to_remove.push(s);
            if s < start {
                // left piece
                let mut left = v.clone();
                left.end = start;
                to_add.push((s, left));
            }
            if v.end > end {
                // right piece
                let mut right = v.clone();
                if let Backing::File { data, offset } = &v.backing {
                    right.backing = Backing::File {
                        data: data.clone(),
                        offset: offset + (end - s),
                    };
                }
                right.end = v.end;
                to_add.push((end, right));
            }
        }
        for s in to_remove {
            self.vmas.remove(&s);
        }
        for (s, v) in to_add {
            self.vmas.insert(s, v);
        }
    }

    pub fn map(&mut self, start: u64, len: u64, prot: u32, backing: Backing) {
        let end = align_up(start + len);
        let start = start & !(PAGE_SIZE - 1);
        self.carve(start, end);
        self.drop_pages(start, end);
        self.vmas.insert(start, Vma { end, prot, backing });
    }

    pub fn unmap(&mut self, start: u64, len: u64) {
        let end = align_up(start + len);
        let start = start & !(PAGE_SIZE - 1);
        self.carve(start, end);
        self.drop_pages(start, end);
    }

    pub fn protect(&mut self, start: u64, len: u64, prot: u32) {
        let end = align_up(start + len);
        let start = start & !(PAGE_SIZE - 1);
        // Split VMAs at boundaries, then set prot on covered ones.
        self.split_at(start);
        self.split_at(end);
        let keys: Vec<u64> = self
            .vmas
            .range(start..end)
            .map(|(&s, _)| s)
            .collect();
        for s in keys {
            if let Some(v) = self.vmas.get_mut(&s) {
                v.prot = prot;
            }
        }
    }

    fn split_at(&mut self, addr: u64) {
        let (s, v) = match self.vmas.range(..addr).next_back() {
            Some((&s, v)) if addr < v.end => (s, v.clone()),
            _ => return,
        };
        if s == addr {
            return;
        }
        let mut left = v.clone();
        left.end = addr;
        let mut right = v.clone();
        if let Backing::File { data, offset } = &v.backing {
            right.backing = Backing::File {
                data: data.clone(),
                offset: offset + (addr - s),
            };
        }
        right.end = v.end;
        self.vmas.insert(s, left);
        self.vmas.insert(addr, right);
    }

    /// Discard page contents in range (MADV_DONTNEED semantics: anon reads
    /// back zero, file-private reverts to the file).
    pub fn discard(&mut self, start: u64, len: u64) {
        self.drop_pages(start & !(PAGE_SIZE - 1), align_up(start + len));
    }

    pub fn alloc_mmap(&mut self, len: u64) -> u64 {
        let addr = self.mmap_cursor;
        self.mmap_cursor = align_up(self.mmap_cursor + len) + PAGE_SIZE; // guard gap
        addr
    }

    pub fn is_mapped(&self, addr: u64) -> bool {
        matches!(self.vmas.range(..=addr).next_back(), Some((_, v)) if addr < v.end)
    }

    /// Does [start, start+len) overlap any file-backed VMA? (Used to decide
    /// whether unmapping can invalidate cached decoded code.)
    pub fn overlaps_file(&self, start: u64, len: u64) -> bool {
        let end = align_up(start.saturating_add(len));
        self.vmas
            .range(..end)
            .rev()
            .take_while(|(_, v)| v.end > start)
            .any(|(_, v)| matches!(v.backing, Backing::File { .. }))
    }
}

#[inline]
pub fn align_up(v: u64) -> u64 {
    (v + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}
