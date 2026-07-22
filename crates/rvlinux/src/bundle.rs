//! Minimal deterministic filesystem bundle format ("ZKFS1").
//!
//! Layout (all integers little-endian):
//!   magic  [u8; 8] = b"ZKFS1\0\0\0"
//!   count  u32
//!   entries (sorted by path):
//!     kind     u8   (0 = dir, 1 = file, 2 = symlink)
//!     mode     u32
//!     path_len u32, path bytes (utf-8, absolute, normalized)
//!     data_len u32, data bytes (file content / symlink target; 0 for dir)

use alloc::borrow::ToOwned;
use alloc::string::String;
use alloc::vec::Vec;

use crate::fs::Fs;

pub const MAGIC: &[u8; 8] = b"ZKFS1\0\0\0";

#[derive(Debug)]
pub enum BundleError {
    BadMagic,
    Truncated,
    BadPath,
}

pub fn parse_into(fs: &mut Fs, data: &[u8]) -> Result<u32, BundleError> {
    if data.len() < 12 || &data[..8] != MAGIC {
        return Err(BundleError::BadMagic);
    }
    let count = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let mut off = 12usize;
    let rd_u32 = |data: &[u8], off: &mut usize| -> Result<u32, BundleError> {
        if *off + 4 > data.len() {
            return Err(BundleError::Truncated);
        }
        let v = u32::from_le_bytes(data[*off..*off + 4].try_into().unwrap());
        *off += 4;
        Ok(v)
    };
    for _ in 0..count {
        if off + 1 > data.len() {
            return Err(BundleError::Truncated);
        }
        let kind = data[off];
        off += 1;
        let mode = rd_u32(data, &mut off)?;
        let plen = rd_u32(data, &mut off)? as usize;
        if off + plen > data.len() {
            return Err(BundleError::Truncated);
        }
        let path = core::str::from_utf8(&data[off..off + plen])
            .map_err(|_| BundleError::BadPath)?
            .to_owned();
        off += plen;
        let dlen = rd_u32(data, &mut off)? as usize;
        if off + dlen > data.len() {
            return Err(BundleError::Truncated);
        }
        let content = &data[off..off + dlen];
        off += dlen;
        match kind {
            0 => fs.mkdir_all(&path),
            1 => fs.add_file(&path, content.to_vec(), mode),
            2 => {
                let target =
                    core::str::from_utf8(content).map_err(|_| BundleError::BadPath)?;
                fs.add_symlink(&path, target);
            }
            _ => return Err(BundleError::BadPath),
        }
    }
    Ok(count)
}

/// Builder (host side).
pub struct Builder {
    entries: Vec<(String, u8, u32, Vec<u8>)>,
}

impl Builder {
    pub fn new() -> Self {
        Builder {
            entries: Vec::new(),
        }
    }
    pub fn dir(&mut self, path: &str) {
        self.entries.push((path.into(), 0, 0o755, Vec::new()));
    }
    pub fn file(&mut self, path: &str, data: Vec<u8>, mode: u32) {
        self.entries.push((path.into(), 1, mode, data));
    }
    pub fn symlink(&mut self, path: &str, target: &str) {
        self.entries
            .push((path.into(), 2, 0o777, target.as_bytes().to_vec()));
    }
    pub fn build(mut self) -> Vec<u8> {
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for (path, kind, mode, data) in &self.entries {
            out.push(*kind);
            out.extend_from_slice(&mode.to_le_bytes());
            out.extend_from_slice(&(path.len() as u32).to_le_bytes());
            out.extend_from_slice(path.as_bytes());
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            out.extend_from_slice(data);
        }
        out
    }
}
