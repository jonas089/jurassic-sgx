#![no_std]

/// Pads `s` on the left with `pad` up to `width`, writing into `out` and
/// returning the used length. `out` must be at least `width.max(s.len())` long.
pub fn leftpad(s: &[u8], width: usize, pad: u8, out: &mut [u8]) -> usize {
    let pad_len = width.saturating_sub(s.len());
    for b in out.iter_mut().take(pad_len) {
        *b = pad;
    }
    let n = pad_len + s.len();
    out[pad_len..n].copy_from_slice(s);
    n
}
