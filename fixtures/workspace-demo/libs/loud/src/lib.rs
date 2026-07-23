#![no_std]

/// Uppercases ASCII letters (leaves everything else untouched) into `out`,
/// returning the used length. Only ever compiled/linked in when `app`'s
/// `loud` feature is active — proves the workspace scanner's feature
/// resolution actually gates which crates get built, not just which code
/// paths run.
pub fn shout(msg: &[u8], out: &mut [u8]) -> usize {
    for (i, &b) in msg.iter().enumerate() {
        out[i] = if b.is_ascii_lowercase() { b - 32 } else { b };
    }
    msg.len()
}
