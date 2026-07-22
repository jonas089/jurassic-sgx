/// Wraps `msg` as `>> {msg} <<\n` into `out`, returning the used length.
pub fn decorate(msg: &[u8], out: &mut [u8]) -> usize {
    let prefix = b">> ";
    let suffix = b" <<\n";
    let mut n = 0;
    out[n..n + prefix.len()].copy_from_slice(prefix);
    n += prefix.len();
    out[n..n + msg.len()].copy_from_slice(msg);
    n += msg.len();
    out[n..n + suffix.len()].copy_from_slice(suffix);
    n += suffix.len();
    n
}
