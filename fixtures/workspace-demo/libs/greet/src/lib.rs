#![no_std]

mod style;

use style::decorate;

/// Builds a greeting for `name` (left-padded to a fixed width via the
/// `leftpad` path-dependency, then decorated by the local `style` module),
/// writing into `out` and returning the used length.
pub fn greeting(name: &[u8], out: &mut [u8]) -> usize {
    let mut padded = [0u8; 32];
    let n = leftpad::leftpad(name, 16, b' ', &mut padded);
    decorate(&padded[..n], out)
}
