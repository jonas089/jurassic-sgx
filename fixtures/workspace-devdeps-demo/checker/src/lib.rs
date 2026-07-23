#![no_std]

/// A stand-in for a test-helper crate you'd normally only want linked into
/// a dev/test build, never a production one — exactly the case
/// `[dev-dependencies]` exists for. Returns `true` if `a + b == expected`.
pub fn check_add(a: i32, b: i32, expected: i32) -> bool {
    a + b == expected
}
