#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Doubles every element into a heap-allocated `Vec`, then sums it —
/// exercises `alloc` (heap allocation, iterator `collect`) from a plain
/// `no_std` lib crate; the binary just needs to supply a `#[global_allocator]`.
pub fn sum_doubled(nums: &[i32]) -> i32 {
    let doubled: Vec<i32> = nums.iter().map(|n| n * 2).collect();
    doubled.iter().sum()
}

/// Same computation, formatted through the real `itoa` crate fetched live
/// from crates.io — proves a genuine, unmodified `no_std` crates.io
/// dependency (not something vendored/local) gets fetched, compiled, and
/// linked correctly by the workspace scanner.
pub fn format_sum(nums: &[i32]) -> String {
    let sum = sum_doubled(nums);
    let mut buf = itoa::Buffer::new();
    alloc::format!("itoa: {}\n", buf.format(sum))
}
