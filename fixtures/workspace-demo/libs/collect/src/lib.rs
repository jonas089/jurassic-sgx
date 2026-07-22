#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// Doubles every element into a heap-allocated `Vec`, then sums it —
/// exercises `alloc` (heap allocation, iterator `collect`) from a plain
/// `no_std` lib crate; the binary just needs to supply a `#[global_allocator]`.
pub fn sum_doubled(nums: &[i32]) -> i32 {
    let doubled: Vec<i32> = nums.iter().map(|n| n * 2).collect();
    doubled.iter().sum()
}
