//! Multi-crate no_std workspace demo: app -> greet -> leftpad (+ a `mod`
//! split inside greet), and app -> collect (heap: Vec + alloc::format!),
//! all compiled and linked inside the enclave from Cargo.toml-driven path
//! dependencies, with app supplying its own global allocator. `app`'s
//! `loud` feature (off by default) additionally activates the optional
//! `loud` crate — proves the workspace scanner's Cargo `[features]`
//! resolution actually gates which crates get compiled/linked, not just
//! which `#[cfg(feature = ...)]` branches run.
#![no_std]
#![no_main]

extern crate alloc;

use core::arch::asm;

fn write(buf: &[u8]) {
    unsafe {
        asm!(
            "ecall",
            in("a7") 64usize,
            inlateout("a0") 1usize => _,
            in("a1") buf.as_ptr(),
            in("a2") buf.len(),
        );
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut buf = [0u8; 64];
    let n = greet::greeting(b"world", &mut buf);
    write(&buf[..n]);

    let sum = collect::sum_doubled(&[1, 2, 3, 4, 5]);
    let msg = alloc::format!("heap sum = {}\n", sum);
    write(msg.as_bytes());
    write(collect::format_sum(&[1, 2, 3, 4, 5]).as_bytes());

    #[cfg(feature = "loud")]
    {
        let mut shout_buf = [0u8; 16];
        let n = loud::shout(b"quiet\n", &mut shout_buf);
        write(&shout_buf[..n]);
    }

    unsafe {
        asm!(
            "ecall",
            in("a7") 94usize,
            in("a0") 0usize,
            options(noreturn),
        );
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

// A no_std binary must supply its own heap: a fixed-size arena + bump
// pointer is the simplest allocator that needs no OS support (no mmap/brk
// syscall emulation required). Never reclaims memory — fine for a short-
// lived enclave computation like this one.
mod bump_alloc {
    use core::alloc::{GlobalAlloc, Layout};
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicUsize, Ordering};

    const HEAP_SIZE: usize = 64 * 1024;

    #[repr(align(16))]
    struct Heap(UnsafeCell<[u8; HEAP_SIZE]>);
    unsafe impl Sync for Heap {}

    static HEAP: Heap = Heap(UnsafeCell::new([0; HEAP_SIZE]));
    static OFFSET: AtomicUsize = AtomicUsize::new(0);

    pub struct BumpAlloc;

    unsafe impl GlobalAlloc for BumpAlloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let base = HEAP.0.get() as usize;
            loop {
                let cur = OFFSET.load(Ordering::Relaxed);
                let start = (base + cur).next_multiple_of(layout.align());
                let next = start - base + layout.size();
                if next > HEAP_SIZE {
                    return core::ptr::null_mut();
                }
                if OFFSET
                    .compare_exchange(cur, next, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return start as *mut u8;
                }
            }
        }
        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }
}

#[global_allocator]
static ALLOCATOR: bump_alloc::BumpAlloc = bump_alloc::BumpAlloc;

// `#[global_allocator]` gives us the `__rust_alloc`/`__rust_dealloc`/etc
// trampolines automatically (ordinary per-crate codegen), but a few pieces
// of `alloc`'s cold-path plumbing are normally generated only when *rustc
// itself* drives the final link (which we can't do here — no `execve`, see
// `compilation_rustc::pipeline`'s doc comment, so `rustc --emit=obj` + a manual
// `rust-lld` stage never gets them). Supply them by hand instead. The names
// below are the *real*, v0-mangled linker symbols — `__rustc::__rust_...`
// (as shown in link errors) is lld's demangled display of them, not a
// literal symbol you can `export_name` to; found via
// `ar x liballoc-*.rlib ...cgu.0.rcgu.o && nm -u` on the pinned toolchain's
// own liballoc, so these are specific to that exact build.
//
// This one is declared `unsafe extern "Rust" fn` upstream and genuinely
// *called* (not just referenced) from every allocating call site — it must
// be a real (empty) function, not a data symbol, or the call jumps into
// whatever bytes happen to sit at that address and executes them as code.
#[unsafe(export_name = "_RNvCs4SDFJOLwvtW_7___rustc35___rust_no_alloc_shim_is_unstable_v2")]
extern "Rust" fn alloc_shim_is_unstable() {}

// The OOM hook `alloc::alloc::handle_alloc_error` calls into; our bump
// allocator never really runs out this small a heap, but the symbol must
// still resolve. size/align args intentionally unused.
#[unsafe(export_name = "_RNvCs4SDFJOLwvtW_7___rustc26___rust_alloc_error_handler")]
extern "C" fn alloc_error_handler(_size: usize, _align: usize) -> ! {
    loop {}
}

// Same `panic=abort`-vs-prebuilt-unwind-tables mismatch as `rust_eh_personality`
// above, this time reached via `alloc::fmt::format`'s (unreachable, since we
// never unwind) error path.
#[unsafe(no_mangle)]
pub extern "C" fn _Unwind_Resume() -> ! {
    loop {}
}

// The prebuilt sysroot `core` was compiled with unwind tables regardless of
// our `panic=abort`, so it references a personality function even though
// it's never actually called here; and `compiler_builtins` here assumes libc
// provides memcpy/memset (this target is `-linux-gnu`), but we link
// `-static` against only a bundled libc.so (no libc.a). Bare-metal `no_std`
// binaries routinely supply both themselves for exactly this reason.
#[unsafe(no_mangle)]
pub extern "C" fn rust_eh_personality() {}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        unsafe { *dest.add(i) = *src.add(i) };
        i += 1;
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if (dest as usize) < (src as usize) {
        let mut i = 0;
        while i < n {
            unsafe { *dest.add(i) = *src.add(i) };
            i += 1;
        }
    } else {
        let mut i = n;
        while i > 0 {
            i -= 1;
            unsafe { *dest.add(i) = *src.add(i) };
        }
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        unsafe { *dest.add(i) = c as u8 };
        i += 1;
    }
    dest
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    let mut i = 0;
    while i < n {
        let (x, y) = unsafe { (*a.add(i), *b.add(i)) };
        if x != y {
            return x as i32 - y as i32;
        }
        i += 1;
    }
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    unsafe { memcmp(a, b, n) }
}
