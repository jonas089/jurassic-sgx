//! Dev-dependencies demo: `checker` is declared under [dev-dependencies]
//! in Cargo.toml, not [dependencies]. It's only available as an --extern
//! (and thus this crate only compiles at all) when `compile-workspace-attest`
//! / `debug-emu-workspace` is run with `--dev` — there's no test harness or
//! separate build mode here, this bin crate's own `_start` *is* the test,
//! and the attested run's stdout is the result.
#![no_std]
#![no_main]

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
    let ok = checker::check_add(2, 2, 4);
    write(if ok { b"PASS\n" } else { b"FAIL\n" });

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
