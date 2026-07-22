//! Minimal no_std hello world for riscv64-linux.
//! Compiled by the real rustc *inside* the SP1 zkVM.

#![no_std]
#![no_main]

use core::arch::asm;

const MSG: &[u8] = b"Hello, zkVM-verified world!\n";

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    unsafe {
        // write(fd=1, buf, len)
        asm!(
            "ecall",
            in("a7") 64usize,
            inlateout("a0") 1usize => _,
            in("a1") MSG.as_ptr(),
            in("a2") MSG.len(),
        );
        // exit_group(0)
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
