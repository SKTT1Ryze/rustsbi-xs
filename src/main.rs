//! RustSBI Implementation for XiangShan Platform
#![no_std]
#![no_main]
#![feature(naked_functions)]
#![feature(alloc_error_handler)]
#![feature(llvm_asm)]
#![feature(asm)]
#![feature(global_asm)]

extern crate xs_hal;
extern crate embedded_hal;
extern crate nb;

#[cfg(not(test))]
use core::alloc::Layout;
use core::panic;
#[cfg(not(test))]
use core::panic::PanicInfo;
use buddy_system_allocator::LockedHeap;
use riscv::register::{
    mtval,
    mstatus::{self, MPP},
    mtvec::{self, TrapMode},
    mcause::{self, Exception, Interrupt, Trap},
    medeleg, mepc, mhartid, mideleg, mie, mip, misa::{self, MXL},
};
use rustsbi::{print, println};

struct Reset;
impl rustsbi::Reset for Reset {
    fn system_reset(&self, reset_type: usize, reset_reason: usize) -> rustsbi::SbiRet {
        println!("[rustsbi] reset triggered! todo: shutdown all harts on XS; program halt. Type: {}, reason: {}", reset_type, reset_reason);
        loop {}
    }
}

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

#[cfg(not(test))]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("[rustsbi-panic] {}", info);
    println!("[rustsbi-panic] system shutdown scheduled due to RustSBI panic");
    use rustsbi::Reset;
    Reset.system_reset(
        rustsbi::reset::RESET_TYPE_SHUTDOWN,
        rustsbi::reset::RESET_REASON_SYSTEM_FAILURE
    );
    loop {}
}

#[cfg(not(test))]
#[alloc_error_handler]
fn oom(_layout: Layout) -> ! {
    loop {}
}

pub extern "C" fn mp_hook() -> bool {
    let hartid = mhartid::read();
    if hartid == 0 {
        // hart 0, return true
        true
    } else {
        #[allow(unused_imports)]
        use riscv::asm::wfi;
        let clint = unsafe { xs_hal::Clint::new() };
        // Clear IPI
        clint.clear_soft(hartid);
        unsafe {
            // Start listening for software interrupts
            mie::set_msoft();
            loop {
                wfi();
                if mip::read().msoft() {
                    break;
                }
            }
            // Stop listening for software interrupts
            mie::clear_msoft();
        }
        clint.clear_soft(hartid);
        false
    }
}

#[export_name = "_start"]
#[link_section = ".init"]
#[naked]
unsafe extern "C" fn start() -> ! {
    // Ref: https://github.com/luojia65/rustsbi/blob/master/platform/qemu/src/main.rs
    asm!(
        "
    csrr    a2, mhartid
    lui     t0, %hi(_max_hart_id)
    add     t0, t0, %lo(_max_hart_id)
    bgtu    a2, t0, _start_abort
    la      sp, _stack_start
    lui     t0, %hi(_hart_stack_size)
    add     t0, t0, %lo(_hart_stack_size)
.ifdef __riscv_mul
    mul     t0, a2, t0
.else
    beqz    a2, 2f  // Jump if single-hart
    mv      t1, a2
    mv      t2, t0
1:
    add     t0, t0, t2
    addi    t1, t1, -1
    bnez    t1, 1b
2:
.endif
    sub     sp, sp, t0
    csrw    mscratch, zero
    j       _start_rust
    
_start_abort:
    wfi
    j _start_abort
", options(noreturn))
}

#[link_section = ".init.rust"]
#[export_name = "_start_rust"]
fn main() -> ! {
    // Ref: https://github.com/qemu/qemu/blob/aeb07b5f6e69ce93afea71027325e3e7a22d2149/hw/riscv/boot.c#L243
    // 设备树的物理地址，操作系统会从 `a1` 寄存器里面读取设备树
    let dtb_pa = unsafe {
        let dtb_pa: usize;
        llvm_asm!("":"={a1}"(dtb_pa));
        dtb_pa
    };

    if mp_hook() {
        // TODO: init
    }
    
    // setup tarp
    extern "C" {
        fn _start_trap();
    }
    unsafe {
        mtvec::write(_start_trap as usize, TrapMode::Direct);
    }

    extern "C" {
        static mut _sheap: u8;
        static _heap_size: u8;
    }

    if mhartid::read() == 0 {
        // init heap allocator
        let sheap = unsafe { &mut _sheap } as *mut _ as usize;
        let heap_size = unsafe { &_heap_size } as *const u8 as usize;
        unsafe {
            ALLOCATOR.lock().init(sheap, heap_size);
        }
        // print! and println! depend on the following step
        // Init Serial
        struct Serial;
        impl Serial {
            pub fn new() -> Self {
                Self
            }
        }
        impl embedded_hal::serial::Read<u8> for Serial {
            type Error = core::convert::Infallible;
            fn try_read(&mut self) -> nb::Result<u8, Self::Error> {
                let uart_lite = xs_hal::UartLite::new();
                uart_lite.try_read()
            }
        }

        impl embedded_hal::serial::Write<u8> for Serial {
            type Error = core::convert::Infallible;
            fn try_write(&mut self, word: u8) -> nb::Result<(), Self::Error> {
                let uart_lite = xs_hal::UartLite::new();
                uart_lite.try_write(word)
            }

            fn try_flush(&mut self) -> nb::Result<(), Self::Error> {
                let uart_lite = xs_hal::UartLite::new();
                uart_lite.try_flush()
            }
        }
        let serial = Serial::new();
        rustsbi::legacy_stdio::init_legacy_stdio_embedded_hal(serial);

        // Init IPI
        struct Ipi;
        impl rustsbi::Ipi for Ipi {
            fn max_hart_id(&self) -> usize {
                1
            }
            fn send_ipi_many(&mut self, hart_mask: rustsbi::HartMask) {
                
                for i in 0..=self.max_hart_id() {
                    if hart_mask.has_bit(i) {
                        let clint = unsafe { xs_hal::Clint::new() };
                        clint.send_soft(i);
                        clint.clear_soft(i);
                    }
                }
            }
        }
        rustsbi::init_ipi(Ipi);

        // Init Timer
        struct Timer;
        impl rustsbi::Timer for Timer {
            fn set_timer(&mut self, stime_value: u64) {
                // This func must clear the pending timer
                // interrupt bit as well
                let clint = unsafe{ xs_hal::Clint::new() };
                clint.set_timer(mhartid::read(), stime_value);
                unsafe { mip::clear_mtimer(); }
            }
        }
        rustsbi::init_timer(Timer);
        // Init Reset
        rustsbi::init_reset(Reset);
    }

    // set mideleg
    unsafe {
        mideleg::set_sext();
        mideleg::set_stimer();
        mideleg::set_ssoft();
        medeleg::set_instruction_misaligned();
        medeleg::set_breakpoint();
        medeleg::set_user_env_call();
        medeleg::set_instruction_page_fault();
        medeleg::set_load_page_fault();
        medeleg::set_store_page_fault();
        medeleg::set_instruction_fault();
        medeleg::set_load_fault();
        medeleg::set_store_fault();
        mie::set_mext();
        // do not set mie::set_mtimer
        mie::set_msoft();
    }

    if mhartid::read() == 0 {
        println!("[rustsbi] RustSBI version {}", rustsbi::VERSION);
        println!("{}", rustsbi::LOGO);
        println!("[rustsbi] Platform: XiangShan (Version {})", env!("CARGO_PKG_VERSION"));
        let isa = misa::read();
        if let Some(isa) = isa {
            let mxl_str = match isa.mxl() {
                MXL::XLEN32 => "RV32",
                MXL::XLEN64 => "RV64",
                MXL::XLEN128 => "RV128",
            };
            print!("[rustsbi] misa: {}", mxl_str);
            for ext in 'A'..='Z' {
                if isa.has_extension(ext) {
                    print!("{}", ext);
                }
            }
            println!("");
        }
        println!("[rustsbi] mideleg: {:#x}", mideleg::read().bits());
        println!("[rustsbi] medeleg: {:#x}", medeleg::read().bits());
        println!("[rustsbi] Kernel entry: 0x80020000");
        
    }

    unsafe {
        mepc::write(s_mode_start as usize);
        mstatus::set_mpp(MPP::Supervisor);
        rustsbi::enter_privileged(mhartid::read(), dtb_pa)
    }
}

// Ref: https://github.com/luojia65/rustsbi/blob/master/platform/qemu/src/main.rs
#[naked]
#[link_section = ".text"] // must add link section for all naked functions
unsafe extern "C" fn s_mode_start() -> ! {
    asm!("
1:  auipc ra, %pcrel_hi(1f)
    ld ra, %pcrel_lo(1b)(ra)
    jr ra
.align  3
1:  .dword 0x80020000
    ", options(noreturn))
}

// Ref: https://github.com/luojia65/rustsbi/blob/master/platform/qemu/src/main.rs
global_asm!(
    "
    .equ REGBYTES, 8
    .macro STORE reg, offset
        sd  \\reg, \\offset*REGBYTES(sp)
    .endm
    .macro LOAD reg, offset
        ld  \\reg, \\offset*REGBYTES(sp)
    .endm
    .section .text
    .global _start_trap
    .p2align 2
_start_trap:
    csrrw   sp, mscratch, sp
    bnez    sp, 1f
    /* from M level, load sp */
    csrrw   sp, mscratch, zero
1:
    addi    sp, sp, -16 * REGBYTES
    STORE   ra, 0
    STORE   t0, 1
    STORE   t1, 2
    STORE   t2, 3
    STORE   t3, 4
    STORE   t4, 5
    STORE   t5, 6
    STORE   t6, 7
    STORE   a0, 8
    STORE   a1, 9
    STORE   a2, 10
    STORE   a3, 11
    STORE   a4, 12
    STORE   a5, 13
    STORE   a6, 14
    STORE   a7, 15
    mv      a0, sp
    call    _start_trap_rust
    LOAD    ra, 0
    LOAD    t0, 1
    LOAD    t1, 2
    LOAD    t2, 3
    LOAD    t3, 4
    LOAD    t4, 5
    LOAD    t5, 6
    LOAD    t6, 7
    LOAD    a0, 8
    LOAD    a1, 9
    LOAD    a2, 10
    LOAD    a3, 11
    LOAD    a4, 12
    LOAD    a5, 13
    LOAD    a6, 14
    LOAD    a7, 15
    addi    sp, sp, 16 * REGBYTES
    csrrw   sp, mscratch, sp
    mret
    "
);

#[allow(unused)]
#[derive(Debug)]
struct TrapFrame {
    ra: usize,
    t0: usize,
    t1: usize,
    t2: usize,
    t3: usize,
    t4: usize,
    t5: usize,
    t6: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
}

#[link_section = ".trap.rust"]
#[export_name = "_start_trap_rust"]
extern "C" fn start_trap_rust(trapframe: &mut TrapFrame) {
    let cause = mcause::read().cause();
    match cause {
        Trap::Exception(Exception::SupervisorEnvCall) => {
            let params = [trapframe.a0, trapframe.a1, trapframe.a2, trapframe.a3];
            // Call RustSBI ecall handler
            let ans = rustsbi::ecall(trapframe.a7, trapframe.a6, params);
            // Write the return value to TrapFrame
            trapframe.a0 = ans.error;
            trapframe.a1 = ans.value;
            // Add `mepc` with 4 to skip ecall instruction
            mepc::write(mepc::read().wrapping_add(4));
        },
        Trap::Interrupt(Interrupt::MachineSoft) => {
            // Return the machine soft interrupt to S mode
            unsafe {
                // `mie` 负责中断使能
                // `mip` 列出当前正准备处理的中断
                // 设置 `mip` 的 `SSIP` 位和
                // 清除 `mie` 的 `MSIE` 位
                // 使得操作系统回到 S 态处理软件中断
                mip::set_ssoft();
                mie::clear_msoft();
            }
        }
        Trap::Interrupt(Interrupt::MachineTimer) => {
            // Return the machine timer interrupt to S mode
            unsafe {
                // 设置 `mip` 的 `STIP` 位和
                // 清除 `mie` 的 `MTIE` 位
                // 使得操作系统回到 S 态处理时钟中断
                mip::set_stimer();
                mie::clear_mtimer();
            }
        }
        Trap::Exception(Exception::IllegalInstruction) => {
            // 操作系统执行非法指令会陷入到这里
            #[inline]
            unsafe fn get_vaddr_u32(vaddr: usize) -> u32 {
                let mut ans: u32;
                llvm_asm!("
                    li      t0, (1 << 17)
                    mv      t1, $1
                    csrrs   t0, mstatus, t0
                    lwu     t1, 0(t1)
                    csrw    mstatus, t0
                    mv      $0, t1
                "
                    :"=r"(ans) 
                    :"r"(vaddr)
                    :"t0", "t1");
                ans
            }
            // Decode illegal instruction
            let va = mepc::read();
            let instr = unsafe { get_vaddr_u32(va) };
            if instr & 0xFFFFF07F == 0xC0102073 {
                // rdtime instruction
                let rd = ((instr >> 7) & 0b1_1111) as u8;
                let clint = unsafe { xs_hal::Clint::new() };
                let mtime = clint.get_mtime() as usize;
                match rd {
                    10 => trapframe.a0 = mtime,
                    11 => trapframe.a1 = mtime,
                    12 => trapframe.a2 = mtime,
                    13 => trapframe.a3 = mtime,
                    14 => trapframe.a4 = mtime,
                    15 => trapframe.a5 = mtime,
                    16 => trapframe.a6 = mtime,
                    17 => trapframe.a7 = mtime,
                    5 => trapframe.t0 = mtime,
                    6 => trapframe.t1 = mtime,
                    7 => trapframe.t2 = mtime,
                    28 => trapframe.t3 = mtime,
                    29 => trapframe.t4 = mtime,
                    30 => trapframe.t5 = mtime,
                    31 => trapframe.t6 = mtime,
                    _ => panic!("invalid target"),
                }
                // Skip instruction
                mepc::write(mepc::read().wrapping_add(4));
            }
        }
        unknown_cause => panic!(
            "Unhandled exception! mcause: {:?}, mepc: {:016x?}, mtval: {:016x?}, trapframe: {:p}, {:x?}",
            unknown_cause,
            mepc::read(),
            mtval::read(),
            &trapframe as *const _,
            trapframe
        )
    }
}