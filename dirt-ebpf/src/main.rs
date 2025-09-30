#![no_std]
#![no_main]

use aya_ebpf::{macros::uprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[uprobe]
pub fn dirt(ctx: ProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: ProbeContext) -> Result<u32, u32> {
    let path_ptr: u64 = ctx.arg(0).ok_or(1u32)?;
    info!(&ctx, "shfs_unlink: path_ptr={:x}", path_ptr);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
