#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, uprobe},
    maps::PerCpuArray,
    programs::ProbeContext,
};
use aya_log_ebpf::info;

#[map]
static mut BUF: PerCpuArray<[u8; 4096]> = PerCpuArray::with_max_entries(1, 0);

#[uprobe]
pub fn dirt(ctx: ProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: ProbeContext) -> Result<u32, u32> {
    let path_ptr: u64 = ctx.arg(0).ok_or(1u32)?;

    let ptr = unsafe { (*(&raw mut BUF)).get_ptr_mut(0) }.ok_or(1u32)?;
    let buf = unsafe { &mut *ptr };

    let path_bytes = unsafe {
        match bpf_probe_read_user_str_bytes(path_ptr as *const u8, buf) {
            Ok(path) => path,
            Err(e) => {
                info!(&ctx, "error reading path: {}", e);
                return Err(1);
            }
        }
    };
    let path = unsafe { core::str::from_utf8_unchecked(path_bytes) };
    info!(&ctx, "shfs_unlink: path={}", path);
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
