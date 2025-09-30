#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    macros::{map, uprobe},
    maps::{PerCpuArray, RingBuf},
    programs::ProbeContext,
};

use dirt_common::{Event, EventType};

#[map]
static mut EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0); // 256 KB

#[map]
static mut SCRATCH: PerCpuArray<Event> = PerCpuArray::with_max_entries(1, 0);

#[uprobe]
pub fn dirt(ctx: ProbeContext) -> u32 {
    match try_dirt(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dirt(ctx: ProbeContext) -> Result<u32, u32> {
    let path_ptr: u64 = ctx.arg(0).ok_or(1u32)?;

    unsafe {
        // Get a mutable pointer to the scratch buffer.
        let event = (*(&raw mut SCRATCH)).get_ptr_mut(0).ok_or(1u32)?;

        // Write the event data.
        (*event).event = EventType::Unlink;
        (*event).tgt_path = [0; 4096]; // Zero out the target path.
        bpf_probe_read_user_str_bytes(
            path_ptr as *const u8,
            &mut (*event).src_path,
        )
        .map_err(|e| e as u32)?;

        // Send the event to the ring buffer.
        let _ = (*(&raw mut EVENTS)).output(&*event, 0);
    }

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