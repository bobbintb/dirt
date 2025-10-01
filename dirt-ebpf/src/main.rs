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
pub fn uprobe_unlink(ctx: ProbeContext) -> u32 {
    match try_uprobe_unlink(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_unlink(ctx: ProbeContext) -> Result<u32, u32> {
    let path_ptr: u64 = ctx.arg(0).ok_or(1u32)?;

    unsafe {
        let event = (*(&raw mut SCRATCH)).get_ptr_mut(0).ok_or(1u32)?;

        (*event).event = EventType::Unlink;

        bpf_probe_read_user_str_bytes(path_ptr as *const u8, &mut (*event).src_path)
            .map_err(|e| e as u32)?;

        let _ = (*(&raw mut EVENTS)).output(&*event, 0);
    }

    Ok(0)
}

#[uprobe]
pub fn uprobe_create(ctx: ProbeContext) -> u32 {
    match try_uprobe_create(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_create(ctx: ProbeContext) -> Result<u32, u32> {
    let path_ptr: u64 = ctx.arg(0).ok_or(1u32)?;

    unsafe {
        let event = (*(&raw mut SCRATCH)).get_ptr_mut(0).ok_or(1u32)?;

        (*event).event = EventType::Create;

        bpf_probe_read_user_str_bytes(path_ptr as *const u8, &mut (*event).src_path)
            .map_err(|e| e as u32)?;

        let _ = (*(&raw mut EVENTS)).output(&*event, 0);
    }

    Ok(0)
}

#[uprobe]
pub fn uprobe_rename(ctx: ProbeContext) -> u32 {
    match try_uprobe_rename(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_uprobe_rename(ctx: ProbeContext) -> Result<u32, u32> {
    let src_path_ptr: u64 = ctx.arg(0).ok_or(1u32)?;
    let tgt_path_ptr: u64 = ctx.arg(1).ok_or(1u32)?;

    unsafe {
        let event = (*(&raw mut SCRATCH)).get_ptr_mut(0).ok_or(1u32)?;

        (*event).event = EventType::Rename;

        bpf_probe_read_user_str_bytes(src_path_ptr as *const u8, &mut (*event).src_path)
            .map_err(|e| e as u32)?;

        bpf_probe_read_user_str_bytes(tgt_path_ptr as *const u8, &mut (*event).tgt_path)
            .map_err(|e| e as u32)?;

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
