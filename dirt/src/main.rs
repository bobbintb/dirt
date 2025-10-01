use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::UProbe,
    Ebpf,
};
use clap::Parser;
use dirt_common::{Event, EventType};
#[rustfmt::skip]
use log::{debug, info, warn};
use serde::Serialize;
use tokio::{io::unix::AsyncFd, signal, task};

mod error;
mod shfs;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
    #[clap(long)]
    debug: bool,
}

#[derive(Serialize)]
struct SerializableEvent<'a> {
    event: EventType,
    src_path: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    tgt_path: &'a str,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if opt.debug { "debug" } else { "info" }),
    )
    .init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let functions_to_find = ["shfs_unlink", "shfs_rename", "shfs_create"];
    let offsets = match shfs::get_function_offsets(&functions_to_find) {
        Ok(offsets) => offsets,
        Err(e) => {
            eprintln!("Error finding function offsets: {}", e);
            return Err(anyhow::anyhow!("Failed to get function offsets"));
        }
    };

    let unlink_offset = *offsets.get("shfs_unlink").ok_or_else(|| {
        anyhow::anyhow!("Offset for 'shfs_unlink' not found in the returned map")
    })?;
    debug!("Found offset for shfs_unlink: {:#x}", unlink_offset);

    let rename_offset = *offsets.get("shfs_rename").ok_or_else(|| {
        anyhow::anyhow!("Offset for 'shfs_rename' not found in the returned map")
    })?;
    debug!("Found offset for shfs_rename: {:#x}", rename_offset);

    let create_offset = *offsets.get("shfs_create").ok_or_else(|| {
        anyhow::anyhow!("Offset for 'shfs_create' not found in the returned map")
    })?;
    debug!("Found offset for shfs_create: {:#x}", create_offset);

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = Ebpf::load(include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dirt"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {e}");
    }

    let ring_buf = RingBuf::try_from(ebpf.take_map("EVENTS").ok_or_else(|| anyhow::anyhow!("EVENTS map not found"))?)?;

    let Opt { pid, .. } = opt;

    let unlink_program: &mut UProbe = ebpf.program_mut("uprobe_unlink").unwrap().try_into()?;
    unlink_program.load()?;
    let _unlink_link = unlink_program.attach(unlink_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    let rename_program: &mut UProbe = ebpf.program_mut("uprobe_rename").unwrap().try_into()?;
    rename_program.load()?;
    let _rename_link = rename_program.attach(rename_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    let create_program: &mut UProbe = ebpf.program_mut("uprobe_create").unwrap().try_into()?;
    create_program.load()?;
    let _create_link = create_program.attach(create_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    task::spawn(async move {
        info!("Listening for events...");
        let mut async_fd = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE).unwrap();
        loop {
            let mut guard = async_fd.readable_mut().await.unwrap();
            let ring_buf_mut = guard.get_inner_mut();
            while let Some(record) = ring_buf_mut.next() {
                let ptr = record.as_ptr() as *const Event;
                let event = unsafe { ptr.read_unaligned() };

                let src_path_len = event.src_path.iter().position(|&b| b == 0).unwrap_or(event.src_path.len());
                let tgt_path_len = event.tgt_path.iter().position(|&b| b == 0).unwrap_or(event.tgt_path.len());

                let serializable_event = SerializableEvent {
                    event: event.event,
                    src_path: core::str::from_utf8(&event.src_path[..src_path_len]).unwrap(),
                    tgt_path: core::str::from_utf8(&event.tgt_path[..tgt_path_len]).unwrap(),
                };

                let json = serde_json::to_string_pretty(&serializable_event).unwrap();
                println!("{}", json);
            }
            guard.clear_ready();
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}