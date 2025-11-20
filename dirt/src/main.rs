use aya::{
    include_bytes_aligned,
    maps::{HashMap, RingBuf},
    programs::UProbe,
    Ebpf,
};
use clap::Parser;
use dirt_common::{Event, EventType, ShareName, MAX_SHARE_LEN};
#[rustfmt::skip]
use log::{debug, info, warn};
use redis::AsyncCommands;
use serde::Serialize;
use tokio::{io::unix::AsyncFd, signal, task};

mod error;
mod shfs;
mod settings;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
    #[clap(long)]
    debug: bool,
}

#[derive(Serialize)]
struct SplitPath<'a> {
    share: &'a str,
    relative_path: &'a str,
}

#[derive(Serialize)]
struct JsonEvent<'a> {
    fs_event: EventType,
    event: &'a str,
    src: SplitPath<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tgt: Option<SplitPath<'a>>,
}

// Returns a tuple of (share, relative_path)
fn split_path(path: &str) -> (&str, &str) {
    let path = path.trim_start_matches('/');
    if let Some(index) = path.find('/') {
        (&path[..index], &path[index + 1..])
    } else {
        (path, "")
    }
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

    let functions_to_find = [
        "shfs_unlink",
        "shfs_rename",
        "shfs_create",
        "shfs_write_buf",
        "shfs_truncate",
        "shfs_fallocate",
        "shfs_flush",
        "shfs_release",
    ];
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

    let write_buf_offset = *offsets
        .get("shfs_write_buf")
        .ok_or_else(|| anyhow::anyhow!("Offset for 'shfs_write_buf' not found"))?;
    debug!("Found offset for shfs_write_buf: {:#x}", write_buf_offset);

    let truncate_offset = *offsets
        .get("shfs_truncate")
        .ok_or_else(|| anyhow::anyhow!("Offset for 'shfs_truncate' not found"))?;
    debug!("Found offset for shfs_truncate: {:#x}", truncate_offset);

    let fallocate_offset = *offsets
        .get("shfs_fallocate")
        .ok_or_else(|| anyhow::anyhow!("Offset for 'shfs_fallocate' not found"))?;
    debug!("Found offset for shfs_fallocate: {:#x}", fallocate_offset);

    let flush_offset = *offsets
        .get("shfs_flush")
        .ok_or_else(|| anyhow::anyhow!("Offset for 'shfs_flush' not found"))?;
    debug!("Found offset for shfs_flush: {:#x}", flush_offset);

    let release_offset = *offsets
        .get("shfs_release")
        .ok_or_else(|| anyhow::anyhow!("Offset for 'shfs_release' not found"))?;
    debug!("Found offset for shfs_release: {:#x}", release_offset);

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

    let settings = match settings::load_settings() {
        Ok(settings) => settings,
        Err(e) => {
            log::error!("Failed to load settings: {}", e);
            return Err(e);
        }
    };

    if settings.share.is_empty() {
        let err_msg = "Configuration file is invalid or `share` list is empty.";
        log::error!("{}", err_msg);
        return Err(anyhow::anyhow!(err_msg));
    }

    let mut whitelist: HashMap<_, ShareName, u8> =
        HashMap::try_from(ebpf.take_map("WHITELIST").ok_or_else(|| anyhow::anyhow!("WHITELIST map not found"))?)?;

    for share in &settings.share {
        let mut share_bytes = [0u8; MAX_SHARE_LEN];
        let len = core::cmp::min(share.len(), MAX_SHARE_LEN);
        share_bytes[..len].copy_from_slice(share.as_bytes());
        whitelist.insert(share_bytes, 0, 0)?;
        info!("Whitelisted share: {}", share);
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

    let uretprobe_unlink_program: &mut UProbe = ebpf.program_mut("uretprobe_unlink").unwrap().try_into()?;
    uretprobe_unlink_program.load()?;
    let _uretprobe_unlink_link = uretprobe_unlink_program.attach(unlink_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    let uretprobe_rename_program: &mut UProbe = ebpf.program_mut("uretprobe_rename").unwrap().try_into()?;
    uretprobe_rename_program.load()?;
    let _uretprobe_rename_link = uretprobe_rename_program.attach(rename_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    let uretprobe_create_program: &mut UProbe = ebpf.program_mut("uretprobe_create").unwrap().try_into()?;
    uretprobe_create_program.load()?;
    let _uretprobe_create_link = uretprobe_create_program.attach(create_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    let write_buf_program: &mut UProbe = ebpf.program_mut("uprobe_write_buf").unwrap().try_into()?;
    write_buf_program.load()?;
    let _write_buf_link = write_buf_program.attach(write_buf_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    let truncate_program: &mut UProbe = ebpf.program_mut("uprobe_truncate").unwrap().try_into()?;
    truncate_program.load()?;
    let _truncate_link = truncate_program.attach(truncate_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    let fallocate_program: &mut UProbe = ebpf.program_mut("uprobe_fallocate").unwrap().try_into()?;
    fallocate_program.load()?;
    let _fallocate_link = fallocate_program.attach(fallocate_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    let flush_program: &mut UProbe = ebpf.program_mut("uprobe_flush").unwrap().try_into()?;
    flush_program.load()?;
    let _flush_link = flush_program.attach(flush_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    let release_program: &mut UProbe = ebpf.program_mut("uprobe_release").unwrap().try_into()?;
    release_program.load()?;
    let _release_link = release_program.attach(release_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    let client = redis::Client::open("redis://127.0.0.1/")?;
    let mut con = client.get_async_connection().await?;

    task::spawn(async move {
        info!("Listening for events...");
        let mut async_fd = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE).unwrap();
        loop {
            let mut guard = async_fd.readable_mut().await.unwrap();
            let ring_buf_mut = guard.get_inner_mut();
            while let Some(record) = ring_buf_mut.next() {
                let ptr = record.as_ptr() as *const Event;
                let event = unsafe { ptr.read_unaligned() };

                let src_path_len = event
                    .src_path
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(event.src_path.len());
                let src_path = core::str::from_utf8(&event.src_path[..src_path_len]).unwrap();
                let (src_share, src_relative_path) = split_path(src_path);

                let tgt_path_len = event
                    .tgt_path
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(event.tgt_path.len());
                let tgt_path = core::str::from_utf8(&event.tgt_path[..tgt_path_len]).unwrap();

                let tgt = if tgt_path.is_empty() {
                    None
                } else {
                    let (tgt_share, tgt_relative_path) = split_path(tgt_path);
                    Some(SplitPath {
                        share: tgt_share,
                        relative_path: tgt_relative_path,
                    })
                };

                let db_event = match event.event {
                    EventType::Create | EventType::Modified => "upsert",
                    EventType::Unlink => "remove",
                    EventType::Rename => {
                        let src_in_whitelist = settings.share.iter().any(|s| s == src_share);
                        let tgt_in_whitelist = if let Some(ref tgt) = tgt {
                            settings.share.iter().any(|s| s == tgt.share)
                        } else {
                            false
                        };

                        if !src_in_whitelist && tgt_in_whitelist {
                            "upsert"
                        } else if src_in_whitelist && tgt_in_whitelist {
                            "rename"
                        } else if src_in_whitelist && !tgt_in_whitelist {
                            "remove"
                        } else {
                            // This case should not be reachable due to eBPF filtering
                            warn!("Unfiltered rename event received: src_share={}, tgt_share={:?}", src_share, tgt.as_ref().map(|t| t.share));
                            continue;
                        }
                    },
                };

                let json_event = JsonEvent {
                    fs_event: event.event,
                    event: db_event,
                    src: SplitPath {
                        share: src_share,
                        relative_path: src_relative_path,
                    },
                    tgt,
                };

                let json = serde_json::to_string(&json_event).unwrap();
                match con.rpush("dirt-events", json).await {
                    Ok(()) => {}
                    Err(e) => {
                        log::error!("Failed to send event to Redis: {}", e);
                    }
                }
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