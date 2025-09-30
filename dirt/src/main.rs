use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::UProbe,
    Ebpf,
};
use clap::Parser;
use dirt_common::Event;
#[rustfmt::skip]
use log::{debug, info, warn};
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

    let functions_to_find = ["shfs_unlink"];
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
    let program: &mut UProbe = ebpf.program_mut("dirt").unwrap().try_into()?;
    program.load()?;
    let _link = program.attach(unlink_offset, "/usr/libexec/unraid/shfs", pid, None /* cookie */)?;

    task::spawn(async move {
        info!("Listening for events...");
        let mut async_fd = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE).unwrap();
        loop {
            let mut guard = async_fd.readable_mut().await.unwrap();
            let ring_buf_mut = guard.get_inner_mut();
            while let Some(record) = ring_buf_mut.next() {
                let ptr = record.as_ptr() as *const Event;
                let event = unsafe { ptr.read_unaligned() };
                let json = serde_json::to_string_pretty(&event).unwrap();
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