use crate::queue::{FsEventJob, Queue};
use std::path::Path;

pub struct Scanner {
    queue: Queue,
}

impl Scanner {
    pub fn new(queue: Queue) -> Self {
        Self { queue }
    }

    pub async fn scan(&mut self, root: &str) -> anyhow::Result<()> {
        log::info!("Starting initial scan of {}", root);
        let root_path = Path::new(root);

        if root_path.is_dir() {
            log::info!("(Placeholder) Walking directory: {}", root);
        }

        log::info!("Initial scan complete");
        Ok(())
    }
}
