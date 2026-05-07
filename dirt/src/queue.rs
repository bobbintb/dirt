use crate::db::{Db, Metadata};
use tokio::time::{sleep, Duration};
use tokio::task;

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct FsEventJob {
    pub path: String,
    pub share: String,
    pub relative_path: String,
    pub event_type: String,
}

#[derive(Clone)]
pub struct Queue {
    db: Db,
}

impl Queue {
    pub fn new(db: Db) -> (Self, task::JoinHandle<()>) {
        let queue = Self { db: db.clone() };
        let worker_db = db.clone();
        let worker = task::spawn(async move {
            loop {
                match worker_db.start_job() {
                    Ok(Some((id, data))) => {
                        if let Ok(job) = bincode::deserialize::<FsEventJob>(&data) {
                            match handle_fs_event(job, worker_db.clone()).await {
                                Ok(_) => {
                                    if let Err(e) = worker_db.complete_job(id) {
                                        log::error!("Failed to complete job {}: {}", id, e);
                                    }
                                }
                                Err(e) => {
                                    log::error!("Job processing failed: {}", e);
                                    // Job remains in in_flight table and will be recovered on next start
                                }
                            }
                        }
                    }
                    Ok(None) => {
                        sleep(Duration::from_millis(500)).await;
                    }
                    Err(e) => {
                        log::error!("Queue start_job failed: {}", e);
                        sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
        (queue, worker)
    }

    pub async fn push(&self, job: FsEventJob) -> anyhow::Result<()> {
        let db = self.db.clone();
        task::spawn_blocking(move || {
            let serialized = bincode::serialize(&job)?;
            db.enqueue_job(&serialized)
        }).await?
    }
}

async fn handle_fs_event(
    job: FsEventJob,
    db: Db,
) -> anyhow::Result<()> {
    log::info!("Starting metadata extraction for {}", job.path);

    // Simulate long-running operation
    sleep(Duration::from_secs(2)).await;

    let metadata = Metadata {
        path: job.path.clone(),
        share: job.share,
        relative_path: job.relative_path,
        size: 1024,
        modified: 123456789,
    };

    db.update_metadata(&metadata)?;

    log::info!("Completed metadata extraction for {}", job.path);
    Ok(())
}
