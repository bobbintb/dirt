use redb::{Database, TableDefinition, ReadableTable};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Metadata {
    pub path: String,
    pub share: String,
    pub relative_path: String,
    pub size: u64,
    pub modified: u64,
}

pub const METADATA_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("metadata");
pub const PENDING_QUEUE_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("pending_queue");
pub const IN_FLIGHT_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("in_flight");

#[derive(Clone)]
pub struct Db {
    database: Arc<Database>,
}

impl Db {
    pub fn new<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let db = Database::builder()
            .create(path)?;

        // Initialize tables
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(METADATA_TABLE)?;
            let _ = write_txn.open_table(PENDING_QUEUE_TABLE)?;
            let _ = write_txn.open_table(IN_FLIGHT_TABLE)?;
        }
        write_txn.commit()?;

        let s = Self {
            database: Arc::new(db),
        };
        s.recover_abandoned_jobs()?;
        Ok(s)
    }

    fn recover_abandoned_jobs(&self) -> anyhow::Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut in_flight = write_txn.open_table(IN_FLIGHT_TABLE)?;
            let mut pending = write_txn.open_table(PENDING_QUEUE_TABLE)?;

            let mut abandoned = Vec::new();
            for item in in_flight.iter()? {
                let (id, data) = item?;
                abandoned.push((id.value(), data.value().to_vec()));
            }

            for (id, data) in abandoned {
                pending.insert(id, data.as_slice())?;
                in_flight.remove(id)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn update_metadata(&self, metadata: &Metadata) -> anyhow::Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(METADATA_TABLE)?;
            let serialized = bincode::serialize(metadata)?;
            table.insert(metadata.path.as_str(), serialized.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn enqueue_job(&self, job: &[u8]) -> anyhow::Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(PENDING_QUEUE_TABLE)?;
            let id = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos() as u64;
            table.insert(id, job)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn start_job(&self) -> anyhow::Result<Option<(u64, Vec<u8>)>> {
        let write_txn = self.database.begin_write()?;
        let result = {
            let pending = write_txn.open_table(PENDING_QUEUE_TABLE)?;
            let first = pending.first()?;
            if let Some((id, value)) = first {
                Some((id.value(), value.value().to_vec()))
            } else {
                None
            }
        };

        if let Some((id, data)) = result.as_ref() {
            {
                let mut pending = write_txn.open_table(PENDING_QUEUE_TABLE)?;
                let mut in_flight = write_txn.open_table(IN_FLIGHT_TABLE)?;
                pending.remove(*id)?;
                in_flight.insert(*id, data.as_slice())?;
            }
            write_txn.commit()?;
        }

        Ok(result)
    }

    pub fn complete_job(&self, id: u64) -> anyhow::Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut in_flight = write_txn.open_table(IN_FLIGHT_TABLE)?;
            in_flight.remove(id)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_metadata(&self, path: &str) -> anyhow::Result<Option<Metadata>> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(METADATA_TABLE)?;
        let value = table.get(path)?;

        if let Some(bytes) = value {
            let metadata: Metadata = bincode::deserialize(bytes.value())?;
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }
}
