//! Durable directory persistence — closes the restart/squatting gap
//! `docs/ARCHITECTURE.md` §6.1 names at its root: `Inner::directory` and
//! `Inner::username_index` (`crate::state`) were in-memory only, so a
//! restart forgot every registration, opening a window for anyone else
//! to claim a `username#NNNN` a device still believed it owned. The
//! client-side `dratchet_app::reconcile_own_profile` (also §6.1) narrows
//! that window by reclaiming on reconnect; this closes it at the source
//! by no longer forgetting registrations in the first place.
//!
//! Deliberately scoped to the directory alone — mailboxes, presence, and
//! subscriptions stay exactly as in-memory-only as before, matching
//! `docs/SERVERS.md` §1.3/1.4's "no durable message storage" stance.
//! Only which `username#NNNN` maps to which identity, and that
//! identity's current bundle (including its remaining one-time-prekey
//! pool — see [`Persistence::save`]'s doc), needs to survive a restart.

use std::path::Path;

use redb::TableDefinition;

use crate::state::{Fingerprint, StoredBundle};
use crate::ws::hex_encode;

const DIRECTORY_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("directory");

pub struct Persistence {
    database: redb::Database,
}

impl Persistence {
    /// Opens (creating if it doesn't exist) the directory's persistence
    /// file at `path`. Only ever called once, at server startup —
    /// `crate::app_with_directory_db`.
    pub fn open(path: &Path) -> Result<Self, redb::DatabaseError> {
        let database = redb::Database::create(path)?;
        Ok(Self { database })
    }

    /// Every persisted `(fingerprint, StoredBundle)` pair, read once at
    /// startup to repopulate `Inner::directory`/`username_index`
    /// (`crate::app_with_directory_db`). A read or decode failure is
    /// logged and treated as "nothing recovered" rather than failing
    /// startup outright — every affected device just re-registers, which
    /// is strictly better than an unbootable server.
    pub fn load_all(&self) -> Vec<(Fingerprint, StoredBundle)> {
        match self.try_load_all() {
            Ok(loaded) => loaded,
            Err(e) => {
                tracing::error!("directory persistence: failed to load, starting empty: {e}");
                Vec::new()
            }
        }
    }

    fn try_load_all(&self) -> Result<Vec<(Fingerprint, StoredBundle)>, Box<dyn std::error::Error>> {
        let read_txn = self.database.begin_read()?;
        let table = match read_txn.open_table(DIRECTORY_TABLE) {
            Ok(table) => table,
            // First run: the table has never been created yet.
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut loaded = Vec::new();
        for entry in table.range::<&[u8]>(..)? {
            let (k, v) = entry?;
            let Ok(fp): Result<Fingerprint, _> = k.value().try_into() else {
                tracing::error!(
                    "directory persistence: skipping a record with a malformed fingerprint key"
                );
                continue;
            };
            match ciborium::from_reader::<StoredBundle, _>(v.value()) {
                Ok(stored) => loaded.push((fp, stored)),
                Err(e) => tracing::error!(
                    "directory persistence: skipping a corrupted record for {}: {e}",
                    hex_encode(&fp),
                ),
            }
        }
        Ok(loaded)
    }

    /// Upsert one fingerprint's current bundle. Called after every
    /// mutation to `Inner::directory` — a publish (registration, rename,
    /// or signed-prekey rotation) and a one-time-prekey consumed by
    /// `FetchBundle` — so a restart never resurrects state already
    /// superseded in memory. The `FetchBundle` case matters as much as
    /// the publish case: without it, a restart would "un-consume" a
    /// one-time prekey and let it be handed out to a second initiator,
    /// which is exactly the single-use guarantee X3DH depends on it for
    /// (`ARCHITECTURE.md` §3.2).
    ///
    /// Best-effort: a write failure is logged, not propagated. The
    /// in-memory mutation this follows already succeeded and is correct
    /// for this process's lifetime — a disk problem here is a durability
    /// degradation, not a reason to fail the request that triggered it.
    pub fn save(&self, fp: &Fingerprint, stored: &StoredBundle) {
        let mut bytes = Vec::new();
        if let Err(e) = ciborium::into_writer(stored, &mut bytes) {
            tracing::error!("directory persistence: failed to encode a record: {e}");
            return;
        }
        if let Err(e) = self.try_save(fp, &bytes) {
            tracing::error!(
                "directory persistence: failed to save a record for {}: {e}",
                hex_encode(fp),
            );
        }
    }

    fn try_save(&self, fp: &Fingerprint, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(DIRECTORY_TABLE)?;
            table.insert(fp.as_slice(), bytes)?;
        }
        write_txn.commit()?;
        Ok(())
    }
}
