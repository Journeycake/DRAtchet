//! Optional on-disk persistence for queued mail (`docs/adr/0001`).
//!
//! Off by default: mailboxes otherwise live only in memory (see
//! `crate::persistence`, which persists the directory alone). When an
//! operator turns it on, each queued entry is stored as a **Sealed
//! Message** -- the envelope with its mailbox, writer and expiry, encrypted
//! under a key derived from the operator's key -- split into **Fragments**,
//! one per configured fragment directory, each in its own file named by a
//! random UUID. An index database maps each entry to its Fragments and the
//! SHA-256 of its Sealed Message; every index record is itself encrypted,
//! so only the key holder can tell which Fragments belong together.
//!
//! The store also owns the **Server Epoch**: a store id plus a counter,
//! sent to every client. It advances whenever queued mail may have been
//! lost -- a start after a run that didn't finish its last save, an entry
//! that couldn't be rebuilt, or a store that was lost or can't be read
//! with the current key -- so clients can offer Retry for their
//! undelivered messages (DRA-0064).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::state::{random_16, Fingerprint, MailboxId};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("mailstore_meta");
const INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("mailstore_index");

/// One index row as stored: entry id, sealed [`IndexRecord`].
type Row = (Vec<u8>, Vec<u8>);
/// The sealed state record and key check, as stored (either may be absent).
type SealedMeta = (Option<Vec<u8>>, Option<Vec<u8>>);

/// The sealed [`StoreState`] record (DRA-0074).
const META_STATE: &str = "state";
const META_KEY_CHECK: &str = "key_check";
const KEY_CHECK_PLAINTEXT: &[u8] = b"dratchet mailstore key check v1";
const FRAGMENT_SUFFIX: &str = ".frag";
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("mail store database: {0}")]
    Db(String),
    #[error("mail store file: {0}")]
    Io(#[from] std::io::Error),
    #[error("mail store entry could not be rebuilt: {0}")]
    Unreadable(&'static str),
}

fn db_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Db(e.to_string())
}

/// The Server Epoch: which mail store, and how many times queued mail in
/// it may have been lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epoch {
    pub store_id: [u8; 16],
    pub number: u64,
}

impl Epoch {
    /// What clients compare (`AuthChallenge::server_boot_id`): any change
    /// in either part is a new epoch.
    pub fn wire_id(&self) -> Vec<u8> {
        let mut id = self.store_id.to_vec();
        id.extend_from_slice(&self.number.to_be_bytes());
        id
    }
}

/// One entry to save.
pub struct PendingEntry {
    pub mailbox_id: MailboxId,
    pub entry_id: [u8; 16],
    pub envelope: Vec<u8>,
    pub expires_at: u64,
    pub written_by: Fingerprint,
}

/// One entry rebuilt at startup (its envelope stays on disk).
pub struct RestoredEntry {
    pub mailbox_id: MailboxId,
    pub entry_id: [u8; 16],
    pub expires_at: u64,
    pub written_by: Fingerprint,
}

#[derive(Serialize, Deserialize)]
struct SealedContent {
    #[serde(with = "serde_bytes")]
    mailbox_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    entry_id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    envelope: Vec<u8>,
    expires_at: u64,
    #[serde(with = "serde_bytes")]
    written_by: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone)]
struct IndexRecord {
    #[serde(with = "serde_bytes")]
    mailbox_id: Vec<u8>,
    expires_at: u64,
    #[serde(with = "serde_bytes")]
    written_by: Vec<u8>,
    /// (fragment directory index, fragment UUID), in order.
    fragments: Vec<(u8, String)>,
    #[serde(with = "serde_bytes")]
    checksum: Vec<u8>,
}

/// The store's own state, sealed under the index key so it can't be
/// changed without the key (DRA-0074). It's rewritten in the same
/// transaction as every change to the index.
#[derive(Serialize, Deserialize)]
struct StoreState {
    #[serde(with = "serde_bytes")]
    store_id: Vec<u8>,
    number: u64,
    /// Every queued entry was saved before the run that wrote this ended.
    clean: bool,
    /// [`manifest`] of every index row this record describes.
    #[serde(with = "serde_bytes")]
    manifest: Vec<u8>,
}

/// SHA-256 over the sorted ids of a set of index rows: removing, adding or
/// renaming any row changes it.
fn manifest<'a>(ids: impl IntoIterator<Item = &'a [u8; 16]>) -> [u8; 32] {
    let mut ids: Vec<&[u8; 16]> = ids.into_iter().collect();
    ids.sort_unstable();
    let mut h = Sha256::new();
    for id in ids {
        h.update(id);
    }
    h.finalize().into()
}

/// Why a store reopened with its own state record starts a new epoch, if
/// it does: the last run didn't finish its last save, or the index rows on
/// disk aren't the ones that run left (DRA-0074).
fn continuing_epoch(advanced_because: &mut Option<&'static str>, state: &StoreState, rows: &[Row]) {
    let present = {
        let mut ids: Vec<&[u8]> = rows.iter().map(|(k, _)| k.as_slice()).collect();
        ids.sort_unstable();
        let mut h = Sha256::new();
        for id in ids {
            // A row whose id isn't 16 bytes was never written by the store;
            // hashing its length too keeps it from posing as two others.
            if id.len() != 16 {
                h.update(b"\xffbad row");
                h.update((id.len() as u64).to_be_bytes());
            }
            h.update(id);
        }
        <[u8; 32]>::from(h.finalize())
    };
    if present.as_slice() != state.manifest.as_slice() {
        tracing::error!("mail store: the index on disk was changed outside the relay");
        *advanced_because = Some("the index was changed outside the relay");
    } else if !state.clean {
        *advanced_because = Some("previous run did not finish its last save");
    }
}

pub struct OpenedStore {
    pub store: MailStore,
    pub restored: Vec<RestoredEntry>,
    pub epoch: Epoch,
    /// Why the epoch advanced at this start, if it did (for the log).
    pub advanced_because: Option<&'static str>,
}

pub struct MailStore {
    db: Database,
    dirs: Vec<PathBuf>,
    seal: ChaCha20Poly1305,
    index: ChaCha20Poly1305,
    records: Mutex<HashMap<[u8; 16], IndexRecord>>,
    epoch: Mutex<Epoch>,
}

fn derive(key: &[u8; 32], label: &[u8]) -> ChaCha20Poly1305 {
    let mut h = Sha256::new();
    h.update(b"dratchet mailstore ");
    h.update(label);
    h.update(key);
    let derived: [u8; 32] = h.finalize().into();
    ChaCha20Poly1305::new(Key::from_slice(&derived))
}

fn seal_bytes(cipher: &ChaCha20Poly1305, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("ChaCha20Poly1305 encryption cannot fail for in-memory buffers");
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    out
}

fn open_bytes(cipher: &ChaCha20Poly1305, aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
}

fn cbor<T: Serialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR encoding into a Vec cannot fail");
    out
}

/// A random version-4 UUID, as a string.
fn uuid_v4() -> String {
    let mut b = random_16();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

fn now_unix() -> u64 {
    crate::state::now_unix()
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Marks a directory as one this store created or adopted while empty.
const OWNED_MARKER: &str = ".dratchet-fragments";

/// Make `dir` a fragment directory this store owns: create it, or adopt it
/// if it exists and is empty, marking it either way. A directory that
/// already holds anything else and isn't marked is refused, so pointing
/// `fragment_dirs` at a shared directory by mistake never changes its
/// permissions or deletes its files (the store removes `*.frag` files it
/// doesn't recognise, and all of them when its key changes).
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    let marker = dir.join(OWNED_MARKER);
    if dir.exists() && !marker.exists() && fs::read_dir(dir)?.next().is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "fragment directory {} already holds other files; give the mail store an \
                 empty or new directory of its own",
                dir.display()
            ),
        ));
    }
    fs::create_dir_all(dir)?;
    if !marker.exists() {
        fs::write(&marker, b"")?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// DRA-0073: refuse two configured names for one directory (a symlink,
/// `./a` beside `a`, an absolute path beside a relative one, a bind
/// mount). The configuration check compares the names only. Each
/// directory's Fragments are swept against its own position in the list,
/// so an aliased pair would delete every entry's other Fragment at the
/// next start, and splitting would gain nothing.
fn refuse_aliased_dirs(dirs: &[PathBuf]) -> std::io::Result<()> {
    let mut seen = HashMap::new();
    for dir in dirs {
        #[cfg(unix)]
        let id = {
            use std::os::unix::fs::MetadataExt;
            let meta = fs::metadata(dir)?;
            (meta.dev(), meta.ino())
        };
        #[cfg(not(unix))]
        let id = fs::canonicalize(dir)?;
        if let Some(first) = seen.insert(id, dir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "fragment directories {} and {} are the same directory; give each \
                     Fragment its own directory, ideally on different volumes",
                    first.display(),
                    dir.display()
                ),
            ));
        }
    }
    Ok(())
}

fn sync_dir(dir: &Path) {
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
}

impl MailStore {
    /// Open (or create) the store and rebuild every entry it holds.
    pub fn open(
        index_path: &Path,
        fragment_dirs: &[PathBuf],
        key: &[u8; 32],
    ) -> Result<OpenedStore, StoreError> {
        for dir in fragment_dirs {
            ensure_private_dir(dir)?;
        }
        refuse_aliased_dirs(fragment_dirs)?;
        if let Some(parent) = index_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let db = Database::create(index_path).map_err(db_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(index_path, fs::Permissions::from_mode(0o600))?;
        }
        let store = MailStore {
            db,
            dirs: fragment_dirs.to_vec(),
            seal: derive(key, b"seal"),
            index: derive(key, b"index"),
            records: Mutex::new(HashMap::new()),
            epoch: Mutex::new(Epoch {
                store_id: [0; 16],
                number: 0,
            }),
        };

        let (sealed_state, key_check) = store.read_meta()?;
        let mut rows = store.read_rows()?;
        let key_ok = key_check
            .as_deref()
            .and_then(|kc| open_bytes(&store.index, META_KEY_CHECK.as_bytes(), kc))
            .is_some_and(|pt| pt == KEY_CHECK_PLAINTEXT);
        let saved_state = sealed_state
            .as_deref()
            .and_then(|s| open_bytes(&store.index, META_STATE.as_bytes(), s))
            .and_then(|pt| ciborium::from_reader::<StoreState, _>(pt.as_slice()).ok())
            .and_then(|s| Some((<[u8; 16]>::try_from(s.store_id.as_slice()).ok()?, s)));

        let new_store_id = || Epoch {
            store_id: random_16(),
            number: 1,
        };
        let mut advanced_because: Option<&'static str> = None;
        // Whether `epoch` continues the stored one, and so has to count up
        // to advance (a new store id is already a new epoch).
        let mut continues = false;
        let mut to_remove: Vec<Vec<u8>> = Vec::new();
        let mut epoch = if key_check.is_some() && !key_ok {
            tracing::error!(
                "mail store: the configured key does not open the existing store; \
                 its queued mail is unreadable and is being discarded"
            );
            store.remove_all_fragments()?;
            to_remove = rows.drain(..).map(|(k, _)| k).collect();
            advanced_because = Some("store unreadable with the current key");
            new_store_id()
        } else if let Some((store_id, state)) = saved_state {
            continuing_epoch(&mut advanced_because, &state, &rows);
            continues = true;
            Epoch {
                store_id,
                number: state.number,
            }
        } else if sealed_state.is_none() && key_check.is_none() && rows.is_empty() {
            advanced_because = Some("new mail store");
            new_store_id()
        } else {
            // DRA-0074: without a readable state record nothing on disk
            // can be vouched for, so start a new epoch outright.
            advanced_because = Some("the store's state record is missing or unreadable");
            new_store_id()
        };

        let (restored, dropped, removed) = store.rebuild(rows);
        to_remove.extend(removed);
        if dropped > 0 {
            tracing::error!(
                dropped,
                "mail store: entries could not be rebuilt and were dropped"
            );
            advanced_because.get_or_insert("entries could not be rebuilt");
        }
        store.remove_orphan_fragments()?;

        if advanced_because.is_some() && continues {
            epoch.number += 1;
        }
        *store.epoch.lock().expect("epoch lock") = epoch;
        {
            let records = store.records.lock().expect("records lock");
            let txn = store.db.begin_write().map_err(db_err)?;
            {
                let mut table = txn.open_table(INDEX).map_err(db_err)?;
                for k in &to_remove {
                    table.remove(k.as_slice()).map_err(db_err)?;
                }
            }
            store.put_state(&txn, &epoch, false, &manifest(records.keys()))?;
            txn.commit().map_err(db_err)?;
        }
        Ok(OpenedStore {
            store,
            restored,
            epoch,
            advanced_because,
        })
    }

    fn read_meta(&self) -> Result<SealedMeta, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        let table = match txn.open_table(META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok((None, None)),
            Err(e) => return Err(db_err(e)),
        };
        let get = |k: &str| -> Result<Option<Vec<u8>>, StoreError> {
            Ok(table.get(k).map_err(db_err)?.map(|v| v.value().to_vec()))
        };
        Ok((get(META_STATE)?, get(META_KEY_CHECK)?))
    }

    fn read_rows(&self) -> Result<Vec<Row>, StoreError> {
        let txn = self.db.begin_read().map_err(db_err)?;
        match txn.open_table(INDEX) {
            Ok(table) => Ok(table
                .iter()
                .map_err(db_err)?
                .filter_map(|r| r.ok())
                .map(|(k, v)| (k.value().to_vec(), v.value().to_vec()))
                .collect()),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(Vec::new()),
            Err(e) => Err(db_err(e)),
        }
    }

    /// Write the sealed state record (and the key check) inside `txn`,
    /// which must also hold any change to the index it describes.
    fn put_state(
        &self,
        txn: &redb::WriteTransaction,
        epoch: &Epoch,
        clean: bool,
        manifest: &[u8; 32],
    ) -> Result<(), StoreError> {
        let state = seal_bytes(
            &self.index,
            META_STATE.as_bytes(),
            &cbor(&StoreState {
                store_id: epoch.store_id.to_vec(),
                number: epoch.number,
                clean,
                manifest: manifest.to_vec(),
            }),
        );
        let key_check = seal_bytes(&self.index, META_KEY_CHECK.as_bytes(), KEY_CHECK_PLAINTEXT);
        let mut table = txn.open_table(META).map_err(db_err)?;
        table.insert(META_STATE, state.as_slice()).map_err(db_err)?;
        table
            .insert(META_KEY_CHECK, key_check.as_slice())
            .map_err(db_err)?;
        Ok(())
    }

    /// Write the state record on its own, with the index unchanged.
    fn write_state(&self, epoch: &Epoch, clean: bool) -> Result<(), StoreError> {
        let records = self.records.lock().expect("records lock");
        let txn = self.db.begin_write().map_err(db_err)?;
        self.put_state(&txn, epoch, clean, &manifest(records.keys()))?;
        txn.commit().map_err(db_err)
    }

    /// Discard every Fragment (the store can't be read with this key).
    fn remove_all_fragments(&self) -> Result<(), StoreError> {
        for dir in &self.dirs {
            for entry in fs::read_dir(dir)? {
                let path = entry?.path();
                if path.to_string_lossy().ends_with(FRAGMENT_SUFFIX) {
                    let _ = fs::remove_file(path);
                }
            }
        }
        Ok(())
    }

    /// Rebuild every entry from the index rows. Returns the survivors, how
    /// many were dropped because they couldn't be read back intact, and
    /// the rows to remove (dropped or expired).
    fn rebuild(&self, rows: Vec<Row>) -> (Vec<RestoredEntry>, usize, Vec<Vec<u8>>) {
        let now = now_unix();
        let mut restored = Vec::new();
        let mut to_remove = Vec::new();
        let mut dropped = 0;
        let mut records = self.records.lock().expect("records lock");
        for (key, value) in rows {
            let Ok(entry_id) = <[u8; 16]>::try_from(key.as_slice()) else {
                dropped += 1;
                to_remove.push(key);
                continue;
            };
            let record = match open_bytes(&self.index, &entry_id, &value)
                .and_then(|pt| ciborium::from_reader::<IndexRecord, _>(pt.as_slice()).ok())
            {
                Some(r) => r,
                None => {
                    dropped += 1;
                    to_remove.push(key);
                    continue;
                }
            };
            if record.expires_at <= now {
                // Expired while the relay was down: removed, not lost.
                self.delete_fragments(&record);
                to_remove.push(key);
                continue;
            }
            match self.read_record(&entry_id, &record) {
                Ok(content) => {
                    let (Ok(mailbox_id), Ok(written_by)) = (
                        <[u8; 16]>::try_from(content.mailbox_id.as_slice()),
                        <[u8; 32]>::try_from(content.written_by.as_slice()),
                    ) else {
                        dropped += 1;
                        to_remove.push(key);
                        continue;
                    };
                    restored.push(RestoredEntry {
                        mailbox_id,
                        entry_id,
                        expires_at: content.expires_at,
                        written_by,
                    });
                    records.insert(entry_id, record);
                }
                Err(e) => {
                    tracing::warn!("mail store: dropping an entry: {e}");
                    self.delete_fragments(&record);
                    dropped += 1;
                    to_remove.push(key);
                }
            }
        }
        (restored, dropped, to_remove)
    }

    /// Reassemble, verify and decrypt one Sealed Message.
    fn read_record(
        &self,
        entry_id: &[u8; 16],
        record: &IndexRecord,
    ) -> Result<SealedContent, StoreError> {
        let mut sealed = Vec::new();
        for (dir_index, uuid) in &record.fragments {
            let dir = self
                .dirs
                .get(*dir_index as usize)
                .ok_or(StoreError::Unreadable(
                    "fragment directory no longer configured",
                ))?;
            let path = dir.join(format!("{uuid}{FRAGMENT_SUFFIX}"));
            let bytes = fs::read(&path).map_err(|_| StoreError::Unreadable("missing fragment"))?;
            sealed.extend_from_slice(&bytes);
        }
        let checksum: [u8; 32] = Sha256::digest(&sealed).into();
        if checksum.as_slice() != record.checksum.as_slice() {
            return Err(StoreError::Unreadable("checksum mismatch"));
        }
        let plaintext = open_bytes(&self.seal, entry_id, &sealed)
            .ok_or(StoreError::Unreadable("sealed message did not decrypt"))?;
        let content: SealedContent = ciborium::from_reader(plaintext.as_slice())
            .map_err(|_| StoreError::Unreadable("sealed message did not decode"))?;
        if content.entry_id.as_slice() != entry_id
            || content.mailbox_id != record.mailbox_id
            || content.written_by != record.written_by
        {
            return Err(StoreError::Unreadable(
                "sealed message does not match its index record",
            ));
        }
        Ok(content)
    }

    fn delete_fragments(&self, record: &IndexRecord) {
        for (dir_index, uuid) in &record.fragments {
            if let Some(dir) = self.dirs.get(*dir_index as usize) {
                let _ = fs::remove_file(dir.join(format!("{uuid}{FRAGMENT_SUFFIX}")));
            }
        }
    }

    /// Delete Fragment files no index record refers to (a save or a
    /// removal interrupted by a crash leaves these behind).
    fn remove_orphan_fragments(&self) -> Result<(), StoreError> {
        let referenced: HashSet<(usize, String)> = self
            .records
            .lock()
            .expect("records lock")
            .values()
            .flat_map(|r| r.fragments.iter().map(|(d, u)| (*d as usize, u.clone())))
            .collect();
        for (i, dir) in self.dirs.iter().enumerate() {
            for entry in fs::read_dir(dir)? {
                let path = entry?.path();
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if let Some(uuid) = name.strip_suffix(FRAGMENT_SUFFIX) {
                    if !referenced.contains(&(i, uuid.to_string())) {
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }
        Ok(())
    }

    /// Save a batch durably: Fragments first (each synced), then the index
    /// records in one transaction. Only once this returns is any of it
    /// safe to acknowledge.
    pub fn save(&self, batch: &[PendingEntry]) -> Result<(), StoreError> {
        if batch.is_empty() {
            return Ok(());
        }
        let n = self.dirs.len();
        let mut new_records = Vec::with_capacity(batch.len());
        for e in batch {
            let sealed = seal_bytes(
                &self.seal,
                &e.entry_id,
                &cbor(&SealedContent {
                    mailbox_id: e.mailbox_id.to_vec(),
                    entry_id: e.entry_id.to_vec(),
                    envelope: e.envelope.clone(),
                    expires_at: e.expires_at,
                    written_by: e.written_by.to_vec(),
                }),
            );
            let checksum: [u8; 32] = Sha256::digest(&sealed).into();
            let chunk = sealed.len().div_ceil(n);
            let mut fragments = Vec::with_capacity(n);
            for (i, dir) in self.dirs.iter().enumerate() {
                let start = (i * chunk).min(sealed.len());
                let end = ((i + 1) * chunk).min(sealed.len());
                let uuid = uuid_v4();
                write_private(
                    &dir.join(format!("{uuid}{FRAGMENT_SUFFIX}")),
                    &sealed[start..end],
                )?;
                fragments.push((i as u8, uuid));
            }
            new_records.push((
                e.entry_id,
                IndexRecord {
                    mailbox_id: e.mailbox_id.to_vec(),
                    expires_at: e.expires_at,
                    written_by: e.written_by.to_vec(),
                    fragments,
                    checksum: checksum.to_vec(),
                },
            ));
        }
        for dir in &self.dirs {
            sync_dir(dir);
        }
        let mut records = self.records.lock().expect("records lock");
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(INDEX).map_err(db_err)?;
            for (entry_id, record) in &new_records {
                let value = seal_bytes(&self.index, entry_id, &cbor(record));
                table
                    .insert(entry_id.as_slice(), value.as_slice())
                    .map_err(db_err)?;
            }
        }
        let after: HashSet<&[u8; 16]> = records
            .keys()
            .chain(new_records.iter().map(|(id, _)| id))
            .collect();
        self.put_state(&txn, &self.epoch(), false, &manifest(after))?;
        txn.commit().map_err(db_err)?;
        for (entry_id, record) in new_records {
            records.insert(entry_id, record);
        }
        Ok(())
    }

    /// Remove every stored entry not in `live` (collected or expired since
    /// it was saved). Index records go first, then their Fragments.
    pub fn retain(&self, live: &HashSet<[u8; 16]>) -> Result<usize, StoreError> {
        let mut records = self.records.lock().expect("records lock");
        let gone: Vec<([u8; 16], IndexRecord)> = records
            .iter()
            .filter(|(id, _)| !live.contains(*id))
            .map(|(id, r)| (*id, r.clone()))
            .collect();
        if gone.is_empty() {
            return Ok(0);
        }
        let txn = self.db.begin_write().map_err(db_err)?;
        {
            let mut table = txn.open_table(INDEX).map_err(db_err)?;
            for (id, _) in &gone {
                table.remove(id.as_slice()).map_err(db_err)?;
            }
        }
        let after = records.keys().filter(|id| live.contains(*id));
        self.put_state(&txn, &self.epoch(), false, &manifest(after))?;
        txn.commit().map_err(db_err)?;
        for (id, record) in &gone {
            records.remove(id);
            self.delete_fragments(record);
        }
        Ok(gone.len())
    }

    /// Read back a saved entry's envelope. `Ok(None)` means the store no
    /// longer holds it because a save removed it after it was collected or
    /// expired (DRA-0072). That isn't lost mail, unlike an `Err`.
    pub fn read_envelope(&self, entry_id: &[u8; 16]) -> Result<Option<Vec<u8>>, StoreError> {
        let Some(record) = self
            .records
            .lock()
            .expect("records lock")
            .get(entry_id)
            .cloned()
        else {
            return Ok(None);
        };
        Ok(Some(self.read_record(entry_id, &record)?.envelope))
    }

    /// Queued mail may have been lost while running (a saved entry failed
    /// to read back): move to a new epoch.
    pub fn advance_epoch(&self) -> Result<Epoch, StoreError> {
        let next = {
            let mut epoch = self.epoch.lock().expect("epoch lock");
            epoch.number += 1;
            *epoch
        };
        self.write_state(&next, false)?;
        Ok(next)
    }

    pub fn epoch(&self) -> Epoch {
        *self.epoch.lock().expect("epoch lock")
    }

    /// Record that this run ended with every queued entry saved, so the
    /// next start keeps the same epoch.
    pub fn mark_clean_shutdown(&self) -> Result<(), StoreError> {
        let epoch = self.epoch();
        self.write_state(&epoch, true)
    }

    pub fn stored_count(&self) -> usize {
        self.records.lock().expect("records lock").len()
    }
}
