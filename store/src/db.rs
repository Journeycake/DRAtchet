//! The encrypted local database itself: a thin, generic encrypted
//! key-value layer over `redb` (a pure-Rust embedded B-tree store), plus
//! account/ratchet persistence built directly on it. `contacts.rs` and
//! `messages.rs` add their own record types on the same primitives.
//!
//! **Encryption — envelope, not one flat key**: every value is `nonce ||
//! ChaCha20Poly1305(plaintext)`, but *which* 32-byte key encrypts it
//! depends on its [`Scope`]. A master key, derived from the caller's
//! passphrase via Argon2id exactly as before, never encrypts application
//! data directly — it only wraps three independently-generated data
//! encryption keys (DEKs), one per scope, themselves stored (wrapped)
//! alongside the salt. This split exists for one reason: `quick_wipe`
//! (`docs/ARCHITECTURE.md` §11.9) has to be able to destroy the key
//! protecting message/ratchet content without touching the key protecting
//! the account's identity, and that's only possible if those were already
//! different keys before the wipe is ever triggered. A wrong passphrase
//! still fails cleanly (AEAD tag mismatch on the KDF check value, checked
//! once at `open()` time, itself encrypted directly with the master key
//! rather than any DEK) rather than silently producing garbage.

use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::RwLock;

use argon2::password_hash::SaltString;
use argon2::Argon2;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key as AeadKey, Nonce};
use dratchet_core::account::Account;
use dratchet_core::ratchet::RatchetState;
use rand_core::{OsRng, RngCore};
use redb::{Database, TableDefinition};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub(crate) const RECORDS: TableDefinition<&str, &[u8]> = TableDefinition::new("records");

const SALT_KEY: &str = "__salt__";
const KDF_CHECK_KEY: &str = "__kdf_check__";
const KDF_CHECK_PLAINTEXT: &[u8] = b"dratchet-store-v1";
const IDENTITY_DEK_KEY: &str = "__identity_dek__";
const CONTACTS_DEK_KEY: &str = "__contacts_dek__";
const CONTENT_DEK_KEY: &str = "__content_dek__";
const ACCOUNT_KEY: &str = "account";

const NONCE_LEN: usize = 12;
const DEK_LEN: usize = 32;

/// Which data-encryption key protects a given record. `Content` covers
/// both messages and ratchet/session state — `docs/ARCHITECTURE.md` §11.9's
/// quick wipe treats those as one unit (both are "this conversation's
/// history", one is just the key material rather than the text), while
/// `Identity` (the account) and `Contacts` (the contact list, including
/// verification state and routing ids) each need to survive a quick wipe
/// independently of it.
#[derive(Clone, Copy)]
pub(crate) enum Scope {
    Identity,
    Contacts,
    Content,
}

pub struct Db {
    pub(crate) database: Database,
    master_key: Zeroizing<[u8; 32]>,
    identity_key: Zeroizing<[u8; 32]>,
    contacts_key: Zeroizing<[u8; 32]>,
    content_key: RwLock<Zeroizing<[u8; 32]>>,
    // In-memory only, reset to 0 on every `create`/`open` — see
    // `messages.rs`'s module doc for why that's fine: it only ever needs
    // to break ties *within* the same `now_unix()` second, and a same-
    // second collision spanning an app restart isn't a real scenario.
    pub(crate) message_sequence: AtomicU64,
}

impl Db {
    /// Create a brand-new encrypted database at `path`, deriving its
    /// master key from `passphrase` via a freshly generated salt, then
    /// generating and wrapping a fresh, independent DEK per [`Scope`].
    /// Errors if a database already exists at `path` — use [`Db::open`]
    /// for that.
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let database = Database::create(path)?;

        let salt = SaltString::generate(&mut OsRng);
        let master_key = derive_key(passphrase, salt.as_str())?;

        let write_txn = database.begin_write()?;
        {
            let mut table = write_txn.open_table(RECORDS)?;
            table.insert(SALT_KEY, salt.as_str().as_bytes())?;
        }
        write_txn.commit()?;

        write_master_encrypted(&database, &master_key, KDF_CHECK_KEY, KDF_CHECK_PLAINTEXT)?;
        let identity_key = random_key();
        let contacts_key = random_key();
        let content_key = random_key();
        write_master_encrypted(&database, &master_key, IDENTITY_DEK_KEY, &*identity_key)?;
        write_master_encrypted(&database, &master_key, CONTACTS_DEK_KEY, &*contacts_key)?;
        write_master_encrypted(&database, &master_key, CONTENT_DEK_KEY, &*content_key)?;

        Ok(Db {
            database,
            master_key,
            identity_key,
            contacts_key,
            content_key: RwLock::new(content_key),
            message_sequence: AtomicU64::new(0),
        })
    }

    /// Open an existing encrypted database at `path`, deriving its master
    /// key from `passphrase` and the salt stored at creation time, then
    /// unwrapping the three scope DEKs. Returns
    /// [`Error::WrongPassphraseOrCorrupted`] if the passphrase doesn't
    /// match — checked once, up front, against a known-plaintext value,
    /// rather than surfacing as a confusing decrypt failure deep in some
    /// later, unrelated call.
    pub fn open(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let database = Database::open(path)?;

        let salt = {
            let read_txn = database.begin_read()?;
            let table = read_txn.open_table(RECORDS)?;
            let raw = table.get(SALT_KEY)?.ok_or(Error::MalformedRecord(
                "missing salt — not a dratchet-store database",
            ))?;
            String::from_utf8(raw.value().to_vec())
                .map_err(|_| Error::MalformedRecord("salt is not valid UTF-8"))?
        };
        let master_key = derive_key(passphrase, &salt)?;

        // The KDF check must decrypt to exactly what create() wrote — any
        // AEAD failure here means the passphrase is wrong (or the database
        // is corrupted), and there's no way to tell those apart, which is
        // the honest answer to give the caller. Checked before touching any
        // DEK, so a wrong passphrase never gets as far as a confusing
        // "missing wrapped DEK" error instead.
        let checked = match read_master_encrypted(&database, &master_key, KDF_CHECK_KEY) {
            Ok(Some(v)) => v,
            Ok(None) => return Err(Error::MalformedRecord("missing KDF check value")),
            Err(Error::DecryptionFailed) => return Err(Error::WrongPassphraseOrCorrupted),
            Err(e) => return Err(e),
        };
        if checked != KDF_CHECK_PLAINTEXT {
            return Err(Error::WrongPassphraseOrCorrupted);
        }

        let identity_key = unwrap_dek(&database, &master_key, IDENTITY_DEK_KEY)?;
        let contacts_key = unwrap_dek(&database, &master_key, CONTACTS_DEK_KEY)?;
        let content_key = unwrap_dek(&database, &master_key, CONTENT_DEK_KEY)?;

        Ok(Db {
            database,
            master_key,
            identity_key,
            contacts_key,
            content_key: RwLock::new(content_key),
            message_sequence: AtomicU64::new(0),
        })
    }

    /// Encrypt `plaintext` under `scope`'s DEK and store it under `key`,
    /// replacing any existing value. `pub(crate)` — `contacts.rs`/
    /// `messages.rs` build their own record types on top of this.
    pub(crate) fn put_encrypted(&self, scope: Scope, key: &str, plaintext: &[u8]) -> Result<()> {
        let encrypted = match scope {
            Scope::Identity => encrypt(&self.identity_key, plaintext),
            Scope::Contacts => encrypt(&self.contacts_key, plaintext),
            Scope::Content => encrypt(&self.content_key.read().unwrap(), plaintext),
        };
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(RECORDS)?;
            table.insert(key, encrypted.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Fetch and decrypt (under `scope`'s DEK) the value stored under
    /// `key`, if any.
    pub(crate) fn get_encrypted(&self, scope: Scope, key: &str) -> Result<Option<Vec<u8>>> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(RECORDS)?;
        match table.get(key)? {
            Some(raw) => {
                let plaintext = match scope {
                    Scope::Identity => decrypt(&self.identity_key, raw.value())?,
                    Scope::Contacts => decrypt(&self.contacts_key, raw.value())?,
                    Scope::Content => decrypt(&self.content_key.read().unwrap(), raw.value())?,
                };
                Ok(Some(plaintext))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn delete(&self, key: &str) -> Result<()> {
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(RECORDS)?;
            table.remove(key)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// All keys currently stored whose name starts with `prefix` — a full
    /// table scan filtered in application code rather than a computed
    /// range-bound, which is the right trade for a single-user local
    /// database (not expected to hold more than a modest number of
    /// contacts/messages) over the subtlety of getting prefix-range byte
    /// arithmetic exactly right.
    pub(crate) fn keys_with_prefix(&self, prefix: &str) -> Result<Vec<String>> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(RECORDS)?;
        let mut out = Vec::new();
        for entry in table.range::<&str>(..)? {
            let (k, _) = entry?;
            if k.value().starts_with(prefix) {
                out.push(k.value().to_string());
            }
        }
        Ok(out)
    }

    pub fn save_account(&self, account: &Account) -> Result<()> {
        self.put_encrypted(Scope::Identity, ACCOUNT_KEY, &account.export())
    }

    pub fn load_account(&self) -> Result<Option<Account>> {
        match self.get_encrypted(Scope::Identity, ACCOUNT_KEY)? {
            Some(bytes) => Ok(Some(Account::import(&bytes)?)),
            None => Ok(None),
        }
    }

    pub(crate) fn ratchet_key(conversation_id: [u8; 16]) -> String {
        format!("ratchet:{}", hex(&conversation_id))
    }

    pub fn save_ratchet(&self, conversation_id: [u8; 16], ratchet: &RatchetState) -> Result<()> {
        self.put_encrypted(
            Scope::Content,
            &Self::ratchet_key(conversation_id),
            &ratchet.export(),
        )
    }

    pub fn load_ratchet(&self, conversation_id: [u8; 16]) -> Result<Option<RatchetState>> {
        match self.get_encrypted(Scope::Content, &Self::ratchet_key(conversation_id))? {
            Some(bytes) => Ok(Some(RatchetState::import(&bytes)?)),
            None => Ok(None),
        }
    }

    /// `docs/ARCHITECTURE.md` §11.9's **quick wipe**: genuinely (not just a
    /// `DELETE`) crypto-shreds every locally-stored message and every
    /// cached ratchet/session state. "Crypto-shred" here means what the
    /// doc insists it has to mean: the `Content`-scope DEK that protected
    /// every one of those records is destroyed — replaced with a freshly
    /// generated one, both in memory and in its wrapped on-disk form — so
    /// even a forensic recovery of already-freed raw bytes from this file
    /// can never be decrypted again, regardless of whether the records
    /// were also individually deleted (which they are, here, as
    /// belt-and-suspenders — a wipe that only threw away the key but left
    /// old ciphertext readable-if-you-had-the-key would be a strange thing
    /// to ship even though it would already be cryptographically safe).
    ///
    /// The account's identity (`Scope::Identity`) and contact list
    /// (`Scope::Contacts`) are untouched — the account keeps functioning
    /// afterward, per the doc's design. One real consequence, stated
    /// plainly rather than hidden: since a conversation's `RatchetState`
    /// is gone, resuming that conversation needs a fresh session
    /// established with that contact — `dratchet-app`'s own module doc
    /// already names starting a session from scratch as a currently-
    /// unimplemented gap, so a contact wiped this way stays unusable for
    /// new messages until that's built, same as it would be for a
    /// brand-new contact today.
    ///
    /// Returns how many message/ratchet records were removed.
    pub fn quick_wipe(&self) -> Result<usize> {
        let mut removed = 0;
        for key in self.keys_with_prefix("message:")? {
            self.delete(&key)?;
            removed += 1;
        }
        for key in self.keys_with_prefix("ratchet:")? {
            self.delete(&key)?;
            removed += 1;
        }

        let fresh_content_key = random_key();
        write_master_encrypted(
            &self.database,
            &self.master_key,
            CONTENT_DEK_KEY,
            &*fresh_content_key,
        )?;
        *self.content_key.write().unwrap() = fresh_content_key;

        Ok(removed)
    }

    /// `docs/ARCHITECTURE.md` §11.9's **full wipe**: everything
    /// [`Db::quick_wipe`] leaves behind — the account's identity key, the
    /// contact list, and the salt/wrapped-DEK records themselves — is
    /// deleted too, so the entire file becomes permanently unreadable
    /// (opening it again fails cleanly with a "missing salt" error, the
    /// same error an unrelated/corrupted file produces, never a
    /// resurrected old passphrase prompt) and every future session for
    /// this path has to start from a freshly generated identity.
    /// Irreversible.
    ///
    /// Deliberately does **not** consume `self` or invalidate this handle
    /// at the type level — matching every other `Db` method's `&self`
    /// shape rather than a one-off exception. The caller must still treat
    /// this `Db` as finished after calling this: any further write from
    /// this same live handle would succeed in memory but never be
    /// recoverable (there's no salt left to derive a key to read it back
    /// with next time the file is opened). `dratchet_app::full_wipe`
    /// documents and enforces the intended caller shape (drop this
    /// handle, then create a fresh one) at that layer.
    pub fn full_wipe(&self) -> Result<()> {
        for key in self.keys_with_prefix("")? {
            self.delete(&key)?;
        }
        Ok(())
    }
}

fn random_key() -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; DEK_LEN]);
    OsRng.fill_bytes(&mut *key);
    key
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .expect("ChaCha20Poly1305 encryption of an unbounded-length plaintext cannot fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

fn decrypt(key: &[u8; 32], stored: &[u8]) -> Result<Vec<u8>> {
    if stored.len() < NONCE_LEN {
        return Err(Error::MalformedRecord("stored value shorter than a nonce"));
    }
    let (nonce_bytes, ciphertext) = stored.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| Error::DecryptionFailed)
}

/// Encrypt `plaintext` directly under the master key (never a scope DEK)
/// and write it to `key` in `database`, in its own write transaction. Used
/// only for the salt-adjacent bootstrap records (KDF check, wrapped DEKs)
/// that have to exist before a full [`Db`] — and its DEKs — can be
/// constructed.
fn write_master_encrypted(
    database: &Database,
    master_key: &Zeroizing<[u8; 32]>,
    key: &str,
    plaintext: &[u8],
) -> Result<()> {
    let encrypted = encrypt(master_key, plaintext);
    let write_txn = database.begin_write()?;
    {
        let mut table = write_txn.open_table(RECORDS)?;
        table.insert(key, encrypted.as_slice())?;
    }
    write_txn.commit()?;
    Ok(())
}

/// The `write_master_encrypted` counterpart, read side.
fn read_master_encrypted(
    database: &Database,
    master_key: &Zeroizing<[u8; 32]>,
    key: &str,
) -> Result<Option<Vec<u8>>> {
    let read_txn = database.begin_read()?;
    let table = read_txn.open_table(RECORDS)?;
    match table.get(key)? {
        Some(raw) => Ok(Some(decrypt(master_key, raw.value())?)),
        None => Ok(None),
    }
}

/// Unwrap (decrypt with the master key) the DEK stored under `key` —
/// `create()` having just written it, or `open()` reading one back.
fn unwrap_dek(
    database: &Database,
    master_key: &Zeroizing<[u8; 32]>,
    key: &str,
) -> Result<Zeroizing<[u8; 32]>> {
    let wrapped =
        read_master_encrypted(database, master_key, key)?.ok_or(Error::MalformedRecord(
            "missing wrapped data-encryption key — not a dratchet-store database",
        ))?;
    let array: [u8; DEK_LEN] = wrapped
        .as_slice()
        .try_into()
        .map_err(|_| Error::MalformedRecord("wrapped data-encryption key has the wrong length"))?;
    Ok(Zeroizing::new(array))
}

fn derive_key(passphrase: &str, salt: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt.as_bytes(), &mut *key)
        .map_err(|e| Error::PassphraseHash(e.to_string()))?;
    Ok(key)
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contacts::{Contact, VerificationState};
    use crate::messages::Message;
    use dratchet_core::x3dh;
    use std::fs;

    fn temp_db_path() -> std::path::PathBuf {
        let dir = tempfile::tempdir().unwrap().keep();
        dir.join("test.redb")
    }

    /// Bypasses scope decryption entirely — reads whatever raw bytes are
    /// actually sitting in the table under `key`. Used only to observe
    /// that `quick_wipe` really did rewrite the wrapped content DEK
    /// record, not merely delete message/ratchet entries.
    fn raw_record(db: &Db, key: &str) -> Vec<u8> {
        let read_txn = db.database.begin_read().unwrap();
        let table = read_txn.open_table(RECORDS).unwrap();
        table.get(key).unwrap().unwrap().value().to_vec()
    }

    fn sample_contact(fingerprint: u8) -> Contact {
        Contact {
            fingerprint: vec![fingerprint; 32],
            username: Some("alice".to_string()),
            discriminator: Some(1234),
            verification_state: VerificationState::Verified,
            mailbox_id: vec![0xAB; 16],
            created_at: 0,
            local_routing_id: vec![0xCD; 32],
            peer_routing_id: None,
            wipe_ask_before_delete: false,
            peer_wipe_ask_before_delete: None,
            wipe_include_session: false,
            peer_wipe_include_session: None,
            wipe_request_pending: false,
        }
    }

    fn sample_ratchet(conversation_id: [u8; 16]) -> RatchetState {
        let responder_secret = x25519_dalek::StaticSecret::from([3u8; 32]);
        let responder_public = x25519_dalek::PublicKey::from(&responder_secret);
        RatchetState::init_as_initiator(
            conversation_id,
            [4u8; 32],
            responder_public,
            dratchet_core::ratchet::DEFAULT_MAX_SKIP,
        )
        .unwrap()
    }

    #[test]
    fn create_then_open_round_trips_a_generic_encrypted_value() {
        let path = temp_db_path();
        let db = Db::create(&path, "correct horse battery staple").unwrap();
        db.put_encrypted(Scope::Content, "k", b"hello world")
            .unwrap();
        assert_eq!(
            db.get_encrypted(Scope::Content, "k").unwrap().unwrap(),
            b"hello world"
        );
        drop(db);

        let db = Db::open(&path, "correct horse battery staple").unwrap();
        assert_eq!(
            db.get_encrypted(Scope::Content, "k").unwrap().unwrap(),
            b"hello world"
        );
    }

    #[test]
    fn opening_with_the_wrong_passphrase_fails_cleanly() {
        let path = temp_db_path();
        Db::create(&path, "the right passphrase").unwrap();

        let result = Db::open(&path, "definitely the wrong passphrase");
        match result {
            Err(Error::WrongPassphraseOrCorrupted) => {}
            Err(other) => panic!("expected WrongPassphraseOrCorrupted, got {other}"),
            Ok(_) => panic!("opening with the wrong passphrase must not succeed"),
        }
    }

    #[test]
    fn delete_and_keys_with_prefix_work() {
        let path = temp_db_path();
        let db = Db::create(&path, "pw").unwrap();
        db.put_encrypted(Scope::Content, "thing:1", b"a").unwrap();
        db.put_encrypted(Scope::Content, "thing:2", b"b").unwrap();
        db.put_encrypted(Scope::Content, "other:1", b"c").unwrap();

        let mut things = db.keys_with_prefix("thing:").unwrap();
        things.sort();
        assert_eq!(things, vec!["thing:1", "thing:2"]);

        db.delete("thing:1").unwrap();
        assert_eq!(db.get_encrypted(Scope::Content, "thing:1").unwrap(), None);
        assert_eq!(db.keys_with_prefix("thing:").unwrap(), vec!["thing:2"]);
    }

    #[test]
    fn account_round_trips_and_is_still_usable_for_a_real_handshake() {
        let path = temp_db_path();
        let db = Db::create(&path, "pw").unwrap();

        let mut original = Account::generate().unwrap();
        original.generate_one_time_prekeys(1);
        db.save_account(&original).unwrap();

        let mut restored = db.load_account().unwrap().expect("account should be there");
        assert_eq!(
            restored.identity.fingerprint(),
            original.identity.fingerprint()
        );

        // A real handshake against the restored account, not just field
        // equality.
        let alice = Account::generate().unwrap();
        let bob_bundle = restored.publish_bundle(true).unwrap();
        let init = x3dh::initiate(
            alice.identity_dh_secret(),
            alice.identity_dh_public,
            &bob_bundle,
        )
        .unwrap();
        let otp = init
            .message
            .used_one_time_prekey_id
            .and_then(|id| restored.take_one_time_prekey_secret(id));
        assert!(otp.is_some());
    }

    #[test]
    fn ratchet_state_survives_a_simulated_restart_and_keeps_chatting() {
        let path = temp_db_path();
        let conversation_id = [7u8; 16];

        let db = Db::create(&path, "pw").unwrap();
        let responder_secret = x25519_dalek::StaticSecret::from([2u8; 32]);
        let responder_public = x25519_dalek::PublicKey::from(&responder_secret);
        let mut alice = dratchet_core::ratchet::RatchetState::init_as_initiator(
            conversation_id,
            [1u8; 32],
            responder_public,
            dratchet_core::ratchet::DEFAULT_MAX_SKIP,
        )
        .unwrap();
        let mut bob = dratchet_core::ratchet::RatchetState::init_as_responder(
            conversation_id,
            [1u8; 32],
            responder_secret,
            dratchet_core::ratchet::DEFAULT_MAX_SKIP,
        )
        .unwrap();

        let e0 = alice.encrypt_payload(0, b"before restart").unwrap();
        let (_, content) = bob.decrypt_payload(&e0).unwrap();
        assert_eq!(content, b"before restart");

        db.save_ratchet(conversation_id, &bob).unwrap();
        drop(bob);
        // Shadowing `db` below does not drop this handle early — redb holds
        // a file lock for as long as the `Database` is alive, so it has to
        // be dropped explicitly before reopening the same path.
        drop(db);

        // "Restart": reopen the database and reload the ratchet.
        let db = Db::open(&path, "pw").unwrap();
        let mut bob = db.load_ratchet(conversation_id).unwrap().unwrap();

        let e1 = alice.encrypt_payload(0, b"after restart").unwrap();
        let (_, content) = bob.decrypt_payload(&e1).unwrap();
        assert_eq!(content, b"after restart");
    }

    /// Mirrors `server/tests/breach.rs`'s rigor at the local-storage layer:
    /// the raw database file on disk must never contain the plaintext
    /// content or key material that went into it, only ciphertext.
    #[test]
    fn the_raw_database_file_never_contains_plaintext_or_key_material() {
        let path = temp_db_path();
        let db = Db::create(&path, "pw").unwrap();

        let account = Account::generate().unwrap();
        let identity_dh_secret_bytes = account.identity_dh_secret().to_bytes();
        db.save_account(&account).unwrap();

        let secret_message = b"the quick brown fox jumps over the lazy dog, launch codes 1234";
        db.put_encrypted(Scope::Content, "probe", secret_message)
            .unwrap();

        // redb keeps its own in-memory cache; drop the handle so everything
        // is definitely flushed before reading the file back from disk.
        drop(db);

        let raw = fs::read(&path).unwrap();
        assert!(
            !raw.windows(secret_message.len())
                .any(|w| w == secret_message),
            "plaintext was found in the raw database file"
        );
        assert!(
            !raw.windows(32).any(|w| w == identity_dh_secret_bytes),
            "an account's private key material was found in the raw database file"
        );
    }

    #[test]
    fn quick_wipe_erases_messages_and_ratchet_state_but_keeps_identity_and_contacts() {
        let path = temp_db_path();
        let db = Db::create(&path, "pw").unwrap();
        let conv = [9u8; 16];

        let account = Account::generate().unwrap();
        db.save_account(&account).unwrap();
        let contact = sample_contact(1);
        db.save_contact(&contact).unwrap();
        db.save_ratchet(conv, &sample_ratchet(conv)).unwrap();
        db.save_message(
            conv,
            &Message {
                id: vec![1u8; 16],
                sender_is_local: true,
                content: b"gone after a quick wipe".to_vec(),
                timestamp: 100,
                sequence: 0,
                send_n: None,
                delivered: false,
            },
        )
        .unwrap();

        let removed = db.quick_wipe().unwrap();
        assert_eq!(removed, 2, "one message + one ratchet record");

        assert!(
            db.load_account().unwrap().is_some(),
            "identity must survive a quick wipe"
        );
        assert!(
            db.load_contact(&contact.fingerprint).unwrap().is_some(),
            "contacts must survive a quick wipe"
        );
        assert!(
            db.load_ratchet(conv).unwrap().is_none(),
            "ratchet/session state must not survive a quick wipe"
        );
        assert!(
            db.list_messages(conv).unwrap().is_empty(),
            "message history must not survive a quick wipe"
        );
    }

    /// The property that actually makes this a *crypto*-shred rather than
    /// a plain delete: the wrapped content DEK record itself must change,
    /// proving a fresh key was generated and the old one discarded — not
    /// just that the message/ratchet rows were removed from the table.
    #[test]
    fn quick_wipe_rotates_the_content_encryption_key() {
        let path = temp_db_path();
        let db = Db::create(&path, "pw").unwrap();
        let wrapped_before = raw_record(&db, CONTENT_DEK_KEY);

        db.quick_wipe().unwrap();

        let wrapped_after = raw_record(&db, CONTENT_DEK_KEY);
        assert_ne!(
            wrapped_before, wrapped_after,
            "quick_wipe must rotate the content encryption key, not merely delete records"
        );

        // The rotated key has to actually work: a message saved after the
        // wipe must round-trip through a simulated restart.
        let conv = [5u8; 16];
        db.save_message(
            conv,
            &Message {
                id: vec![2u8; 16],
                sender_is_local: true,
                content: b"written after the wipe, under the new key".to_vec(),
                timestamp: 200,
                sequence: 0,
                send_n: None,
                delivered: false,
            },
        )
        .unwrap();
        drop(db);

        let db = Db::open(&path, "pw").unwrap();
        let messages = db.list_messages(conv).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0].content,
            b"written after the wipe, under the new key"
        );
    }

    /// A quick wipe must never touch the *other* scopes' keys — proven the
    /// same way, at the raw wrapped-DEK level, for identity and contacts.
    #[test]
    fn quick_wipe_does_not_rotate_identity_or_contacts_keys() {
        let path = temp_db_path();
        let db = Db::create(&path, "pw").unwrap();
        let identity_before = raw_record(&db, IDENTITY_DEK_KEY);
        let contacts_before = raw_record(&db, CONTACTS_DEK_KEY);

        db.quick_wipe().unwrap();

        assert_eq!(identity_before, raw_record(&db, IDENTITY_DEK_KEY));
        assert_eq!(contacts_before, raw_record(&db, CONTACTS_DEK_KEY));
    }

    #[test]
    fn full_wipe_makes_the_database_permanently_unopenable() {
        let path = temp_db_path();
        let db = Db::create(&path, "pw").unwrap();
        let account = Account::generate().unwrap();
        db.save_account(&account).unwrap();
        db.save_contact(&sample_contact(1)).unwrap();

        db.full_wipe().unwrap();
        drop(db);

        match Db::open(&path, "pw") {
            Err(Error::MalformedRecord(_)) => {}
            Err(other) => panic!("expected a MalformedRecord (missing salt) error, got {other}"),
            Ok(_) => panic!("opening a fully wiped database must not succeed"),
        }

        // And not because the passphrase changed underneath it — no
        // passphrase opens it, which is the whole point.
        match Db::open(&path, "some other passphrase entirely") {
            Err(Error::MalformedRecord(_)) => {}
            Err(other) => panic!("expected a MalformedRecord (missing salt) error, got {other}"),
            Ok(_) => panic!("opening a fully wiped database must not succeed"),
        }
    }

    /// Mirrors `the_raw_database_file_never_contains_plaintext_or_key_material`
    /// for the wipe itself: after a full wipe, none of the wrapped DEK
    /// records exist any more — not just inaccessible, genuinely gone from
    /// the table.
    #[test]
    fn full_wipe_removes_every_wrapped_key_record() {
        let path = temp_db_path();
        let db = Db::create(&path, "pw").unwrap();
        db.full_wipe().unwrap();

        let read_txn = db.database.begin_read().unwrap();
        let table = read_txn.open_table(RECORDS).unwrap();
        for key in [
            SALT_KEY,
            KDF_CHECK_KEY,
            IDENTITY_DEK_KEY,
            CONTACTS_DEK_KEY,
            CONTENT_DEK_KEY,
        ] {
            assert!(
                table.get(key).unwrap().is_none(),
                "{key} must not survive a full wipe"
            );
        }
    }
}
