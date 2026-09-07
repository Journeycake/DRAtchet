//! The encrypted local database itself: a thin, generic encrypted
//! key-value layer over `redb` (a pure-Rust embedded B-tree store), plus
//! account/ratchet persistence built directly on it. `contacts.rs` and
//! `messages.rs` add their own record types on the same primitives.
//!
//! **Encryption**: every value except the Argon2 salt itself (which can't
//! be encrypted — it's needed to derive the key that would decrypt it) is
//! `nonce || ChaCha20Poly1305(plaintext)`, keyed by a 32-byte key derived
//! from the caller's passphrase via Argon2id. A wrong passphrase fails
//! cleanly (AEAD tag mismatch on the KDF check value, checked once at
//! `open()` time) rather than silently producing garbage.

use std::path::Path;

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
const ACCOUNT_KEY: &str = "account";

const NONCE_LEN: usize = 12;

pub struct Db {
    pub(crate) database: Database,
    key: Zeroizing<[u8; 32]>,
}

impl Db {
    /// Create a brand-new encrypted database at `path`, deriving its key
    /// from `passphrase` via a freshly generated salt. Errors if a database
    /// already exists at `path` — use [`Db::open`] for that.
    pub fn create(path: impl AsRef<Path>, passphrase: &str) -> Result<Self> {
        let database = Database::create(path)?;

        let salt = SaltString::generate(&mut OsRng);
        let key = derive_key(passphrase, salt.as_str())?;

        let write_txn = database.begin_write()?;
        {
            let mut table = write_txn.open_table(RECORDS)?;
            table.insert(SALT_KEY, salt.as_str().as_bytes())?;
        }
        write_txn.commit()?;

        let db = Db { database, key };
        db.put_encrypted(KDF_CHECK_KEY, KDF_CHECK_PLAINTEXT)?;
        Ok(db)
    }

    /// Open an existing encrypted database at `path`, deriving its key from
    /// `passphrase` and the salt stored at creation time. Returns
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
        let key = derive_key(passphrase, &salt)?;

        let db = Db { database, key };
        // The KDF check must decrypt to exactly what create() wrote — any
        // AEAD failure here means the passphrase is wrong (or the database
        // is corrupted), and there's no way to tell those apart, which is
        // the honest answer to give the caller.
        let checked = match db.get_encrypted(KDF_CHECK_KEY) {
            Ok(Some(v)) => v,
            Ok(None) => return Err(Error::MalformedRecord("missing KDF check value")),
            Err(Error::DecryptionFailed) => return Err(Error::WrongPassphraseOrCorrupted),
            Err(e) => return Err(e),
        };
        if checked != KDF_CHECK_PLAINTEXT {
            return Err(Error::WrongPassphraseOrCorrupted);
        }
        Ok(db)
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(&*self.key));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .expect("ChaCha20Poly1305 encryption of an unbounded-length plaintext cannot fail");
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    fn decrypt(&self, stored: &[u8]) -> Result<Vec<u8>> {
        if stored.len() < NONCE_LEN {
            return Err(Error::MalformedRecord("stored value shorter than a nonce"));
        }
        let (nonce_bytes, ciphertext) = stored.split_at(NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(AeadKey::from_slice(&*self.key));
        cipher
            .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
            .map_err(|_| Error::DecryptionFailed)
    }

    /// Encrypt `plaintext` and store it under `key`, replacing any existing
    /// value. `pub(crate)` — `contacts.rs`/`messages.rs` build their own
    /// record types on top of this.
    pub(crate) fn put_encrypted(&self, key: &str, plaintext: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(plaintext);
        let write_txn = self.database.begin_write()?;
        {
            let mut table = write_txn.open_table(RECORDS)?;
            table.insert(key, encrypted.as_slice())?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Fetch and decrypt the value stored under `key`, if any.
    pub(crate) fn get_encrypted(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let read_txn = self.database.begin_read()?;
        let table = read_txn.open_table(RECORDS)?;
        match table.get(key)? {
            Some(raw) => Ok(Some(self.decrypt(raw.value())?)),
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
        self.put_encrypted(ACCOUNT_KEY, &account.export())
    }

    pub fn load_account(&self) -> Result<Option<Account>> {
        match self.get_encrypted(ACCOUNT_KEY)? {
            Some(bytes) => Ok(Some(Account::import(&bytes)?)),
            None => Ok(None),
        }
    }

    fn ratchet_key(conversation_id: [u8; 16]) -> String {
        format!("ratchet:{}", hex(&conversation_id))
    }

    pub fn save_ratchet(&self, conversation_id: [u8; 16], ratchet: &RatchetState) -> Result<()> {
        self.put_encrypted(&Self::ratchet_key(conversation_id), &ratchet.export())
    }

    pub fn load_ratchet(&self, conversation_id: [u8; 16]) -> Result<Option<RatchetState>> {
        match self.get_encrypted(&Self::ratchet_key(conversation_id))? {
            Some(bytes) => Ok(Some(RatchetState::import(&bytes)?)),
            None => Ok(None),
        }
    }
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
    use dratchet_core::x3dh;
    use std::fs;

    fn temp_db_path() -> std::path::PathBuf {
        let dir = tempfile::tempdir().unwrap().keep();
        dir.join("test.redb")
    }

    #[test]
    fn create_then_open_round_trips_a_generic_encrypted_value() {
        let path = temp_db_path();
        let db = Db::create(&path, "correct horse battery staple").unwrap();
        db.put_encrypted("k", b"hello world").unwrap();
        assert_eq!(db.get_encrypted("k").unwrap().unwrap(), b"hello world");
        drop(db);

        let db = Db::open(&path, "correct horse battery staple").unwrap();
        assert_eq!(db.get_encrypted("k").unwrap().unwrap(), b"hello world");
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
        db.put_encrypted("thing:1", b"a").unwrap();
        db.put_encrypted("thing:2", b"b").unwrap();
        db.put_encrypted("other:1", b"c").unwrap();

        let mut things = db.keys_with_prefix("thing:").unwrap();
        things.sort();
        assert_eq!(things, vec!["thing:1", "thing:2"]);

        db.delete("thing:1").unwrap();
        assert_eq!(db.get_encrypted("thing:1").unwrap(), None);
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
        db.put_encrypted("probe", secret_message).unwrap();

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
}
