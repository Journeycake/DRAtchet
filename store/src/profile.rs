//! This device's own directory-facing profile — the `username#NNNN`
//! chosen at self-registration (`docs/ARCHITECTURE.md` §6.1) and the id
//! of the signed prekey most recently published under it. Distinct from
//! `Account` (the cryptographic identity, which has no username at all —
//! `username`/`discriminator` are purely wire-level addressing metadata,
//! chosen by whoever calls `PublishBundle`). Singleton, same shape as
//! `Db::save_account`/`load_account`.

use serde::{Deserialize, Serialize};

use crate::db::{Db, Scope};
use crate::error::{Error, Result};

const OWN_PROFILE_KEY: &str = "own_profile";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnProfile {
    pub username: String,
    pub discriminator: u16,
    pub signed_prekey_id: u32,
}

impl Db {
    pub fn save_own_profile(&self, profile: &OwnProfile) -> Result<()> {
        let mut bytes = Vec::new();
        ciborium::into_writer(profile, &mut bytes)
            .expect("CBOR encoding of a well-formed struct cannot fail");
        self.put_encrypted(Scope::Identity, OWN_PROFILE_KEY, &bytes)
    }

    pub fn load_own_profile(&self) -> Result<Option<OwnProfile>> {
        match self.get_encrypted(Scope::Identity, OWN_PROFILE_KEY)? {
            Some(bytes) => Ok(Some(ciborium::from_reader(bytes.as_slice()).map_err(
                |_| Error::MalformedRecord("stored own profile is not valid CBOR for this shape"),
            )?)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    fn temp_db() -> Db {
        let dir = tempfile::tempdir().unwrap().keep();
        Db::create(dir.join("test.redb"), "pw").unwrap()
    }

    #[test]
    fn no_profile_before_registration() {
        let db = temp_db();
        assert!(db.load_own_profile().unwrap().is_none());
    }

    #[test]
    fn save_then_load_round_trips() {
        let db = temp_db();
        let profile = OwnProfile {
            username: "alice".into(),
            discriminator: 4821,
            signed_prekey_id: 1,
        };
        db.save_own_profile(&profile).unwrap();

        let loaded = db.load_own_profile().unwrap().unwrap();
        assert_eq!(loaded.username, "alice");
        assert_eq!(loaded.discriminator, 4821);
        assert_eq!(loaded.signed_prekey_id, 1);
    }

    #[test]
    fn saving_again_overwrites_the_previous_profile() {
        let db = temp_db();
        db.save_own_profile(&OwnProfile {
            username: "alice".into(),
            discriminator: 4821,
            signed_prekey_id: 1,
        })
        .unwrap();
        db.save_own_profile(&OwnProfile {
            username: "alice2".into(),
            discriminator: 4821,
            signed_prekey_id: 2,
        })
        .unwrap();

        let loaded = db.load_own_profile().unwrap().unwrap();
        assert_eq!(loaded.username, "alice2");
        assert_eq!(loaded.signed_prekey_id, 2);
    }
}
