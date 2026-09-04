//! Ties an [`Identity`] together with its X3DH DH identity key and prekeys into
//! something a test (or, later, an application) can drive both sides of a
//! handshake with. Not part of the wire protocol itself — see `x3dh.rs` and
//! `prekey.rs` for that.

use std::collections::HashMap;

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::Result;
use crate::identity::Identity;
use crate::prekey::{OneTimePrekey, OneTimePrekeyPublic, PrekeyBundle, SignedPrekey};

/// Reserved prekey id used to sign the long-term X3DH identity DH key itself,
/// distinct from any real (rotating) signed-prekey id.
pub const IDENTITY_DH_SIGNATURE_ID: u32 = u32::MAX;

pub struct Account {
    pub identity: Identity,
    identity_dh_secret: StaticSecret,
    pub identity_dh_public: PublicKey,
    identity_dh_signature: Vec<u8>,
    pub signed_prekey: SignedPrekey,
    one_time_prekeys: HashMap<u32, OneTimePrekey>,
    next_otp_id: u32,
}

impl Account {
    pub fn generate() -> Result<Self> {
        let identity = Identity::generate()?;
        let identity_dh_secret = StaticSecret::random_from_rng(OsRng);
        let identity_dh_public = PublicKey::from(&identity_dh_secret);
        let identity_dh_signature =
            identity.sign_prekey(IDENTITY_DH_SIGNATURE_ID, identity_dh_public.as_bytes())?;
        let signed_prekey = SignedPrekey::generate(0, &identity)?;

        Ok(Account {
            identity,
            identity_dh_secret,
            identity_dh_public,
            identity_dh_signature,
            signed_prekey,
            one_time_prekeys: HashMap::new(),
            next_otp_id: 0,
        })
    }

    /// Generate and store `count` fresh one-time prekeys, returning their public
    /// halves as they'd be uploaded to a directory (`docs/MESSAGE_SCHEMA.md` §1).
    pub fn generate_one_time_prekeys(&mut self, count: u32) -> Vec<OneTimePrekeyPublic> {
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let id = self.next_otp_id;
            self.next_otp_id += 1;
            let otp = OneTimePrekey::generate(id);
            out.push(otp.public_bundle_entry());
            self.one_time_prekeys.insert(id, otp);
        }
        out
    }

    /// Publish a prekey bundle as an initiator would fetch it. If `include_one_time_prekey`
    /// is true and one is available, its *public* half is included — the secret stays in
    /// local storage until [`Account::take_one_time_prekey_secret`] actually consumes it
    /// while responding to a handshake that names it (`docs/ARCHITECTURE.md` §3.2/§3.4).
    /// `&self`, not `&mut self`: publishing a bundle doesn't itself change local state.
    pub fn publish_bundle(&self, include_one_time_prekey: bool) -> Result<PrekeyBundle> {
        let one_time_prekey = if include_one_time_prekey {
            self.peek_any_one_time_prekey()
        } else {
            None
        };
        Ok(PrekeyBundle {
            identity_public_key: self.identity.export_public_key()?,
            identity_dh_public: self.identity_dh_public,
            identity_dh_signature: self.identity_dh_signature.clone(),
            signed_prekey: self.signed_prekey.public_bundle_entry(),
            one_time_prekey,
        })
    }

    /// Peek at (not remove) one available one-time prekey's public half, as if handing
    /// it to a directory server to publish. The secret stays in local storage — the
    /// account itself doesn't consume it until [`Account::take_one_time_prekey_secret`]
    /// is called while actually responding to a handshake that names it. A real
    /// directory server tracks "already handed out" separately from an account's own
    /// key storage, which this test-support type doesn't attempt to model.
    fn peek_any_one_time_prekey(&self) -> Option<OneTimePrekeyPublic> {
        let otp = self.one_time_prekeys.values().next()?;
        Some(otp.public_bundle_entry())
    }

    /// Look up the secret behind one of our own one-time prekeys by id, consuming it
    /// (removing it from local storage) — used when responding to an X3DH handshake
    /// that names it. Returns `None` if it's already been consumed or never existed.
    pub fn take_one_time_prekey_secret(&mut self, id: u32) -> Option<StaticSecret> {
        self.one_time_prekeys.remove(&id).map(|otp| otp.secret)
    }

    pub fn identity_dh_secret(&self) -> &StaticSecret {
        &self.identity_dh_secret
    }

    pub fn signed_prekey_secret(&self) -> &StaticSecret {
        &self.signed_prekey.secret
    }
}
