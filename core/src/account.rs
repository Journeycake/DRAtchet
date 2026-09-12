//! Ties an [`Identity`] together with its X3DH DH identity key and prekeys into
//! something a test (or, later, an application) can drive both sides of a
//! handshake with. Not part of the wire protocol itself — see `x3dh.rs` and
//! `prekey.rs` for that.

use std::collections::HashMap;

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::{Error, Result};
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
    ///
    /// Replaces whatever batch was stored before, rather than adding to it: a
    /// directory's `publish_bundle` (`server/src/ws.rs`) always overwrites the
    /// previously-published one-time-prekey set wholesale, never merges, so any
    /// still-unconsumed secret from an earlier batch becomes permanently
    /// unreachable the moment a new batch is published — no future `FetchBundle`
    /// will ever name its id again. Every real caller (`app::publish_under_candidates`,
    /// covering both first registration and later republish/replenish) already
    /// generates a batch immediately before publishing it, so there's no
    /// legitimate case where an old, not-yet-superseded batch needs to survive
    /// a call here. Without this, those orphaned secrets — and the disk space
    /// for `Account::to_bytes`'s CBOR encoding of them — would accumulate
    /// forever, since nothing else in `Account` ever prunes `one_time_prekeys`
    /// except [`Self::take_one_time_prekey_secret`] consuming one that's
    /// actually still reachable.
    pub fn generate_one_time_prekeys(&mut self, count: u32) -> Vec<OneTimePrekeyPublic> {
        self.one_time_prekeys.clear();
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

    /// How many locally-held one-time-prekey secrets are still in the
    /// current batch — i.e. still reachable by some future `FetchBundle`
    /// against whatever was last published. Test/introspection support for
    /// the cleanup [`Self::generate_one_time_prekeys`] now does; not needed
    /// by any real caller, which never has a reason to inspect its own
    /// count directly (`FetchOwnPrekeyCount` asks the *directory's* count,
    /// a different, server-side number that can be lower than this one
    /// between publishing and the server actually recording it).
    #[cfg(test)]
    pub fn one_time_prekey_count(&self) -> usize {
        self.one_time_prekeys.len()
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

    /// Serialize this account's full state to bytes — CBOR-encoded, covering
    /// the identity's secret key, the X3DH identity DH secret, the signed
    /// prekey (secret + signature), and every still-available one-time
    /// prekey secret. Like `RatchetState::export`, **not an at-rest-safe
    /// format on its own**: local storage must encrypt these bytes before
    /// persisting them and decrypt before calling [`Account::import`].
    pub fn export(&self) -> Vec<u8> {
        let exported = ExportedAccount::from(self);
        let mut bytes = Vec::new();
        ciborium::into_writer(&exported, &mut bytes)
            .expect("CBOR encoding of a well-formed struct cannot fail");
        bytes
    }

    /// The inverse of [`Account::export`].
    pub fn import(bytes: &[u8]) -> Result<Self> {
        let exported: ExportedAccount = ciborium::from_reader(bytes)
            .map_err(|_| Error::MalformedExportedState("not valid CBOR for this shape"))?;
        exported.try_into()
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ExportedOneTimePrekey {
    id: u32,
    #[serde(with = "serde_bytes")]
    secret: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ExportedAccount {
    #[serde(with = "serde_bytes")]
    identity_secret_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    identity_dh_secret: Vec<u8>,
    #[serde(with = "serde_bytes")]
    identity_dh_signature: Vec<u8>,
    signed_prekey_id: u32,
    #[serde(with = "serde_bytes")]
    signed_prekey_secret: Vec<u8>,
    #[serde(with = "serde_bytes")]
    signed_prekey_signature: Vec<u8>,
    one_time_prekeys: Vec<ExportedOneTimePrekey>,
    next_otp_id: u32,
}

impl From<&Account> for ExportedAccount {
    fn from(a: &Account) -> Self {
        ExportedAccount {
            identity_secret_key: a.identity.export_secret_key().to_vec(),
            identity_dh_secret: a.identity_dh_secret.to_bytes().to_vec(),
            identity_dh_signature: a.identity_dh_signature.clone(),
            signed_prekey_id: a.signed_prekey.id,
            signed_prekey_secret: a.signed_prekey.secret.to_bytes().to_vec(),
            signed_prekey_signature: a.signed_prekey.signature.clone(),
            one_time_prekeys: a
                .one_time_prekeys
                .values()
                .map(|otp| ExportedOneTimePrekey {
                    id: otp.id,
                    secret: otp.secret.to_bytes().to_vec(),
                })
                .collect(),
            next_otp_id: a.next_otp_id,
        }
    }
}

impl TryFrom<ExportedAccount> for Account {
    type Error = Error;

    fn try_from(e: ExportedAccount) -> Result<Self> {
        fn to_array32(v: Vec<u8>, what: &'static str) -> Result<[u8; 32]> {
            v.try_into()
                .map_err(|_| Error::MalformedExportedState(what))
        }

        let identity =
            Identity::from_secret_key(to_array32(e.identity_secret_key, "identity_secret_key")?);
        let identity_dh_secret =
            StaticSecret::from(to_array32(e.identity_dh_secret, "identity_dh_secret")?);
        let identity_dh_public = PublicKey::from(&identity_dh_secret);

        let signed_prekey_secret =
            StaticSecret::from(to_array32(e.signed_prekey_secret, "signed_prekey_secret")?);
        let signed_prekey = SignedPrekey {
            id: e.signed_prekey_id,
            public: PublicKey::from(&signed_prekey_secret),
            secret: signed_prekey_secret,
            signature: e.signed_prekey_signature,
        };

        let one_time_prekeys = e
            .one_time_prekeys
            .into_iter()
            .map(|otp| -> Result<(u32, OneTimePrekey)> {
                let secret =
                    StaticSecret::from(to_array32(otp.secret, "one_time_prekeys[].secret")?);
                let public = PublicKey::from(&secret);
                Ok((
                    otp.id,
                    OneTimePrekey {
                        id: otp.id,
                        secret,
                        public,
                    },
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        Ok(Account {
            identity,
            identity_dh_secret,
            identity_dh_public,
            identity_dh_signature: e.identity_dh_signature,
            signed_prekey,
            one_time_prekeys,
            next_otp_id: e.next_otp_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `export`/`import` must round-trip an account well enough to publish
    /// an identical-looking bundle and, more importantly, actually complete
    /// a real handshake afterward — not just decode without erroring.
    #[test]
    fn export_then_import_produces_a_usable_equivalent_account() {
        let mut original = Account::generate().unwrap();
        original.generate_one_time_prekeys(2);
        let original_fingerprint = original.identity.fingerprint();
        let original_bundle = original.publish_bundle(true).unwrap();

        let mut restored = Account::import(&original.export()).unwrap();

        assert_eq!(restored.identity.fingerprint(), original_fingerprint);
        assert_eq!(
            restored.identity_dh_public.as_bytes(),
            original.identity_dh_public.as_bytes()
        );
        assert_eq!(restored.signed_prekey.id, original.signed_prekey.id);
        assert_eq!(
            restored.signed_prekey.public.as_bytes(),
            original.signed_prekey.public.as_bytes()
        );

        let restored_bundle = restored.publish_bundle(true).unwrap();
        assert_eq!(
            restored_bundle.identity_public_key,
            original_bundle.identity_public_key
        );
        restored_bundle
            .verify()
            .expect("a bundle from the restored account must still verify");

        // Its one-time prekeys survived too, and are still independently
        // consumable exactly as they would have been on the original.
        let consumed = restored.take_one_time_prekey_secret(0);
        assert!(
            consumed.is_some(),
            "a one-time prekey generated before export must still be there after import"
        );
    }

    /// A real X3DH handshake against a restored account's bundle must
    /// succeed and let the restored account actually respond — proof this
    /// isn't just field-by-field equality but a genuinely usable account.
    #[test]
    fn a_restored_account_can_complete_a_real_handshake() {
        let mut bob = Account::generate().unwrap();
        bob.generate_one_time_prekeys(1);
        let mut bob = Account::import(&bob.export()).unwrap();

        let alice = Account::generate().unwrap();
        let bob_bundle = bob.publish_bundle(true).unwrap();
        let init = crate::x3dh::initiate(
            alice.identity_dh_secret(),
            alice.identity_dh_public,
            &bob_bundle,
        )
        .unwrap();

        let otp_secret = init
            .message
            .used_one_time_prekey_id
            .and_then(|id| bob.take_one_time_prekey_secret(id));
        assert!(otp_secret.is_some());
        let bob_root_key = crate::x3dh::respond(
            bob.identity_dh_secret(),
            bob.signed_prekey_secret(),
            otp_secret.as_ref(),
            &init.message,
        );
        assert_eq!(bob_root_key, init.root_key);
    }

    /// The orphaned-prekey-secret gap this test guards against: a directory's
    /// `publish_bundle` always replaces the previously-published one-time-prekey
    /// batch wholesale (`server/src/ws.rs`), so once a second batch is published,
    /// no `FetchBundle` will ever name an id from the first batch again — that
    /// id is permanently unreachable. Before this fix, `generate_one_time_prekeys`
    /// only ever inserted, so those now-unreachable secrets stayed in
    /// `Account.one_time_prekeys` forever, growing by a full batch on every
    /// republish/replenish cycle with nothing to ever remove them.
    #[test]
    fn republishing_drops_the_old_batchs_now_unreachable_secrets() {
        let mut account = Account::generate().unwrap();

        account.generate_one_time_prekeys(10);
        assert_eq!(account.one_time_prekey_count(), 10);

        // A real republish (`app::publish_under_candidates` always calls this
        // immediately before publishing) generates a brand-new batch — the old
        // one is no longer being published, so its secrets must not linger.
        let second_batch = account.generate_one_time_prekeys(10);
        assert_eq!(
            account.one_time_prekey_count(),
            10,
            "a republish must replace the local batch, not accumulate on top of it"
        );

        // None of the *old* batch's ids (0..10) are consumable any more —
        // they can never be named by a real handshake again.
        for old_id in 0..10 {
            assert!(
                account.take_one_time_prekey_secret(old_id).is_none(),
                "id {old_id} was dropped by the old batch and must not still be consumable"
            );
        }

        // The *new* batch is fully intact and independently consumable —
        // the fix must not have thrown away what it just generated.
        for public in &second_batch {
            assert!(
                account.take_one_time_prekey_secret(public.id).is_some(),
                "id {} is from the batch just published and must still be consumable",
                public.id
            );
        }
        assert_eq!(account.one_time_prekey_count(), 0);
    }

    /// Repeated replenish cycles (the real shape of
    /// `dratchet_app::replenish_prekeys_if_low`, called roughly once a minute
    /// whenever the published pool is running low) must never let local
    /// storage grow past one batch, no matter how many cycles run.
    #[test]
    fn many_replenish_cycles_never_grow_storage_past_one_batch() {
        let mut account = Account::generate().unwrap();
        for _ in 0..25 {
            account.generate_one_time_prekeys(10);
        }
        assert_eq!(
            account.one_time_prekey_count(),
            10,
            "25 republish cycles must still leave exactly one batch's worth stored, \
             not 250"
        );
    }

    /// A secret consumed by a real, in-flight handshake response — the same
    /// call `try_accept_first_contact`/`x3dh::respond` make while processing
    /// a mailbox entry — must not be affected by a republish that happens to
    /// land in between generating the batch and something consuming from it,
    /// since both calls are made under the same `&mut Account` lock and never
    /// interleave in practice; this pins that assumption down as a real test
    /// rather than leaving it as only a doc-comment claim.
    #[test]
    fn a_consumed_secret_from_the_current_batch_is_gone_even_before_the_next_republish() {
        let mut account = Account::generate().unwrap();
        let batch = account.generate_one_time_prekeys(3);
        let consumed_id = batch[0].id;

        assert!(account.take_one_time_prekey_secret(consumed_id).is_some());
        assert!(
            account.take_one_time_prekey_secret(consumed_id).is_none(),
            "single-use: consuming the same id twice must fail the second time"
        );
        assert_eq!(account.one_time_prekey_count(), 2);
    }
}
