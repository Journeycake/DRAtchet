//! Penetration-test finding, DRA-0014 (priority 1: unauthorized access to
//! another identity's pending communications; also a targeted
//! denial-of-service), discovered auditing `ws.rs`'s `MailboxWrite`/
//! `MailboxFetch`/`MailboxDelete` handlers directly: none of the three
//! checked that the caller was actually a party to the `mailbox_id` they
//! named — only that *some* identity had authenticated on this connection
//! (`authenticated.ok_or(Error::AuthRequired)?`). The implicit security
//! model is that a `mailbox_id` itself is an unguessable capability (true
//! for the post-transition, routing-id-derived id,
//! `store::routing::compute_mailbox_id` — a genuine shared secret only the
//! two participants ever learn).
//!
//! It is **not** true for `bootstrap_mailbox_id` (`core::x3dh`):
//! deliberately `SHA256("dratchet-x3dh-bootstrap-v1" || recipient_fingerprint)`,
//! so the *intended* recipient's own client can compute it before any
//! relationship exists — but a recipient's identity fingerprint is public
//! (needed for X3DH, discoverable via `FetchBundle`/the username
//! directory), so *anyone* can compute the same id for *any* registered
//! user. `core::x3dh::bootstrap_mailbox_id`'s own doc already accepted a
//! narrower version of this ("a relay can observe someone wrote to this
//! recipient") as a bounded, intentional metadata leak. What it didn't
//! call out, and what this test demonstrates against the pre-fix server,
//! is that the exposure was not limited to the server operator observing
//! metadata — with no ownership check on the handlers themselves, *any
//! other registered user* got full read *and delete* access to a third
//! party's queued first-contact attempts, not just linkability metadata.
//!
//! **Fixed**: `mailbox_id_belongs_to_someone_else` (`server/src/ws.rs`)
//! rejects `MailboxFetch`/`MailboxDelete` with `Error::NotMailboxOwner`
//! whenever the requested id matches a *different* registered identity's
//! `bootstrap_mailbox_id`. `MailboxWrite` is deliberately left
//! unrestricted (first-contact delivery still needs to work), and a
//! post-transition `mailbox_id` is unaffected (see that function's doc).
//!
//! This test proves both the attack and the fix in one place: run against
//! the pre-fix handler it would fail at the "blocked" assertions below and
//! succeed at the vulnerability-demonstrating ones; against the fixed
//! handler (the current state of this branch) it proves the attacker is
//! rejected while the real sender's write and the real victim's own
//! fetch/delete continue to work normally.

mod common;

use common::*;
use dratchet_core::account::Account;
use dratchet_core::identity::fingerprint_of_public_key;
use dratchet_core::x3dh::bootstrap_mailbox_id;
use dratchet_server::protocol::*;

#[tokio::test]
async fn an_uninvolved_third_party_cannot_read_or_delete_another_identitys_pending_first_contact_mail(
) {
    let url = spawn_server().await;

    // The victim publishes a real bundle — the only realistic way an
    // attacker learns a fingerprint to target in the first place, via the
    // ordinary, intended `FetchBundle` directory lookup.
    let (victim, victim_bundle) = fresh_account_and_bundle("victim", 1, 5);
    let mut victim_conn = TestClient::connect(&url).await;
    victim_conn.authenticate(&victim).await;
    victim_conn
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: victim_bundle,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = victim_conn.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);

    // A real sender attempting first contact, and an uninvolved attacker —
    // neither paired with the victim or each other.
    let real_sender = Account::generate().unwrap();
    let mut sender_conn = TestClient::connect(&url).await;
    sender_conn.authenticate(&real_sender).await;

    let attacker = Account::generate().unwrap();
    let mut attacker_conn = TestClient::connect(&url).await;
    attacker_conn.authenticate(&attacker).await;

    // The attacker discovers the victim's fingerprint the ordinary,
    // intended way — a `FetchBundle` directory lookup — then computes the
    // exact same bootstrap mailbox id the real sender's own client would.
    attacker_conn
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "victim".to_string(),
                discriminator: 1,
            },
        )
        .await;
    let (tag, result): (_, BundleResult) = attacker_conn.recv().await;
    assert_eq!(tag, FrameTag::BundleResult);
    let victim_fingerprint = fingerprint_of_public_key(&result.bundle.unwrap().identity_key)
        .as_bytes()
        .to_vec();
    let mailbox_id = bootstrap_mailbox_id(&victim_fingerprint).to_vec();

    // The real sender writes a genuine first-contact attempt to the
    // victim's bootstrap mailbox — exactly what a legitimate client does
    // during pairing, before any routing-id exchange exists. Writes stay
    // unrestricted by design (anyone must be able to initiate contact).
    let real_envelope = b"a real first-contact handshake, opaque ciphertext to the server".to_vec();
    sender_conn
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.clone(),
                envelope: real_envelope.clone(),
                ttl: 60,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = sender_conn.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(
        ack.ok,
        "writing a first-contact attempt must still succeed for anyone"
    );

    // The attacker — who has no relationship with the victim or the real
    // sender beyond an ordinary public directory lookup — tries to fetch
    // the victim's bootstrap mailbox directly. This must now be rejected.
    attacker_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.clone(),
            },
        )
        .await;
    let (tag, err): (_, ErrorFrame) = attacker_conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "FIX VERIFIED: an uninvolved third party's fetch of another identity's bootstrap \
         mailbox must be rejected, not answered with its contents"
    );
    assert!(
        err.message
            .to_lowercase()
            .contains("belongs to a different identity")
            || err.message.to_lowercase().contains("mailbox"),
        "rejection should be attributable to mailbox ownership, got: {}",
        err.message
    );

    // Also try to delete it outright — must be rejected the same way, so
    // the attacker cannot destroy the real sender's pairing attempt either.
    attacker_conn
        .send(
            FrameTag::MailboxDelete,
            &MailboxDelete {
                mailbox_id: mailbox_id.clone(),
                entry_id: vec![0u8; 16],
            },
        )
        .await;
    let (tag, _err): (_, ErrorFrame) = attacker_conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "FIX VERIFIED: an uninvolved third party's delete against another identity's bootstrap \
         mailbox must be rejected"
    );

    // The real victim's own fetch of their own bootstrap mailbox must be
    // completely unaffected — they still see the real sender's entry.
    victim_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.clone(),
            },
        )
        .await;
    let (tag, entries): (_, MailboxEntries) = victim_conn.recv().await;
    assert_eq!(tag, FrameTag::MailboxEntries);
    assert_eq!(
        entries.entries.len(),
        1,
        "the real victim's own fetch of their own bootstrap mailbox must still work normally"
    );
    assert_eq!(entries.entries[0].envelope, real_envelope);

    // And the victim can still delete it themselves, as intended.
    victim_conn
        .send(
            FrameTag::MailboxDelete,
            &MailboxDelete {
                mailbox_id: mailbox_id.clone(),
                entry_id: entries.entries[0].entry_id.clone(),
            },
        )
        .await;
    let (tag, ack): (_, Ack) = victim_conn.recv().await;
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok, "the real owner's own delete must still succeed");
}
