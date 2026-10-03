//! Penetration-test finding, DRA-0017 (round 2, priority 3: denial of
//! service for a *single conversation*), found while re-examining
//! DRA-0015's own fix (`docs/DELIVERY_FAILURE_FINDINGS.md`): capping
//! `MAX_MAILBOX_ENTRIES` per mailbox closed unbounded growth, but a
//! mailbox is *bidirectional* — `ARCHITECTURE.md` §11.1: both
//! participants in a conversation write to and fetch from the identical
//! `mailbox_id`. The cap is enforced on the mailbox as a whole, not
//! per-writer, so nothing stops one side from filling the *entire* cap
//! with their own entries — at which point the *other* side's own
//! legitimate `MailboxWrite` into that same shared mailbox is rejected
//! too, with `Error::MailboxFull`, exactly as if they were the flooder.
//!
//! Concretely: Alice and Bob are already paired and share `mailbox_id`.
//! Bob (malicious, or just a misbehaving/compromised client) writes
//! `MAX_MAILBOX_ENTRIES` garbage entries. Alice — who has done nothing
//! wrong, and has no way to know the mailbox is already full until she
//! tries — then attempts to send Bob a real message. Pre-fix, her write
//! was rejected: Bob had unilaterally, silently blocked further outgoing
//! communication from Alice in *this one conversation*, without needing
//! anything more than the shared mailbox id every already-paired contact
//! already has. (Before DRA-0015's cap existed at all, the equivalent
//! attack was even easier — an unbounded flood, not merely blocking
//! until the cap, so this was not a regression DRA-0015 introduced, but
//! a related gap DRA-0015's fix didn't close.)
//!
//! **Fixed**: `state::MAX_ENTRIES_PER_WRITER_PER_MAILBOX` (half of
//! `MAX_MAILBOX_ENTRIES`) caps each writer's own share within a mailbox,
//! enforced alongside the existing total cap. This test now proves the
//! fix: Bob's own flood is capped well before he could ever exhaust the
//! whole mailbox, and Alice's own write succeeds regardless of how much
//! of his own share Bob has used.

mod common;

use common::*;
use dratchet_core::account::Account;
use dratchet_server::protocol::*;

#[tokio::test]
async fn one_side_flooding_a_shared_mailbox_cannot_block_the_other_sides_own_writes() {
    let url = spawn_server().await;

    let alice = Account::generate().unwrap();
    let mut alice_conn = TestClient::connect(&url).await;
    alice_conn.authenticate(&alice).await;

    let bob = Account::generate().unwrap();
    let mut bob_conn = TestClient::connect(&url).await;
    bob_conn.authenticate(&bob).await;

    // A shared mailbox id, standing in for the real routing-id-derived
    // one two paired contacts would actually use — the server treats it
    // identically either way (`store::routing::compute_mailbox_id` is
    // opaque to the server, just 16 bytes).
    let shared_mailbox_id = [42u8; 16];

    // Bob (the flooder) fills exactly his own share of the mailbox with
    // garbage — every one of these succeeds, per the fix's own contract
    // (writes up to a writer's own quota must work).
    for i in 0..dratchet_server::state::MAX_ENTRIES_PER_WRITER_PER_MAILBOX {
        bob_conn
            .send(
                FrameTag::MailboxWrite,
                &MailboxWrite {
                    mailbox_id: shared_mailbox_id.to_vec(),
                    envelope: vec![0u8; 32],
                    ttl: 60,
                },
            )
            .await;
        let (_, ack): (_, Ack) = bob_conn.recv().await;
        assert!(ack.ok, "write {i} within Bob's own share must succeed");
    }

    // One more from Bob, past his own share, must now be rejected --
    // distinctly, so a client can tell "I'm the one over quota" apart
    // from "the mailbox itself is full."
    bob_conn
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: shared_mailbox_id.to_vec(),
                envelope: vec![0u8; 32],
                ttl: 60,
            },
        )
        .await;
    let (tag, err): (_, ErrorFrame) = bob_conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::Error,
        "FIX VERIFIED: Bob must be capped at his own share of the mailbox, well before he could \
         ever exhaust the whole thing"
    );
    assert!(err.message.to_lowercase().contains("your share"));

    // Alice, who has done nothing wrong, now tries to send Bob a real
    // message into their shared conversation -- this must succeed
    // regardless of how much of his own share Bob has used.
    alice_conn
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: shared_mailbox_id.to_vec(),
                envelope: b"a real message Alice is trying to send Bob".to_vec(),
                ttl: 60,
            },
        )
        .await;
    let (tag, ack): (_, Ack) = alice_conn.recv().await;
    assert_eq!(
        tag,
        FrameTag::Ack,
        "FIX VERIFIED: Bob filling his own share of the shared mailbox must never block Alice's \
         own legitimate write into the same conversation"
    );
    assert!(ack.ok);
}
