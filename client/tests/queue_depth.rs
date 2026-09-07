//! The full-stack version of `core/tests/queue_depth.rs`'s claim: a burst of
//! messages queued before any reply, delivered in an order that has nothing
//! to do with the order they were sent in, must still all decrypt correctly.
//! `core/tests/queue_depth.rs` proves this against the ratchet directly, with
//! no transport involved; this file proves the same thing through the real
//! stack this project actually ships — real X3DH pairing, a real spawned
//! `dratchet_server::app()`, real `MailboxWrite`/`MailboxFetch` frames over a
//! real WebSocket. The server stores each mailbox as a plain
//! `Vec<MailboxEntry>` and returns it in write order (`server/src/ws.rs`), so
//! controlling the order of `MailboxWrite` calls — independently of the order
//! the envelopes were *encrypted* in — is what actually simulates a relay
//! delivering messages out of the order they were sent, rather than merely
//! replaying them in order.

use dratchet_client::{handshake, net::Connection};
use dratchet_core::account::Account;
use dratchet_core::envelope::Envelope;
use dratchet_server::protocol::*;
use tokio::net::TcpListener;

const PAYLOAD_CHAT: u8 = 0;

async fn spawn_server() -> String {
    let (router, _state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.expect("server task");
    });
    format!("ws://{addr}/v1/ws")
}

/// Same deterministic pseudo-shuffle `core/tests/queue_depth.rs`'s property
/// test uses, so a failure here is reproducible from the printed seed without
/// needing to capture the whole random delivery order by hand.
fn shuffle(seed: u64, len: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..len).collect();
    let mut state = seed;
    for i in (1..order.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let j = (state >> 33) as usize % (i + 1);
        order.swap(i, j);
    }
    order
}

#[tokio::test]
async fn burst_delivered_through_the_real_server_in_adversarial_order_still_decrypts() {
    let url = spawn_server().await;
    let seed: u64 = 0xC0FFEE_u64.wrapping_mul(2654435761);
    println!("shuffle seed: {seed:#x}");

    let mut alice = Account::generate().unwrap();
    alice.generate_one_time_prekeys(1);
    let alice_routing_id = handshake::random_routing_id();

    let mut bob = Account::generate().unwrap();
    bob.generate_one_time_prekeys(1);
    let bob_routing_id = handshake::random_routing_id();

    // Pair exactly as two real clients would (Option B, no directory).
    let bob_bundle = handshake::build_pairing_bundle(&bob, bob_routing_id.clone()).unwrap();
    let (mut alice_ratchet, response) =
        handshake::initiate(&alice, &bob_bundle, alice_routing_id.clone()).unwrap();
    let mut bob_ratchet = handshake::respond(&mut bob, &response).unwrap();
    let mailbox_id = dratchet_core::conversation_id(&alice_routing_id, &bob_routing_id).to_vec();

    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();

    // Alice (the initiator — the only side that can send before any reply,
    // per the Double Ratchet's own rules) encrypts a burst of 40 messages,
    // in order, exactly as if typed one after another with no reply in
    // between.
    let burst_size = 40;
    let plaintexts: Vec<String> = (0..burst_size)
        .map(|i| format!("queued message {i}"))
        .collect();
    let envelopes: Vec<Envelope> = plaintexts
        .iter()
        .map(|text| {
            alice_ratchet
                .encrypt_payload(PAYLOAD_CHAT, text.as_bytes())
                .unwrap()
        })
        .collect();

    // Written to the real mailbox in an adversarial order that has nothing
    // to do with encryption order — reversed, then interleaved from both
    // ends, same shape as core/tests/queue_depth.rs's hand-picked case, but
    // here it's *actual delivery order to the actual server*, not just an
    // in-memory decrypt order.
    let mut write_order: Vec<usize> = (0..burst_size).collect();
    write_order.reverse();
    let (front, back) = write_order.split_at(write_order.len() / 2);
    let interleaved: Vec<usize> = front
        .iter()
        .zip(back.iter())
        .flat_map(|(a, b)| [*a, *b])
        .collect();

    for &i in &interleaved {
        alice_conn
            .send(
                FrameTag::MailboxWrite,
                &MailboxWrite {
                    mailbox_id: mailbox_id.clone(),
                    envelope: envelopes[i].encode(),
                    ttl: 86_400,
                },
            )
            .await
            .unwrap();
        let (tag, ack): (_, Ack) = alice_conn.recv().await.unwrap();
        assert_eq!(tag, FrameTag::Ack);
        assert!(ack.ok);
    }

    // Bob fetches the whole queued burst in one call — the server hands it
    // back in exactly the adversarial write order above, not encryption
    // order — and must decrypt every one of them to the right plaintext.
    bob_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.clone(),
            },
        )
        .await
        .unwrap();
    let (tag, entries): (_, MailboxEntries) = bob_conn.recv().await.unwrap();
    assert_eq!(tag, FrameTag::MailboxEntries);
    assert_eq!(
        entries.entries.len(),
        burst_size,
        "the whole burst must have survived queueing, regardless of delivery order"
    );

    // Every message must decrypt to the right plaintext, and — since each
    // skipped message key is single-use, removed from the cache the moment
    // it's consumed — arrive exactly once, not zero and not twice.
    let mut decrypted = std::collections::HashSet::new();
    for entry in &entries.entries {
        let envelope = Envelope::decode(&entry.envelope).unwrap();
        let (payload_type, content) = bob_ratchet
            .decrypt_payload(&envelope)
            .expect("every message within MAX_SKIP must decrypt regardless of delivery order");
        assert_eq!(payload_type, PAYLOAD_CHAT);
        let text = String::from_utf8(content).unwrap();
        assert!(
            plaintexts.contains(&text),
            "decrypted to an unexpected plaintext: {text}"
        );
        assert!(decrypted.insert(text), "a message decrypted more than once");
    }
    assert_eq!(
        decrypted.len(),
        burst_size,
        "every originally-encrypted message must have been written and delivered exactly once"
    );

    // Clean up: delete every entry, mirroring what a real client does after
    // a successful decrypt, and confirm the mailbox is actually empty after.
    for entry in &entries.entries {
        bob_conn
            .send(
                FrameTag::MailboxDelete,
                &MailboxDelete {
                    mailbox_id: mailbox_id.clone(),
                    entry_id: entry.entry_id.clone(),
                },
            )
            .await
            .unwrap();
        let (_, ack): (_, Ack) = bob_conn.recv().await.unwrap();
        assert!(ack.ok);
    }
    bob_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: mailbox_id.clone(),
            },
        )
        .await
        .unwrap();
    let (_, entries): (_, MailboxEntries) = bob_conn.recv().await.unwrap();
    assert!(
        entries.entries.is_empty(),
        "mailbox must be empty after deleting the whole burst"
    );
}

/// Property-style companion to the fixed adversarial order above: for many
/// random seeds and burst sizes, a burst written to the real mailbox in a
/// pseudo-random order must still fully decrypt regardless of order.
#[tokio::test]
async fn burst_delivered_through_the_real_server_in_random_orders_always_decrypts() {
    for seed in [1u64, 2, 3, 42, 1_000_003, 0xDEADBEEF, u64::MAX / 7] {
        let url = spawn_server().await;

        let mut alice = Account::generate().unwrap();
        alice.generate_one_time_prekeys(1);
        let alice_routing_id = handshake::random_routing_id();
        let mut bob = Account::generate().unwrap();
        bob.generate_one_time_prekeys(1);
        let bob_routing_id = handshake::random_routing_id();

        let bob_bundle = handshake::build_pairing_bundle(&bob, bob_routing_id.clone()).unwrap();
        let (mut alice_ratchet, response) =
            handshake::initiate(&alice, &bob_bundle, alice_routing_id.clone()).unwrap();
        let mut bob_ratchet = handshake::respond(&mut bob, &response).unwrap();
        let mailbox_id =
            dratchet_core::conversation_id(&alice_routing_id, &bob_routing_id).to_vec();

        let mut alice_conn = Connection::connect(&url).await.unwrap();
        alice_conn.authenticate(&alice).await.unwrap();
        let mut bob_conn = Connection::connect(&url).await.unwrap();
        bob_conn.authenticate(&bob).await.unwrap();

        let burst_size = 1 + (seed % 30) as usize;
        let plaintexts: Vec<String> = (0..burst_size).map(|i| format!("m{i}-{seed}")).collect();
        let envelopes: Vec<Envelope> = plaintexts
            .iter()
            .map(|text| {
                alice_ratchet
                    .encrypt_payload(PAYLOAD_CHAT, text.as_bytes())
                    .unwrap()
            })
            .collect();

        let order = shuffle(seed, burst_size);
        for &i in &order {
            alice_conn
                .send(
                    FrameTag::MailboxWrite,
                    &MailboxWrite {
                        mailbox_id: mailbox_id.clone(),
                        envelope: envelopes[i].encode(),
                        ttl: 86_400,
                    },
                )
                .await
                .unwrap();
            let (_, ack): (_, Ack) = alice_conn.recv().await.unwrap();
            assert!(ack.ok);
        }

        bob_conn
            .send(
                FrameTag::MailboxFetch,
                &MailboxFetch {
                    mailbox_id: mailbox_id.clone(),
                },
            )
            .await
            .unwrap();
        let (_, entries): (_, MailboxEntries) = bob_conn.recv().await.unwrap();
        assert_eq!(
            entries.entries.len(),
            burst_size,
            "seed {seed}: burst size mismatch"
        );

        let mut decrypted = std::collections::HashSet::new();
        for entry in &entries.entries {
            let envelope = Envelope::decode(&entry.envelope).unwrap();
            let (payload_type, content) = bob_ratchet
                .decrypt_payload(&envelope)
                .unwrap_or_else(|e| panic!("seed {seed}: decrypt failed: {e}"));
            assert_eq!(payload_type, PAYLOAD_CHAT);
            let text = String::from_utf8(content).unwrap();
            assert!(
                plaintexts.contains(&text),
                "seed {seed}: unexpected plaintext {text}"
            );
            decrypted.insert(text);
        }
        assert_eq!(
            decrypted.len(),
            burst_size,
            "seed {seed}: every message in the burst must decrypt exactly once"
        );
    }
}
