//! Drives two full accounts through the entire Option B flow
//! (`docs/ARCHITECTURE.md` §6.3a) against a real, running server: pairing
//! (`handshake::build_pairing_bundle` -> `handshake::initiate` ->
//! `handshake::respond`) with no `PublishBundle`/directory involved at all,
//! then a real encrypted message exchange over real `net::Connection`s.
//! This is the concrete proof of "server + two clients (A and B) can test
//! communications" — no mocks, a real spawned `dratchet_server::app()`,
//! matching the project's established testing philosophy
//! (`server/tests/common/mod.rs`).

use dratchet_client::{handshake, net::Connection, pairing};
use dratchet_core::account::Account;
use dratchet_core::envelope::Envelope;
use dratchet_server::protocol::*;
use tokio::net::TcpListener;

/// Bind the real service to an OS-assigned port and serve it in the
/// background for the duration of the test. Mirrors
/// `server/tests/common/mod.rs::spawn_server()` exactly — that helper lives
/// behind `server`'s own `tests/` module boundary and isn't exported, so
/// this is the same few lines duplicated, not a shared dependency.
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

const PAYLOAD_CHAT: u8 = 0;

#[tokio::test]
async fn two_clients_pair_directly_and_exchange_messages_through_the_server() {
    let url = spawn_server().await;

    // Both identities are generated locally and never call `PublishBundle`
    // — Option B's whole point is that the directory is never involved.
    let mut alice = Account::generate().unwrap();
    alice.generate_one_time_prekeys(1);
    let alice_routing_id = handshake::random_routing_id();

    let mut bob = Account::generate().unwrap();
    bob.generate_one_time_prekeys(1);
    let bob_routing_id = handshake::random_routing_id();

    // Bob is "the responder" in X3DH terms: he shares his bundle first,
    // out of band (the QR code in production, a copy-pasted blob here).
    let bob_bundle = handshake::build_pairing_bundle(&bob, bob_routing_id.clone()).unwrap();
    let blob = pairing::encode_blob(&bob_bundle);

    // Alice ("the initiator") scans/decodes it and runs X3DH against it.
    let decoded_bundle: pairing::PairingBundle = pairing::decode_blob(&blob).unwrap();
    let (mut alice_ratchet, response) =
        handshake::initiate(&alice, &decoded_bundle, alice_routing_id.clone()).unwrap();
    let response_blob = pairing::encode_blob(&response);

    // Bob decodes Alice's response and completes his side of the handshake.
    let decoded_response: pairing::PairingResponse = pairing::decode_blob(&response_blob).unwrap();
    let mut bob_ratchet = handshake::respond(&mut bob, &decoded_response).unwrap();

    // Both sides derive the same shared Tier 1 mailbox from the two routing
    // ids — never from either party's long-term identity fingerprint.
    let alice_mailbox = dratchet_core::conversation_id(&alice_routing_id, &bob_routing_id);
    let bob_mailbox = dratchet_core::conversation_id(&bob_routing_id, &alice_routing_id);
    assert_eq!(
        alice_mailbox, bob_mailbox,
        "both sides must land on the identical mailbox id"
    );
    let mailbox_id = alice_mailbox.to_vec();

    // Now the transport: both clients authenticate against the real server
    // with no prior registration at all (the self-certifying `AuthResponse`
    // change this same phase of work made possible).
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();

    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();

    // Alice sends a real Double-Ratchet-encrypted chat message into the
    // shared mailbox.
    let plaintext = b"hello bob, this is alice";
    let envelope = alice_ratchet
        .encrypt_payload(PAYLOAD_CHAT, plaintext)
        .unwrap();
    alice_conn
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.clone(),
                envelope: envelope.encode(),
                ttl: 86_400,
            },
        )
        .await
        .unwrap();
    let (tag, ack): (_, Ack) = alice_conn.recv().await.unwrap();
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok, "mailbox write should have succeeded");

    // Bob fetches the mailbox and must be able to decrypt exactly what
    // Alice sent.
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
    assert_eq!(entries.entries.len(), 1, "bob should see alice's message");

    let entry = &entries.entries[0];
    let received_envelope = Envelope::decode(&entry.envelope).unwrap();
    let (payload_type, content) = bob_ratchet.decrypt_payload(&received_envelope).unwrap();
    assert_eq!(payload_type, PAYLOAD_CHAT);
    assert_eq!(content, plaintext);

    // Bob deletes the entry now that he's read it — the "only delete on
    // successful decrypt" rule (`client/src/main.rs`'s `receive_pending`).
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
    let (tag, ack): (_, Ack) = bob_conn.recv().await.unwrap();
    assert_eq!(tag, FrameTag::Ack);
    assert!(ack.ok);

    // Bob replies; Alice must be able to decrypt it back.
    let reply = b"hi alice, bob here";
    let reply_envelope = bob_ratchet.encrypt_payload(PAYLOAD_CHAT, reply).unwrap();
    bob_conn
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: mailbox_id.clone(),
                envelope: reply_envelope.encode(),
                ttl: 86_400,
            },
        )
        .await
        .unwrap();
    let (_, ack): (_, Ack) = bob_conn.recv().await.unwrap();
    assert!(ack.ok);

    alice_conn
        .send(FrameTag::MailboxFetch, &MailboxFetch { mailbox_id })
        .await
        .unwrap();
    let (_, entries): (_, MailboxEntries) = alice_conn.recv().await.unwrap();
    assert_eq!(entries.entries.len(), 1, "alice should see bob's reply");
    let received = Envelope::decode(&entries.entries[0].envelope).unwrap();
    let (payload_type, content) = alice_ratchet.decrypt_payload(&received).unwrap();
    assert_eq!(payload_type, PAYLOAD_CHAT);
    assert_eq!(content, reply);
}
