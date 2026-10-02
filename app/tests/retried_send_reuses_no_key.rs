//! DRA-0059: a send retried after a lost acknowledgement reused the same
//! message key *and* nonce.
//!
//! `send_message` saved the advanced ratchet only after the server's
//! `Ack`. If the server stored the envelope but the `Ack` never arrived
//! (the connection dropped in between), the caller got an error, the
//! ratchet on disk was unchanged, and a retry encrypted again from the
//! same chain position. The nonce is derived from the message key
//! (`core::ratchet::derive_message_cipher`), so both envelopes used the
//! same (key, nonce). With different plaintexts -- an edited retry, or a
//! changed piggyback ack -- anyone holding both ciphertexts, the relay
//! included, learns their XOR. DRA-era audit scenario 22 called this
//! "masked" because the recipient rejects the second copy; that protects
//! the recipient, not what the relay can see.

use std::sync::Arc;

use dratchet_app::{
    add_contact_by_username, generate_pairing_code, open_account, publish_own_bundle,
    receive_first_contact_attempts, send_message,
};
use dratchet_client::net::Connection;
use dratchet_core::envelope::Envelope;
use dratchet_server::protocol::*;
use dratchet_store::Db;
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

async fn spawn_server() -> String {
    let (router, _state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("ws://{addr}/v1/ws")
}

fn temp_db() -> Db {
    let dir = tempfile::tempdir().unwrap().keep();
    Db::create(dir.join("test.redb"), "pw").unwrap()
}

/// A stand-in relay: authenticates anyone, stores (reports) the first
/// `MailboxWrite` it receives, then drops the connection *without*
/// acknowledging it -- the lost-`Ack` case.
async fn spawn_relay_that_loses_the_ack(stored: mpsc::UnboundedSender<Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let stored = stored.clone();
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let challenge = encode(
                    FrameTag::AuthChallenge,
                    &AuthChallenge {
                        nonce: vec![7u8; 32],
                    },
                );
                ws.send(WsMessage::Binary(challenge)).await.unwrap();
                while let Some(Ok(WsMessage::Binary(frame))) = ws.next().await {
                    let (tag, body) = split_tag(&frame).unwrap();
                    match tag {
                        FrameTag::AuthResponse => {
                            let ack = encode(FrameTag::Ack, &Ack { ok: true });
                            ws.send(WsMessage::Binary(ack)).await.unwrap();
                        }
                        FrameTag::MailboxWrite => {
                            let write: MailboxWrite = decode_body(body).unwrap();
                            stored.send(write.envelope).unwrap();
                            return; // dropped: the Ack never goes out
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    format!("ws://{addr}/v1/ws")
}

#[tokio::test]
async fn a_send_retried_after_a_lost_ack_uses_a_fresh_message_key() {
    // Pair Alice and Bob for real, so Alice has a genuine ratchet session.
    let url = spawn_server().await;
    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    let alice_profile = publish_own_bundle(&db_alice, &mut alice_conn, &mut alice, "alice59")
        .await
        .unwrap();
    let db_bob = Arc::new(temp_db());
    let mut bob = open_account(&db_bob).unwrap();
    let mut bob_conn = Connection::connect(&url).await.unwrap();
    bob_conn.authenticate(&bob).await.unwrap();
    let bob_profile = publish_own_bundle(&db_bob, &mut bob_conn, &mut bob, "bob59")
        .await
        .unwrap();
    let code = generate_pairing_code(&db_bob).unwrap().code;
    let contact = add_contact_by_username(
        &db_alice,
        &mut alice_conn,
        &alice,
        &alice_profile,
        &bob_profile.username,
        bob_profile.discriminator,
        &code,
    )
    .await
    .unwrap();
    receive_first_contact_attempts(&db_bob, &mut bob_conn, &mut bob)
        .await
        .unwrap();

    // Alice's next two sends go through a relay that stores each one and
    // then loses the Ack. The second is the user pressing send again.
    let (tx, mut rx) = mpsc::unbounded_channel();
    let lossy = spawn_relay_that_loses_the_ack(tx).await;
    for text in [&b"first attempt"[..], &b"edited retry"[..]] {
        let mut conn = Connection::connect(&lossy).await.unwrap();
        conn.authenticate(&alice).await.unwrap();
        assert!(
            send_message(&db_alice, &mut conn, &alice, &contact, text)
                .await
                .is_err(),
            "with no Ack, the send must report failure"
        );
    }
    let first = Envelope::decode(&rx.recv().await.unwrap()).unwrap();
    let retry = Envelope::decode(&rx.recv().await.unwrap()).unwrap();

    assert!(
        (first.dh_pub, first.n) != (retry.dh_pub, retry.n),
        "VULNERABILITY: the retry was encrypted at the same chain position (n = {}) as the \
         attempt the relay already stored, so both use the same message key and nonce -- \
         the relay holds two different plaintexts under one (key, nonce)",
        retry.n
    );
}
