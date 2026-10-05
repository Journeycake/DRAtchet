//! DRA-0061: a send to a server that stopped answering waited forever.
//!
//! Nothing bounded how long `Connection` waited for a reply. If the
//! network stalled without the connection closing (packets silently
//! dropped, a half-dead NAT mapping), a send sat waiting until the OS gave
//! up on the socket, which can take many minutes. In the desktop app the
//! connection lock was held the whole time, so incoming mail stopped too.

use std::time::Duration;

use dratchet_app::{open_account, send_message, Error};
use dratchet_client::net::Connection;
use dratchet_server::protocol::*;
use dratchet_store::{Contact, Db, VerificationState};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message as WsMessage;

/// Authenticates anyone, then reads and ignores every request, keeping the
/// connection open but never answering.
async fn spawn_server_that_stops_answering() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
                let challenge = encode(
                    FrameTag::AuthChallenge,
                    &AuthChallenge {
                        nonce: vec![7u8; 32],
                        server_boot_id: Vec::new(),
                        server_epoch: 0,
                        save_interval_ms: 0,
                    },
                );
                ws.send(WsMessage::Binary(challenge)).await.unwrap();
                while let Some(Ok(WsMessage::Binary(frame))) = ws.next().await {
                    if split_tag(&frame).unwrap().0 == FrameTag::AuthResponse {
                        let ack = encode(FrameTag::Ack, &Ack { ok: true });
                        ws.send(WsMessage::Binary(ack)).await.unwrap();
                    }
                    // Everything else: silence.
                }
            });
        }
    });
    format!("ws://{addr}/v1/ws")
}

#[tokio::test]
async fn a_send_to_a_server_that_stopped_answering_fails_instead_of_hanging() {
    let url = spawn_server_that_stops_answering().await;
    let dir = tempfile::tempdir().unwrap().keep();
    let db = Db::create(dir.join("test.redb"), "pw").unwrap();
    let account = open_account(&db).unwrap();

    // A verified contact with a session, so the send gets as far as the
    // network: the session's own content doesn't matter here.
    let peer = dratchet_core::account::Account::generate().unwrap();
    let contact = Contact {
        fingerprint: peer.identity.fingerprint().as_bytes().to_vec(),
        username: None,
        discriminator: None,
        verification_state: VerificationState::Verified,
        mailbox_id: vec![1u8; 16],
        created_at: 0,
        local_routing_id: vec![2u8; 32],
        peer_routing_id: None,
        wipe_ask_before_delete: false,
        peer_wipe_ask_before_delete: None,
        wipe_include_session: false,
        peer_wipe_include_session: None,
        wipe_request_pending: false,
        wipe_boundary_timestamp: None,
        wipe_boundary_sequence: None,
        peer_wipe_boundary_timestamp: None,
        peer_wipe_boundary_sequence: None,
        routing_confirmed: false,
        routing_announce: Vec::new(),
    };
    db.save_contact(&contact).unwrap();
    let conv = dratchet_core::conversation_id(
        account.identity.fingerprint().as_bytes(),
        &contact.fingerprint,
    );
    let ratchet = dratchet_core::ratchet::RatchetState::init_as_initiator(
        conv,
        [9u8; 32],
        x25519_dalek::PublicKey::from(peer.signed_prekey_secret()),
        dratchet_core::ratchet::MIN_MAX_SKIP,
    )
    .unwrap();
    db.save_ratchet(conv, &ratchet).unwrap();

    let mut conn = Connection::connect(&url).await.unwrap();
    conn.authenticate(&account).await.unwrap();
    conn.set_request_timeout(Duration::from_millis(500));

    let outcome = tokio::time::timeout(
        Duration::from_secs(10),
        send_message(&db, &mut conn, &account, &contact, b"hello?"),
    )
    .await;
    let result = outcome.unwrap_or_else(|_| {
        panic!(
            "VULNERABILITY: a send to a server that accepted the connection but stopped \
             answering was still waiting after 10s -- nothing bounds the wait, so the caller \
             (and the desktop app's connection lock) hangs until the OS drops the socket"
        )
    });
    match result {
        Err(Error::NotSent { cause, .. }) => assert!(
            matches!(*cause, Error::Connection(_)),
            "a timeout is a lost connection, so the app reconnects: {cause:?}"
        ),
        other => panic!("expected NotSent after a timeout, got {other:?}"),
    }
}
