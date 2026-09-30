//! DRA-0058: the app filed every client-side failure as a lost connection.
//!
//! `dratchet_client::net::Connection` returned plain `String` errors, and
//! `dratchet_app::Error` turned every `String` into `Error::Connection`.
//! The desktop app's poll loop reconnects on exactly that variant
//! (`ui/src-tauri`'s `is_connection_error`), so a server *refusal* -- rate
//! limited, not the mailbox owner -- tore down a working connection,
//! showed "Reconnecting…", and spent one of DRA-0055's per-address
//! new-connection allowances on a reconnect the refusal never called for.
//! A failed pairing step (a `String` from `dratchet_client::handshake`)
//! was misfiled the same way.

use std::sync::Arc;

use dratchet_app::{open_account, publish_own_bundle, Error};
use dratchet_client::net::Connection;
use dratchet_server::protocol::*;
use dratchet_store::Db;
use tokio::net::TcpListener;

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

#[tokio::test]
async fn a_real_server_refusal_is_not_reported_as_a_lost_connection() {
    let url = spawn_server().await;

    // Alice registers, so her bootstrap mailbox id is a protected one.
    let db_alice = Arc::new(temp_db());
    let mut alice = open_account(&db_alice).unwrap();
    let mut alice_conn = Connection::connect(&url).await.unwrap();
    alice_conn.authenticate(&alice).await.unwrap();
    publish_own_bundle(&db_alice, &mut alice_conn, &mut alice, "alice58")
        .await
        .unwrap();

    // A stranger asks for Alice's bootstrap mailbox: the server refuses.
    let db_mallory = temp_db();
    let mallory = open_account(&db_mallory).unwrap();
    let mut conn = Connection::connect(&url).await.unwrap();
    conn.authenticate(&mallory).await.unwrap();
    conn.send(
        FrameTag::MailboxFetch,
        &MailboxFetch {
            mailbox_id: dratchet_core::x3dh::bootstrap_mailbox_id(
                alice.identity.fingerprint().as_bytes(),
            )
            .to_vec(),
        },
    )
    .await
    .unwrap();

    // The same conversion every `?` in dratchet_app applies.
    let err: Error = conn
        .recv::<MailboxEntries>()
        .await
        .expect_err("a stranger's fetch of another account's bootstrap mailbox is refused")
        .into();

    assert!(
        !matches!(err, Error::Connection(_)),
        "VULNERABILITY: a server refusal ({err}) is classified as Error::Connection, so the \
         desktop poll loop tears down a working connection and reconnects on every refusal"
    );
    assert!(
        matches!(
            err,
            Error::ServerRefused {
                code: ErrorCode::NotMailboxOwner,
                ..
            }
        ),
        "the refusal must carry the server's reason as a typed code, got {err:?}"
    );

    // And the connection really is still usable: the next request on it
    // succeeds.
    conn.send(FrameTag::FetchOwnPrekeyCount, &FetchOwnPrekeyCount {})
        .await
        .unwrap();
    let (tag, _count): (_, OwnPrekeyCount) = conn.recv().await.unwrap();
    assert_eq!(tag, FrameTag::OwnPrekeyCount);
}

#[test]
fn a_failed_pairing_step_is_not_reported_as_a_lost_connection() {
    // `dratchet_client::handshake`/`::pairing` still report failures as
    // `String`; none of them involve the network.
    let err: Error = String::from("pairing response signature did not verify").into();
    assert!(
        !matches!(err, Error::Connection(_)),
        "VULNERABILITY: a local handshake/pairing failure is classified as Error::Connection, \
         so it too makes the poll loop drop and re-open a healthy connection"
    );
}

/// Guard: a genuine transport failure is still a connection error, so the
/// poll loop still reconnects when it should.
#[tokio::test]
async fn a_real_transport_failure_is_still_a_connection_error() {
    let unused = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = unused.local_addr().unwrap();
    drop(unused);
    let err: Error = Connection::connect(&format!("ws://{addr}/v1/ws"))
        .await
        .err()
        .expect("nothing is listening there")
        .into();
    assert!(matches!(err, Error::Connection(_)), "got {err:?}");
}
