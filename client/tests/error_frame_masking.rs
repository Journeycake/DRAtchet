//! Penetration-test finding DRA-0052 (round 9, availability/robustness).
//!
//! `net::Connection::recv<T>` decodes every response body as the caller's
//! expected type `T`, with no check of the frame's tag first. When the
//! server genuinely refuses a request -- rate limited, not the mailbox
//! owner, username taken, anything -- it replies with an `Error` frame
//! carrying the real reason as `ErrorFrame.message`. A caller expecting
//! `Ack`/`MailboxEntries`/`BundleResult`/etc. then tries to decode that
//! `Error` frame's body as its own type, which fails, discarding the
//! server's actual message and surfacing a generic "did not decode as
//! expected CBOR shape" instead. Every one of `app/src/lib.rs`'s ~14
//! typed `recv()` call sites has this shape.
//!
//! This is availability-relevant, not just cosmetic: DRA-0049/DRA-0050
//! made rate limiting a normal, expected response on busy paths. Without
//! this fix, the app layer cannot tell "the server is asking me to slow
//! down" apart from "the wire protocol is corrupted" -- so it cannot
//! implement correct backoff-and-retry, and is pushed toward treating a
//! transient, self-correcting refusal as a fatal error instead.

use dratchet_client::net::Connection;
use dratchet_core::account::Account;
use dratchet_server::protocol::*;
use tokio::net::TcpListener;

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

/// Publish `account` under `username`/`discriminator`, solving the real
/// registration proof-of-work -- the same recipe
/// `server/tests/common/mod.rs::fresh_account_and_bundle` uses, inlined
/// here since that helper lives behind `server`'s own `tests/` module
/// boundary and isn't exported.
fn build_bundle_wire(
    account: &mut Account,
    username: &str,
    discriminator: u16,
) -> PrekeyBundleWire {
    let core_bundle = account.publish_bundle(false).unwrap();
    let registration_pow = Some(dratchet_server::abuse::solve_registration_pow(
        username,
        discriminator,
        &core_bundle.identity_public_key,
    ));
    PrekeyBundleWire {
        username: username.to_string(),
        discriminator,
        identity_key: core_bundle.identity_public_key.clone(),
        identity_dh_public: core_bundle.identity_dh_public.as_bytes().to_vec(),
        identity_dh_signature: core_bundle.identity_dh_signature.clone(),
        signed_prekey_id: core_bundle.signed_prekey.id,
        signed_prekey: core_bundle.signed_prekey.public.as_bytes().to_vec(),
        signed_prekey_sig: core_bundle.signed_prekey.signature.clone(),
        signed_prekey_expires_at: 0,
        one_time_prekeys: Vec::new(),
        registration_pow,
    }
}

/// Trigger a genuine, real server refusal -- not a hand-crafted malformed
/// frame -- and confirm the client surfaces the server's actual reason
/// rather than a generic decode-failure message.
#[tokio::test]
async fn a_genuine_server_refusal_is_not_reported_as_a_decode_failure() {
    let url = spawn_server().await;

    // The target must be a real directory resident for its bootstrap
    // mailbox to be a protected id at all (DRA-0014).
    let mut target = Account::generate().unwrap();
    let target_wire = build_bundle_wire(&mut target, "dra0052target", 5052);
    let target_mailbox =
        dratchet_core::x3dh::bootstrap_mailbox_id(target.identity.fingerprint().as_bytes());

    let mut target_conn = Connection::connect(&url).await.unwrap();
    target_conn.authenticate(&target).await.unwrap();
    target_conn
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: target_wire,
            },
        )
        .await
        .unwrap();
    let (_, ack): (_, Ack) = target_conn.recv().await.unwrap();
    assert!(ack.ok);

    // A stranger fetches the target's bootstrap mailbox -- a real,
    // well-formed request this identity has no right to, refused via a
    // genuine Error frame, not a hand-built malformed one.
    let stranger = Account::generate().unwrap();
    let mut conn = Connection::connect(&url).await.unwrap();
    conn.authenticate(&stranger).await.unwrap();
    conn.send(
        FrameTag::MailboxFetch,
        &MailboxFetch {
            mailbox_id: target_mailbox.to_vec(),
        },
    )
    .await
    .unwrap();

    let result: Result<(FrameTag, MailboxEntries), String> = conn.recv().await;
    let err = result
        .expect_err("a stranger's fetch of another account's bootstrap mailbox must be refused");

    assert!(
        !err.contains("did not decode as expected CBOR shape") && !err.contains("MalformedFrame"),
        "VULNERABILITY: a genuine server refusal (an Error frame) is reported to the caller as a \
         CBOR decode failure, discarding the server's actual reason (\"{err}\") and making a \
         real refusal indistinguishable from wire corruption -- every one of app/src/lib.rs's \
         typed recv() calls has this shape"
    );
}

/// Non-regression guard: an ordinary successful reply still decodes
/// exactly as before -- the fix must only change what happens on an
/// `Error` frame, nothing else.
#[tokio::test]
async fn an_ordinary_successful_reply_still_decodes_normally() {
    let url = spawn_server().await;
    let mut account = Account::generate().unwrap();
    let wire = build_bundle_wire(&mut account, "dra0052ok", 5053);

    let mut conn = Connection::connect(&url).await.unwrap();
    conn.authenticate(&account).await.unwrap();
    conn.send(FrameTag::PublishBundle, &PublishBundle { bundle: wire })
        .await
        .unwrap();
    let (tag, ack): (_, Ack) = conn.recv().await.unwrap();
    assert_eq!(tag, FrameTag::Ack);
    assert!(
        ack.ok,
        "an ordinary successful publish must still Ack normally"
    );
}
