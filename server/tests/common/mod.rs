//! Shared test-only client for driving the real service over a real
//! WebSocket — every test in `integration.rs`/`adversarial.rs`/
//! `stress.rs` talks to an actually-bound `dratchet_server::app()`, not an
//! in-process mock, per the phase's test gate ("no mocked crypto").

use dratchet_core::account::Account;
use dratchet_server::protocol::*;
use futures_util::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

pub type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Bind the real service to an OS-assigned port and serve it in the
/// background for the duration of the test process. Returns the base
/// `ws://` URL for the WebSocket endpoint.
pub async fn spawn_server() -> String {
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

pub struct TestClient {
    ws: WsStream,
}

impl TestClient {
    pub async fn connect(url: &str) -> Self {
        let (ws, _resp) = connect_async(url).await.expect("ws connect");
        TestClient { ws }
    }

    pub async fn send<T: Serialize>(&mut self, tag: FrameTag, body: &T) {
        let frame = encode(tag, body);
        self.ws
            .send(WsMessage::Binary(frame))
            .await
            .expect("ws send");
    }

    /// Used by `adversarial.rs` to send hand-built malformed frames; each
    /// test binary compiles this module separately, so it shows as unused
    /// dead code from `integration.rs`'s point of view.
    #[allow(dead_code)]
    pub async fn send_raw(&mut self, bytes: Vec<u8>) {
        self.ws
            .send(WsMessage::Binary(bytes))
            .await
            .expect("ws send raw");
    }

    /// Wait for the next binary frame, skipping any non-binary control
    /// frames the underlying transport surfaces.
    pub async fn recv_raw(&mut self) -> Vec<u8> {
        loop {
            match self.ws.next().await {
                Some(Ok(WsMessage::Binary(b))) => return b,
                Some(Ok(_)) => continue,
                Some(Err(e)) => panic!("ws recv error: {e}"),
                None => panic!("connection closed while waiting for a frame"),
            }
        }
    }

    pub async fn recv<T: DeserializeOwned>(&mut self) -> (FrameTag, T) {
        let raw = self.recv_raw().await;
        let (tag, body) = split_tag(&raw).expect("valid frame from the server");
        let parsed: T = decode_body(body).expect("server frame decodes as expected type");
        (tag, parsed)
    }

    /// Full auth handshake: receive the challenge, sign the nonce with
    /// `account`'s identity key, send it back. Panics (test failure) if the
    /// server doesn't Ack.
    pub async fn authenticate(&mut self, account: &Account) {
        let (tag, challenge): (_, AuthChallenge) = self.recv().await;
        assert_eq!(tag, FrameTag::AuthChallenge);
        let signature = account.identity.sign(&challenge.nonce).unwrap();
        let fingerprint = account.identity.fingerprint().as_bytes().to_vec();
        self.send(
            FrameTag::AuthResponse,
            &AuthResponse {
                identity_fingerprint: fingerprint,
                signature,
            },
        )
        .await;
        let (tag, ack): (_, Ack) = self.recv().await;
        assert_eq!(tag, FrameTag::Ack);
        assert!(ack.ok, "authentication should have succeeded");
    }

    /// Drain and discard the initial `AuthChallenge` without authenticating
    /// — for tests that deliberately probe pre-auth or malformed behavior.
    #[allow(dead_code)]
    pub async fn skip_challenge(&mut self) {
        let _: (_, AuthChallenge) = self.recv().await;
    }

    /// Like `recv`, but silently skips server-pushed frames that aren't a
    /// response to anything this connection asked for
    /// (`RendezvousOffer`/`RendezvousAnswer` relayed from a peer,
    /// `PresenceUpdate` from a subscription) — needed once multiple
    /// concurrent peers can push unsolicited frames into a connection that's
    /// also being driven request/response style, as in the stress test.
    #[allow(dead_code)]
    pub async fn recv_skip_pushes<T: DeserializeOwned>(&mut self, expected: FrameTag) -> T {
        loop {
            let raw = self.recv_raw().await;
            let (tag, body) = split_tag(&raw).expect("valid frame from the server");
            if tag == expected {
                return decode_body(body).expect("server frame decodes as expected type");
            }
            assert!(
                matches!(
                    tag,
                    FrameTag::RendezvousOffer
                        | FrameTag::RendezvousAnswer
                        | FrameTag::PresenceUpdate
                ),
                "unexpected frame tag {tag:?} while waiting for {expected:?}"
            );
        }
    }
}

/// A real generated account plus its bundle already converted to the
/// *published* wire form (`MESSAGE_SCHEMA.md` §1's batch shape) — the
/// fixture every test starts from.
pub fn fresh_account_and_bundle(
    username: &str,
    discriminator: u16,
    one_time_prekey_count: u32,
) -> (Account, PrekeyBundleWire) {
    let mut account = Account::generate().unwrap();
    let otp_publics = account.generate_one_time_prekeys(one_time_prekey_count);
    // `publish_bundle(false)` never touches the one-time-prekey store (see
    // its own doc comment) — the batch below is built directly from what
    // `generate_one_time_prekeys` just returned instead.
    let core_bundle = account.publish_bundle(false).unwrap();

    let one_time_prekeys = otp_publics
        .into_iter()
        .map(|otp| OneTimePrekeyWire {
            id: otp.id,
            key: otp.public.as_bytes().to_vec(),
        })
        .collect();

    let wire = PrekeyBundleWire {
        username: username.to_string(),
        discriminator,
        identity_key: core_bundle.identity_public_key.clone(),
        identity_dh_public: core_bundle.identity_dh_public.as_bytes().to_vec(),
        identity_dh_signature: core_bundle.identity_dh_signature.clone(),
        signed_prekey_id: core_bundle.signed_prekey.id,
        signed_prekey: core_bundle.signed_prekey.public.as_bytes().to_vec(),
        signed_prekey_sig: core_bundle.signed_prekey.signature.clone(),
        signed_prekey_expires_at: 0,
        one_time_prekeys,
    };
    (account, wire)
}

pub fn fingerprint_of(account: &Account) -> Vec<u8> {
    account.identity.fingerprint().as_bytes().to_vec()
}
