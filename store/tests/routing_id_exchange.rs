//! Phase 1.6.2's routing-id exchange, proven through the real stack this
//! project actually ships — real X3DH via directory FetchBundle, a real
//! spawned `dratchet_server::app()`, real `MailboxWrite`/`MailboxFetch`
//! frames — not just `store/src/routing.rs`'s own unit tests, which check
//! the transition logic in isolation. Mirrors `server/tests/breach.rs`'s
//! and `client/tests/queue_depth.rs`'s "real server, no mocks" style.

use dratchet_core::account::Account;
use dratchet_core::envelope::Envelope;
use dratchet_core::payload::{RoutingIdAnnounce, PAYLOAD_CHAT, PAYLOAD_ROUTING_ID_ANNOUNCE};
use dratchet_core::prekey::{OneTimePrekeyPublic, PrekeyBundle, SignedPrekeyPublic};
use dratchet_core::ratchet::{RatchetState, DEFAULT_MAX_SKIP};
use dratchet_core::x3dh::{self, bootstrap_mailbox_id};
use dratchet_server::protocol::*;
use dratchet_store::{compute_mailbox_id, Contact, Db, VerificationState};
use futures_util::{SinkExt, StreamExt};
use rand_core::{OsRng, RngCore};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use x25519_dalek::PublicKey;

type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct Conn {
    ws: WsStream,
}

impl Conn {
    async fn connect(url: &str) -> Self {
        let (ws, _) = connect_async(url).await.expect("ws connect");
        Conn { ws }
    }

    async fn send<T: serde::Serialize>(&mut self, tag: FrameTag, body: &T) {
        self.ws
            .send(WsMessage::Binary(encode(tag, body)))
            .await
            .expect("ws send");
    }

    async fn recv<T: for<'de> serde::Deserialize<'de>>(&mut self) -> (FrameTag, T) {
        loop {
            match self.ws.next().await {
                Some(Ok(WsMessage::Binary(b))) => {
                    let (tag, body) = split_tag(&b).expect("valid frame");
                    return (tag, decode_body(body).expect("expected shape"));
                }
                Some(Ok(_)) => continue,
                other => panic!("unexpected ws result: {other:?}"),
            }
        }
    }

    async fn authenticate(&mut self, account: &Account) {
        let (_, challenge): (_, AuthChallenge) = self.recv().await;
        let signature = account.identity.sign(&challenge.nonce).unwrap();
        let identity_key = account.identity.export_public_key().unwrap();
        self.send(
            FrameTag::AuthResponse,
            &AuthResponse {
                identity_key,
                signature,
            },
        )
        .await;
        let (_, ack): (_, Ack) = self.recv().await;
        assert!(ack.ok);
    }

    /// The server always sends an `AuthChallenge` first on every new
    /// connection — consume it without authenticating, for a connection
    /// that only ever needs to do unauthenticated calls like
    /// `PublishBundle`/`FetchBundle`.
    async fn skip_challenge(&mut self) {
        let (_, _challenge): (_, AuthChallenge) = self.recv().await;
    }
}

async fn spawn_server() -> String {
    let (router, _state) = dratchet_server::app();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    format!("ws://{addr}/v1/ws")
}

fn to_core_bundle(wire: &FetchedBundleWire) -> PrekeyBundle {
    let identity_dh_public: [u8; 32] = wire.identity_dh_public.as_slice().try_into().unwrap();
    let signed_prekey_public: [u8; 32] = wire.signed_prekey.as_slice().try_into().unwrap();
    PrekeyBundle {
        identity_public_key: wire.identity_key.clone(),
        identity_dh_public: PublicKey::from(identity_dh_public),
        identity_dh_signature: wire.identity_dh_signature.clone(),
        signed_prekey: SignedPrekeyPublic {
            id: wire.signed_prekey_id,
            public: PublicKey::from(signed_prekey_public),
            signature: wire.signed_prekey_sig.clone(),
        },
        one_time_prekey: wire.one_time_prekey.as_ref().map(|otp| {
            let public: [u8; 32] = otp.key.as_slice().try_into().unwrap();
            OneTimePrekeyPublic {
                id: otp.id,
                public: PublicKey::from(public),
            }
        }),
    }
}

fn random_routing_id() -> Vec<u8> {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    buf.to_vec()
}

fn temp_db() -> Db {
    let dir = tempfile::tempdir().unwrap().keep();
    Db::create(dir.join("test.redb"), "pw").unwrap()
}

#[tokio::test]
async fn both_sides_exchange_routing_ids_over_the_real_server_and_converge_on_the_same_mailbox() {
    let url = spawn_server().await;

    // --- Real X3DH via the directory, exactly as Phase 1.6's v1 flow uses. ---
    let mut bob = Account::generate().unwrap();
    let bob_otp_publics = bob.generate_one_time_prekeys(1);
    let bob_local_bundle = bob.publish_bundle(false).unwrap();
    let bob_bundle_wire = PrekeyBundleWire {
        username: "bob".into(),
        discriminator: 5001,
        identity_key: bob_local_bundle.identity_public_key.clone(),
        identity_dh_public: bob_local_bundle.identity_dh_public.as_bytes().to_vec(),
        identity_dh_signature: bob_local_bundle.identity_dh_signature.clone(),
        signed_prekey_id: bob_local_bundle.signed_prekey.id,
        signed_prekey: bob_local_bundle.signed_prekey.public.as_bytes().to_vec(),
        signed_prekey_sig: bob_local_bundle.signed_prekey.signature.clone(),
        signed_prekey_expires_at: 0,
        one_time_prekeys: bob_otp_publics
            .into_iter()
            .map(|otp| OneTimePrekeyWire {
                id: otp.id,
                key: otp.public.as_bytes().to_vec(),
            })
            .collect(),
        registration_pow: Some(dratchet_server::abuse::solve_registration_pow(
            "bob",
            5001,
            &bob_local_bundle.identity_public_key,
        )),
    };
    let mut publisher = Conn::connect(&url).await;
    publisher.skip_challenge().await;
    publisher
        .send(
            FrameTag::PublishBundle,
            &PublishBundle {
                bundle: bob_bundle_wire,
            },
        )
        .await;

    let alice = Account::generate().unwrap();
    let mut fetcher = Conn::connect(&url).await;
    fetcher.skip_challenge().await;
    fetcher
        .send(
            FrameTag::FetchBundle,
            &FetchBundle {
                username: "bob".into(),
                discriminator: 5001,
            },
        )
        .await;
    let (_, result): (_, BundleResult) = fetcher.recv().await;
    let fetched = result.bundle.expect("bob's bundle should be found");
    let core_bundle = to_core_bundle(&fetched);

    let init = x3dh::initiate(
        alice.identity_dh_secret(),
        alice.identity_dh_public,
        &core_bundle,
    )
    .unwrap();
    let conv_id = dratchet_core::conversation_id(
        alice.identity.fingerprint().as_bytes(),
        bob.identity.fingerprint().as_bytes(),
    );
    let mut alice_ratchet = RatchetState::init_as_initiator(
        conv_id,
        init.root_key,
        core_bundle.signed_prekey.public,
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    let bob_otp_secret = init
        .message
        .used_one_time_prekey_id
        .and_then(|id| bob.take_one_time_prekey_secret(id));
    let bob_root_key = x3dh::respond(
        bob.identity_dh_secret(),
        bob.signed_prekey_secret(),
        bob_otp_secret.as_ref(),
        &init.message,
    );
    let mut bob_ratchet = RatchetState::init_as_responder(
        conv_id,
        bob_root_key,
        bob.signed_prekey_secret().clone(),
        DEFAULT_MAX_SKIP,
    )
    .unwrap();

    // --- Each side creates its own Pending contact, addressed at the
    // bootstrap mailbox for writing to the other. ---
    let alice_fp = alice.identity.fingerprint().as_bytes().to_vec();
    let bob_fp = bob.identity.fingerprint().as_bytes().to_vec();
    let alice_routing_id = random_routing_id();
    let bob_routing_id = random_routing_id();

    let db_alice = temp_db();
    let alice_contact = Contact {
        fingerprint: bob_fp.clone(),
        username: Some("bob".into()),
        discriminator: Some(5001),
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&bob_fp).to_vec(),
        created_at: 0,
        disappearing_timer_secs: None,
        local_routing_id: alice_routing_id.clone(),
        peer_routing_id: None,
        wipe_ask_before_delete: false,
        peer_wipe_ask_before_delete: None,
        wipe_include_session: false,
        peer_wipe_include_session: None,
        wipe_request_pending: false,
    };
    db_alice.save_contact(&alice_contact).unwrap();

    let db_bob = temp_db();
    let bob_contact = Contact {
        fingerprint: alice_fp.clone(),
        username: None,
        discriminator: None,
        verification_state: VerificationState::Pending,
        mailbox_id: bootstrap_mailbox_id(&alice_fp).to_vec(),
        created_at: 0,
        disappearing_timer_secs: None,
        local_routing_id: bob_routing_id.clone(),
        peer_routing_id: None,
        wipe_ask_before_delete: false,
        peer_wipe_ask_before_delete: None,
        wipe_include_session: false,
        peer_wipe_include_session: None,
        wipe_request_pending: false,
    };
    db_bob.save_contact(&bob_contact).unwrap();

    // --- Both sides announce their routing id over the real server, each
    // addressed at the *recipient's* bootstrap mailbox. ---
    let mut alice_conn = Conn::connect(&url).await;
    alice_conn.authenticate(&alice).await;
    let mut bob_conn = Conn::connect(&url).await;
    bob_conn.authenticate(&bob).await;

    // Only the X3DH *initiator* has a sending chain before receiving
    // anything (a responder's sending chain doesn't exist until it's
    // ratcheted forward on an incoming message — the same real protocol
    // constraint the reference CLI client's README documents). So the
    // exchange is necessarily sequential, not simultaneous: Alice announces
    // first, which is what gives Bob a sending chain of his own once he
    // decrypts it.
    let alice_announce_envelope = alice_ratchet
        .encrypt_payload(
            PAYLOAD_ROUTING_ID_ANNOUNCE,
            &RoutingIdAnnounce {
                routing_id: alice_routing_id.clone(),
            }
            .encode(),
        )
        .unwrap();
    alice_conn
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: bootstrap_mailbox_id(&bob_fp).to_vec(),
                envelope: alice_announce_envelope.encode(),
                ttl: 86_400,
            },
        )
        .await;
    let (_, ack): (_, Ack) = alice_conn.recv().await;
    assert!(ack.ok);

    // Bob fetches his own bootstrap mailbox, decrypts Alice's announce
    // (ratcheting his session forward — now he has a sending chain), and
    // transitions his side of the contact.
    bob_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: bootstrap_mailbox_id(&bob_fp).to_vec(),
            },
        )
        .await;
    let (_, entries): (_, MailboxEntries) = bob_conn.recv().await;
    assert_eq!(entries.entries.len(), 1);
    let envelope = Envelope::decode(&entries.entries[0].envelope).unwrap();
    let (payload_type, content) = bob_ratchet.decrypt_payload(&envelope).unwrap();
    assert_eq!(payload_type, PAYLOAD_ROUTING_ID_ANNOUNCE);
    let received = RoutingIdAnnounce::decode(&content).unwrap();
    assert_eq!(received.routing_id, alice_routing_id);
    let bob_updated = db_bob
        .record_peer_routing_id(&alice_fp, received.routing_id)
        .unwrap();
    bob_conn
        .send(
            FrameTag::MailboxDelete,
            &MailboxDelete {
                mailbox_id: bootstrap_mailbox_id(&bob_fp).to_vec(),
                entry_id: entries.entries[0].entry_id.clone(),
            },
        )
        .await;
    let (_, ack): (_, Ack) = bob_conn.recv().await;
    assert!(ack.ok);

    // Now Bob can reply with his own announce — still addressed to
    // Alice's bootstrap mailbox, since she hasn't transitioned yet either.
    let bob_announce_envelope = bob_ratchet
        .encrypt_payload(
            PAYLOAD_ROUTING_ID_ANNOUNCE,
            &RoutingIdAnnounce {
                routing_id: bob_routing_id.clone(),
            }
            .encode(),
        )
        .unwrap();
    bob_conn
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: bootstrap_mailbox_id(&alice_fp).to_vec(),
                envelope: bob_announce_envelope.encode(),
                ttl: 86_400,
            },
        )
        .await;
    let (_, ack): (_, Ack) = bob_conn.recv().await;
    assert!(ack.ok);

    alice_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: bootstrap_mailbox_id(&alice_fp).to_vec(),
            },
        )
        .await;
    let (_, entries): (_, MailboxEntries) = alice_conn.recv().await;
    assert_eq!(entries.entries.len(), 1);
    let envelope = Envelope::decode(&entries.entries[0].envelope).unwrap();
    let (payload_type, content) = alice_ratchet.decrypt_payload(&envelope).unwrap();
    assert_eq!(payload_type, PAYLOAD_ROUTING_ID_ANNOUNCE);
    let received = RoutingIdAnnounce::decode(&content).unwrap();
    assert_eq!(received.routing_id, bob_routing_id);
    let alice_updated = db_alice
        .record_peer_routing_id(&bob_fp, received.routing_id)
        .unwrap();
    alice_conn
        .send(
            FrameTag::MailboxDelete,
            &MailboxDelete {
                mailbox_id: bootstrap_mailbox_id(&alice_fp).to_vec(),
                entry_id: entries.entries[0].entry_id.clone(),
            },
        )
        .await;
    let (_, ack): (_, Ack) = alice_conn.recv().await;
    assert!(ack.ok);

    // --- The actual claim: both independently converge on the identical
    // mailbox id, computed with no coordination beyond the two routing
    // ids each already had. ---
    assert_eq!(alice_updated.mailbox_id, bob_updated.mailbox_id);
    assert_eq!(
        alice_updated.mailbox_id,
        compute_mailbox_id(&alice_routing_id, &bob_routing_id).to_vec()
    );

    // --- And a chat message sent after the transition is not retrievable
    // from the old bootstrap mailbox — the conversation has genuinely
    // moved, not just gained a second address. ---
    let post_transition_mailbox = alice_updated.mailbox_id.clone();
    let chat_envelope = alice_ratchet
        .encrypt_payload(PAYLOAD_CHAT, b"we've moved")
        .unwrap();
    alice_conn
        .send(
            FrameTag::MailboxWrite,
            &MailboxWrite {
                mailbox_id: post_transition_mailbox.clone(),
                envelope: chat_envelope.encode(),
                ttl: 86_400,
            },
        )
        .await;
    let (_, ack): (_, Ack) = alice_conn.recv().await;
    assert!(ack.ok);

    bob_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: bootstrap_mailbox_id(&bob_fp).to_vec(),
            },
        )
        .await;
    let (_, entries): (_, MailboxEntries) = bob_conn.recv().await;
    assert!(
        entries.entries.is_empty(),
        "the post-transition chat message must not be sitting in the old bootstrap mailbox"
    );

    bob_conn
        .send(
            FrameTag::MailboxFetch,
            &MailboxFetch {
                mailbox_id: post_transition_mailbox,
            },
        )
        .await;
    let (_, entries): (_, MailboxEntries) = bob_conn.recv().await;
    assert_eq!(entries.entries.len(), 1);
    let envelope = Envelope::decode(&entries.entries[0].envelope).unwrap();
    let (payload_type, content) = bob_ratchet.decrypt_payload(&envelope).unwrap();
    assert_eq!(payload_type, PAYLOAD_CHAT);
    assert_eq!(content, b"we've moved");
}
