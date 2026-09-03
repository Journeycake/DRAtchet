//! The Signaling & Presence Service's single WebSocket connection handler —
//! all four jobs from `docs/SERVERS.md` §1.1 (directory, rendezvous,
//! mailbox, presence) multiplexed over one persistent connection per
//! device, per §1.2.
//!
//! **Auth model, and why `PublishBundle` doesn't require it first (a real
//! design decision, not an oversight):** the connection-level auth handshake
//! (nonce + signature, §1.2) is the only thing that binds a socket to an
//! identity, and it must be tied to a *fresh, per-connection* nonce — a
//! signature over anything reusable (like a previously-published bundle's
//! own bytes) could be replayed by an observer who never held the private
//! key, silently hijacking presence/mailbox/rendezvous access for that
//! identity. So `PublishBundle` is deliberately **not** a way to authenticate
//! a connection — it's validated purely by the bundle's own internal
//! signature chain (`identity_dh_signature`/`signed_prekey_sig`, both
//! checked via `dratchet_core::prekey::PrekeyBundle::verify`), the same
//! self-contained check `core::x3dh::initiate` already does before trusting
//! a fetched bundle. That makes it safe to allow on any connection,
//! authenticated or not — it only ever adds already-labeled-public data to
//! the directory, never grants privilege. Presence, rendezvous, and mailbox
//! operations all separately require the nonce-signature auth to have
//! succeeded on *this* connection.

use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tracing::debug;
use x25519_dalek::PublicKey;

use dratchet_core::identity;
use dratchet_core::prekey::{
    OneTimePrekeyPublic, PrekeyBundle as CorePrekeyBundle, SignedPrekeyPublic,
};

use crate::abuse::{self, ConnectionId};
use crate::error::{Error, Result};
use crate::protocol::*;
use crate::state::{
    now_unix, prune_expired, random_16, random_32, AppState, Fingerprint, MailboxEntry,
    PresenceState, StoredBundle, UsernameKey,
};

/// Log a warning every `N`th `FetchBundle` that lands on an empty one-time-
/// prekey pool for the same target — a coarse, best-effort signal, not a
/// precise attack detector (see `state.rs`'s doc on `otp_exhaustion_attempts`
/// for the caveat that a never-published pool looks the same as an
/// exhausted one here).
const OTP_EXHAUSTION_ALERT_THRESHOLD: u32 = 10;

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (mut ws_sender, mut ws_receiver) = socket.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let send_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if ws_sender.send(Message::Binary(bytes)).await.is_err() {
                break;
            }
        }
    });

    let nonce = random_32();
    let _ = tx.send(encode(
        FrameTag::AuthChallenge,
        &AuthChallenge {
            nonce: nonce.to_vec(),
        },
    ));

    // Identifies this connection for the rate limiter (`crate::abuse`) only
    // — unrelated to the auth nonce above, and never sent to the client.
    let connection_id: ConnectionId = random_16();

    let mut authenticated: Option<Fingerprint> = None;

    loop {
        let Some(next) = ws_receiver.next().await else {
            break;
        };
        let msg = match next {
            Ok(m) => m,
            Err(_) => break,
        };
        let frame = match msg {
            Message::Binary(b) => b,
            Message::Close(_) => break,
            _ => continue, // text/ping/pong: not part of this protocol, ignored rather than treated as fatal
        };

        let (tag, body) = match split_tag(&frame) {
            Ok(t) => t,
            Err(e) => {
                debug!("malformed frame from client: {e}");
                let _ = tx.send(encode(
                    FrameTag::Error,
                    &ErrorFrame {
                        message: e.to_string(),
                    },
                ));
                continue;
            }
        };

        if let Err(e) = dispatch(
            tag,
            body,
            &state,
            &tx,
            &nonce,
            connection_id,
            &mut authenticated,
        )
        .await
        {
            let _ = tx.send(encode(
                FrameTag::Error,
                &ErrorFrame {
                    message: e.to_string(),
                },
            ));
        }
    }

    if let Some(fp) = authenticated {
        let last_seen = now_unix();
        let subscribers = {
            let mut inner = state.inner.write().await;
            inner
                .presence
                .insert(fp, PresenceState::Offline { last_seen });
            inner.connections.remove(&fp);
            inner.subscriptions.get(&fp).cloned().unwrap_or_default()
        };
        notify_presence(
            &state,
            fp,
            PresenceState::Offline { last_seen },
            &subscribers,
        )
        .await;
    }
    send_task.abort();
}

async fn dispatch(
    tag: FrameTag,
    body: &[u8],
    state: &Arc<AppState>,
    tx: &mpsc::UnboundedSender<Vec<u8>>,
    nonce: &[u8; 32],
    connection_id: ConnectionId,
    authenticated: &mut Option<Fingerprint>,
) -> Result<()> {
    match tag {
        FrameTag::AuthResponse => {
            if authenticated.is_some() {
                return Err(Error::AlreadyAuthenticated);
            }
            let req: AuthResponse = decode_body(body)?;
            let fp: Fingerprint = req
                .identity_fingerprint
                .as_slice()
                .try_into()
                .map_err(|_| Error::MalformedFrame("identity_fingerprint must be 32 bytes"))?;

            let public_key = {
                let inner = state.inner.read().await;
                inner
                    .directory
                    .get(&fp)
                    .map(|sb| sb.bundle.identity_key.clone())
                    .ok_or(Error::AuthFailed)?
            };
            identity::verify_signature(&public_key, nonce, &req.signature)
                .map_err(|_| Error::AuthFailed)?;

            *authenticated = Some(fp);
            let subscribers = {
                let mut inner = state.inner.write().await;
                inner.presence.insert(fp, PresenceState::Online);
                inner.connections.insert(fp, tx.clone());
                inner.subscriptions.get(&fp).cloned().unwrap_or_default()
            };
            let _ = tx.send(encode(FrameTag::Ack, &Ack { ok: true }));
            notify_presence(state, fp, PresenceState::Online, &subscribers).await;
            Ok(())
        }

        FrameTag::PublishBundle => {
            let req: PublishBundle = decode_body(body)?;
            publish_bundle(state, req.bundle).await
        }

        FrameTag::FetchBundle => {
            let req: FetchBundle = decode_body(body)?;
            let result = fetch_bundle(state, &req, *authenticated, connection_id).await?;
            let _ = tx.send(encode(FrameTag::BundleResult, &result));
            Ok(())
        }

        FrameTag::PresenceAnnounce => {
            let fp = authenticated.ok_or(Error::AuthRequired)?;
            let req: PresenceAnnounce = decode_body(body)?;
            let new_state = match req.state {
                0 => PresenceState::Online,
                1 => PresenceState::Away,
                _ => return Err(Error::MalformedFrame("unknown presence state")),
            };
            let subscribers = {
                let mut inner = state.inner.write().await;
                inner.presence.insert(fp, new_state);
                inner.subscriptions.get(&fp).cloned().unwrap_or_default()
            };
            notify_presence(state, fp, new_state, &subscribers).await;
            Ok(())
        }

        FrameTag::PresenceSubscribe => {
            let subscriber = authenticated.ok_or(Error::AuthRequired)?;
            let req: PresenceSubscribe = decode_body(body)?;
            let target: Fingerprint = req
                .identity_fingerprint
                .as_slice()
                .try_into()
                .map_err(|_| Error::MalformedFrame("identity_fingerprint must be 32 bytes"))?;

            let mut inner = state.inner.write().await;
            let has_evidence = inner
                .fetch_evidence
                .get(&subscriber)
                .is_some_and(|s| s.contains(&target));
            if !has_evidence {
                return Err(Error::AuthRequired);
            }
            inner
                .subscriptions
                .entry(target)
                .or_default()
                .insert(subscriber);
            let current = inner.presence.get(&target).copied();
            drop(inner);

            if let Some(state_now) = current {
                let (state_byte, last_seen) = presence_wire(state_now);
                let _ = tx.send(encode(
                    FrameTag::PresenceUpdate,
                    &PresenceUpdate {
                        identity_fingerprint: target.to_vec(),
                        state: state_byte,
                        last_seen,
                    },
                ));
            }
            Ok(())
        }

        FrameTag::RendezvousOffer => {
            let from = authenticated.ok_or(Error::AuthRequired)?;
            let req: RendezvousOffer = decode_body(body)?;
            let relayed = encode(
                FrameTag::RendezvousOffer,
                &RendezvousOffer {
                    peer_fingerprint: from.to_vec(),
                    sdp_offer: req.sdp_offer,
                    ice_candidates: req.ice_candidates,
                },
            );
            relay_to_peer(state, &req.peer_fingerprint, tx, relayed).await
        }

        FrameTag::RendezvousAnswer => {
            let from = authenticated.ok_or(Error::AuthRequired)?;
            let req: RendezvousAnswer = decode_body(body)?;
            let relayed = encode(
                FrameTag::RendezvousAnswer,
                &RendezvousAnswer {
                    peer_fingerprint: from.to_vec(),
                    sdp_answer: req.sdp_answer,
                    ice_candidates: req.ice_candidates,
                },
            );
            relay_to_peer(state, &req.peer_fingerprint, tx, relayed).await
        }

        FrameTag::MailboxWrite => {
            authenticated.ok_or(Error::AuthRequired)?;
            let req: MailboxWrite = decode_body(body)?;
            let mailbox_id: [u8; 16] = req
                .mailbox_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::MalformedFrame("mailbox_id must be 16 bytes"))?;
            let entry = MailboxEntry {
                entry_id: random_16(),
                envelope: req.envelope,
                expires_at: std::time::SystemTime::now() + crate::state::ttl_from_secs(req.ttl),
            };
            let mut inner = state.inner.write().await;
            inner.mailboxes.entry(mailbox_id).or_default().push(entry);
            drop(inner);
            let _ = tx.send(encode(FrameTag::Ack, &Ack { ok: true }));
            Ok(())
        }

        FrameTag::MailboxFetch => {
            authenticated.ok_or(Error::AuthRequired)?;
            let req: MailboxFetch = decode_body(body)?;
            let mailbox_id: [u8; 16] = req
                .mailbox_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::MalformedFrame("mailbox_id must be 16 bytes"))?;
            let mut inner = state.inner.write().await;
            let entries = inner.mailboxes.entry(mailbox_id).or_default();
            prune_expired(entries);
            let wire_entries: Vec<MailboxEntryWire> = entries
                .iter()
                .map(|e| MailboxEntryWire {
                    entry_id: e.entry_id.to_vec(),
                    envelope: e.envelope.clone(),
                })
                .collect();
            drop(inner);
            let _ = tx.send(encode(
                FrameTag::MailboxEntries,
                &MailboxEntries {
                    entries: wire_entries,
                },
            ));
            Ok(())
        }

        FrameTag::MailboxDelete => {
            authenticated.ok_or(Error::AuthRequired)?;
            let req: MailboxDelete = decode_body(body)?;
            let mailbox_id: [u8; 16] = req
                .mailbox_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::MalformedFrame("mailbox_id must be 16 bytes"))?;
            let entry_id: [u8; 16] = req
                .entry_id
                .as_slice()
                .try_into()
                .map_err(|_| Error::MalformedFrame("entry_id must be 16 bytes"))?;
            let mut inner = state.inner.write().await;
            if let Some(entries) = inner.mailboxes.get_mut(&mailbox_id) {
                entries.retain(|e| e.entry_id != entry_id);
            }
            drop(inner);
            let _ = tx.send(encode(FrameTag::Ack, &Ack { ok: true }));
            Ok(())
        }

        // Server-to-client-only tags received from a client: not part of the protocol.
        FrameTag::AuthChallenge
        | FrameTag::BundleResult
        | FrameTag::PresenceUpdate
        | FrameTag::MailboxEntries
        | FrameTag::Ack
        | FrameTag::Error => Err(Error::MalformedFrame(
            "this frame type is server-to-client only",
        )),
    }
}

async fn publish_bundle(state: &Arc<AppState>, wire: PrekeyBundleWire) -> Result<()> {
    let core_bundle = to_core_bundle(&wire, None)?;
    core_bundle
        .verify()
        .map_err(|_| Error::InvalidBundle("signature verification failed"))?;

    let fp = *identity::fingerprint_of_public_key(&wire.identity_key).as_bytes();
    let username_key = UsernameKey {
        username: wire.username.clone(),
        discriminator: wire.discriminator,
    };

    let mut inner = state.inner.write().await;
    match inner.username_index.get(&username_key) {
        // Already owned by this exact identity — a rotation/republish
        // (signed-prekey renewal, topping up one-time prekeys). No
        // proof-of-work required again; this is the common case.
        Some(&existing_fp) if existing_fp == fp => {}
        // Owned by a *different* identity — reject outright, regardless of
        // proof-of-work. `username#NNNN` is first-come-first-served
        // (`ARCHITECTURE.md` §11.8); without this check any later publish
        // for a taken username would silently reassign it, which is worse
        // than the squatting problem §11.8 actually names.
        Some(_) => return Err(Error::UsernameTaken),
        // Brand-new registration — require the registration proof-of-work
        // (`crate::abuse`), a PII-free floor against mass-registering
        // usernames to squat them.
        None => {
            let solved = wire.registration_pow.is_some_and(|solution| {
                abuse::verify_registration_pow(
                    &wire.username,
                    wire.discriminator,
                    &wire.identity_key,
                    solution,
                )
            });
            if !solved {
                return Err(Error::ProofOfWorkRequired);
            }
        }
    }

    let mut one_time_prekeys = std::collections::HashMap::new();
    for otp in &wire.one_time_prekeys {
        one_time_prekeys.insert(otp.id, otp.key.clone());
    }

    inner.username_index.insert(username_key, fp);
    inner.directory.insert(
        fp,
        StoredBundle {
            bundle: wire,
            one_time_prekeys,
        },
    );
    Ok(())
}

async fn fetch_bundle(
    state: &Arc<AppState>,
    req: &FetchBundle,
    fetcher: Option<Fingerprint>,
    connection_id: ConnectionId,
) -> Result<BundleResult> {
    let username_key = UsernameKey {
        username: req.username.clone(),
        discriminator: req.discriminator,
    };
    let mut inner = state.inner.write().await;
    let Some(&target_fp) = inner.username_index.get(&username_key) else {
        return Ok(BundleResult { bundle: None });
    };

    // Rate-limit *before* touching the one-time-prekey pool — a rejected
    // fetch must not itself consume anything (`crate::abuse`).
    if !inner.fetch_rate_limiter.allow(connection_id, target_fp) {
        return Err(Error::RateLimited);
    }

    let Some(stored) = inner.directory.get_mut(&target_fp) else {
        return Ok(BundleResult { bundle: None });
    };

    // Consume one one-time prekey if any remain — single-use, discard-after-use
    // (ARCHITECTURE.md §3.4) — before borrowing `stored.bundle` immutably below.
    let one_time_prekey = stored
        .one_time_prekeys
        .keys()
        .next()
        .copied()
        .and_then(|id| {
            stored
                .one_time_prekeys
                .remove(&id)
                .map(|key| OneTimePrekeyWire { id, key })
        });

    let b = &stored.bundle;
    let fetched = FetchedBundleWire {
        username: b.username.clone(),
        discriminator: b.discriminator,
        identity_key: b.identity_key.clone(),
        identity_dh_public: b.identity_dh_public.clone(),
        identity_dh_signature: b.identity_dh_signature.clone(),
        signed_prekey_id: b.signed_prekey_id,
        signed_prekey: b.signed_prekey.clone(),
        signed_prekey_sig: b.signed_prekey_sig.clone(),
        signed_prekey_expires_at: b.signed_prekey_expires_at,
        one_time_prekey,
    };

    if let Some(fetcher_fp) = fetcher {
        inner
            .fetch_evidence
            .entry(fetcher_fp)
            .or_default()
            .insert(target_fp);
    }

    if fetched.one_time_prekey.is_none() {
        let count = inner.otp_exhaustion_attempts.entry(target_fp).or_insert(0);
        *count += 1;
        if *count % OTP_EXHAUSTION_ALERT_THRESHOLD == 0 {
            tracing::warn!(
                target_fingerprint = %hex_encode(&target_fp),
                attempts = *count,
                "repeated fetches against an empty one-time-prekey pool for this account \
                 (ARCHITECTURE.md §11.8) — possible enumeration/exhaustion attempt; surfacing \
                 this to the affected account is future client work",
            );
        }
    }

    Ok(BundleResult {
        bundle: Some(fetched),
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Deliver an already-built frame to `to`'s live connection, if it has one —
/// rendezvous is direct relay-while-online only, with no store-and-forward
/// (that's what the Tier 1 mailbox is for). Acks the *original* sender with
/// whether delivery actually happened.
async fn relay_to_peer(
    state: &Arc<AppState>,
    to: &[u8],
    original_sender_tx: &mpsc::UnboundedSender<Vec<u8>>,
    frame: Vec<u8>,
) -> Result<()> {
    let to_fp: Fingerprint = to
        .try_into()
        .map_err(|_| Error::MalformedFrame("peer_fingerprint must be 32 bytes"))?;
    let inner = state.inner.read().await;
    let sent = match inner.connections.get(&to_fp) {
        Some(peer_tx) => peer_tx.send(frame).is_ok(),
        None => false,
    };
    drop(inner);
    let _ = original_sender_tx.send(encode(FrameTag::Ack, &Ack { ok: sent }));
    Ok(())
}

async fn notify_presence(
    state: &Arc<AppState>,
    who: Fingerprint,
    new_state: PresenceState,
    subscribers: &std::collections::HashSet<Fingerprint>,
) {
    if subscribers.is_empty() {
        return;
    }
    let (state_byte, last_seen) = presence_wire(new_state);
    let frame = encode(
        FrameTag::PresenceUpdate,
        &PresenceUpdate {
            identity_fingerprint: who.to_vec(),
            state: state_byte,
            last_seen,
        },
    );
    let inner = state.inner.read().await;
    for sub in subscribers {
        if let Some(sub_tx) = inner.connections.get(sub) {
            let _ = sub_tx.send(frame.clone());
        }
    }
}

fn presence_wire(s: PresenceState) -> (u8, Option<u64>) {
    match s {
        PresenceState::Online => (0, None),
        PresenceState::Away => (1, None),
        PresenceState::Offline { last_seen } => (2, Some(last_seen)),
    }
}

fn to_core_bundle(
    wire: &PrekeyBundleWire,
    one_time_prekey: Option<OneTimePrekeyPublic>,
) -> Result<CorePrekeyBundle> {
    let identity_dh_public: [u8; 32] = wire
        .identity_dh_public
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidBundle("identity_dh_public must be 32 bytes"))?;
    let signed_prekey_public: [u8; 32] = wire
        .signed_prekey
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidBundle("signed_prekey must be 32 bytes"))?;

    Ok(CorePrekeyBundle {
        identity_public_key: wire.identity_key.clone(),
        identity_dh_public: PublicKey::from(identity_dh_public),
        identity_dh_signature: wire.identity_dh_signature.clone(),
        signed_prekey: SignedPrekeyPublic {
            id: wire.signed_prekey_id,
            public: PublicKey::from(signed_prekey_public),
            signature: wire.signed_prekey_sig.clone(),
        },
        one_time_prekey,
    })
}
