//! DRAtchet reference CLI client — see `Cargo.toml`'s description and
//! `client/README.md` for what this is and isn't. Two clients (A and B),
//! each running this binary against the same `dratchetd`, pair directly
//! with each other (Option B, `docs/ARCHITECTURE.md` §6.3a — X3DH runs
//! client-to-client, never through the server) and then chat over the
//! Tier 1 mailbox.

use std::io::{self, Write};

use clap::Parser;
use dratchet_client::{handshake, net::Connection, pairing};
use dratchet_core::account::Account;
use dratchet_core::ratchet::RatchetState;
use dratchet_server::protocol::*;
use tokio::io::{AsyncBufReadExt, BufReader};

/// DRAtchet reference CLI client — pairs directly with a peer (no directory,
/// no server-mediated key exchange) and chats over the Tier 1 mailbox.
#[derive(Parser, Debug)]
#[command(name = "dratchet-cli", version, about)]
struct Args {
    /// WebSocket URL of the Signaling & Presence Service.
    #[arg(long, default_value = "ws://127.0.0.1:8787/v1/ws")]
    server: String,
}

const MAILBOX_TTL_SECS: u32 = 86_400;
const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    if let Err(e) = run(&args).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(args: &Args) -> Result<(), String> {
    println!("Generating a fresh identity for this session...");
    let mut account = Account::generate().map_err(|e| e.to_string())?;
    account.generate_one_time_prekeys(1);
    let my_routing_id = handshake::random_routing_id();

    println!("Connecting to {}...", args.server);
    let mut conn = Connection::connect(&args.server).await?;
    conn.authenticate(&account).await?;
    println!("Authenticated (no directory registration needed).\n");

    let role = prompt("Are you scanning your peer's pairing code, or waiting for them to scan yours? [scan/wait]: ");
    let (ratchet, mailbox_id) = match role.trim().to_lowercase().as_str() {
        "scan" => pair_as_initiator(&account, &my_routing_id)?,
        _ => pair_as_responder(&mut account, &my_routing_id)?,
    };

    println!("\nPaired. Mailbox id: {}", hex(&mailbox_id));
    println!("Type a message and press Enter to send it. /quit to exit.\n");

    chat_loop(&mut conn, ratchet, mailbox_id).await
}

fn pair_as_initiator(
    account: &Account,
    my_routing_id: &[u8],
) -> Result<(RatchetState, Vec<u8>), String> {
    let blob = prompt("Paste the pairing bundle your peer shared: ");
    let peer_bundle: pairing::PairingBundle = pairing::decode_blob(&blob)?;
    let (ratchet, response) = handshake::initiate(account, &peer_bundle, my_routing_id.to_vec())?;

    println!("\nShare this pairing response with your peer:\n");
    println!("{}\n", pairing::encode_blob(&response));

    let mailbox_id = dratchet_core::conversation_id(my_routing_id, &peer_bundle.routing_id);
    Ok((ratchet, mailbox_id.to_vec()))
}

fn pair_as_responder(
    account: &mut Account,
    my_routing_id: &[u8],
) -> Result<(RatchetState, Vec<u8>), String> {
    let bundle = handshake::build_pairing_bundle(account, my_routing_id.to_vec())?;
    println!("\nShare this pairing bundle with your peer:\n");
    println!("{}\n", pairing::encode_blob(&bundle));

    let blob = prompt("Paste the pairing response your peer sends back: ");
    let peer_response: pairing::PairingResponse = pairing::decode_blob(&blob)?;
    let ratchet = handshake::respond(account, &peer_response)?;

    let mailbox_id = dratchet_core::conversation_id(my_routing_id, &peer_response.routing_id);
    Ok((ratchet, mailbox_id.to_vec()))
}

async fn chat_loop(
    conn: &mut Connection,
    mut ratchet: RatchetState,
    mailbox_id: Vec<u8>,
) -> Result<(), String> {
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    let mut poll = tokio::time::interval(POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            line = stdin.next_line() => {
                let Some(line) = line.map_err(|e| e.to_string())? else {
                    break; // stdin closed
                };
                if line.trim() == "/quit" {
                    break;
                }
                if line.is_empty() {
                    continue;
                }
                // A single failed send (e.g. the responder side trying to
                // send before it's received anything — the ratchet has no
                // sending chain yet until then, standard Double Ratchet
                // behavior, see client/README.md) must not take down the
                // whole session: report it and keep chatting.
                if let Err(e) = send_message(conn, &mut ratchet, &mailbox_id, &line).await {
                    eprintln!("(could not send: {e})");
                }
            }
            _ = poll.tick() => {
                if let Err(e) = receive_pending(conn, &mut ratchet, &mailbox_id).await {
                    eprintln!("(could not check for messages: {e})");
                }
            }
        }
    }
    Ok(())
}

async fn send_message(
    conn: &mut Connection,
    ratchet: &mut RatchetState,
    mailbox_id: &[u8],
    text: &str,
) -> Result<(), String> {
    let envelope = ratchet
        .encrypt_payload(PAYLOAD_CHAT, text.as_bytes())
        .map_err(|e| e.to_string())?;
    conn.send(
        FrameTag::MailboxWrite,
        &MailboxWrite {
            mailbox_id: mailbox_id.to_vec(),
            envelope: envelope.encode(),
            ttl: MAILBOX_TTL_SECS,
        },
    )
    .await?;
    let (tag, ack): (_, Ack) = conn.recv().await?;
    if tag != FrameTag::Ack || !ack.ok {
        eprintln!("(send failed)");
    }
    Ok(())
}

/// Chat message content, per `MESSAGE_SCHEMA.md` §2's `payload_type` tag.
const PAYLOAD_CHAT: u8 = 0;

async fn receive_pending(
    conn: &mut Connection,
    ratchet: &mut RatchetState,
    mailbox_id: &[u8],
) -> Result<(), String> {
    conn.send(
        FrameTag::MailboxFetch,
        &MailboxFetch {
            mailbox_id: mailbox_id.to_vec(),
        },
    )
    .await?;
    let (tag, entries): (_, MailboxEntries) = conn.recv().await?;
    if tag != FrameTag::MailboxEntries {
        return Ok(());
    }

    for entry in entries.entries {
        let Ok(envelope) = dratchet_core::envelope::Envelope::decode(&entry.envelope) else {
            continue; // corrupted in transit — nothing to do but skip it
        };
        // A message this same client sent (the mailbox is shared by both
        // directions under Option B) fails to decrypt here: this ratchet
        // has no receiving chain for its own outgoing dh_pub. That's a
        // safe, expected outcome, not a bug — see client/README.md — so a
        // decrypt failure is only ever a silent skip, never a delete: only
        // the actual intended recipient, on a successful decrypt, removes
        // an entry.
        let Ok((payload_type, content)) = ratchet.decrypt_payload(&envelope) else {
            continue;
        };
        if payload_type == PAYLOAD_CHAT {
            if let Ok(text) = String::from_utf8(content) {
                println!("peer: {text}");
            }
        }
        conn.send(
            FrameTag::MailboxDelete,
            &MailboxDelete {
                mailbox_id: mailbox_id.to_vec(),
                entry_id: entry.entry_id,
            },
        )
        .await?;
        let _: (FrameTag, Ack) = conn.recv().await?;
    }
    Ok(())
}

fn prompt(message: &str) -> String {
    print!("{message}");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().read_line(&mut line).ok();
    line.trim().to_string()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
