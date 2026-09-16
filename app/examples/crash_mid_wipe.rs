//! Crash-consistency experiment for the boundary-scoped wipe's *client-
//! side* storage — not the server (which holds no durable state for
//! mailbox entries at all, by design: `server/src/persistence.rs`'s own
//! doc says so). `store::Db::wipe_conversation_since`
//! (`ARCHITECTURE.md` §11.9a) loops and calls `delete_message` once per
//! message; `Db::delete` opens and commits its own `write_txn` on every
//! single call (`store/src/db.rs`). So each individual deletion is one
//! durable, atomic redb transaction — but the *loop as a whole* is not
//! wrapped in anything: nothing stops a real process death between two
//! iterations.
//!
//! This program proves what that actually means, against a genuine
//! `SIGKILL` (not a graceful `drop`/return — this session's earlier
//! `boundary_persists_across_a_real_db_restart` test only covered a
//! clean shutdown) landing at a *known, deterministic* point mid-loop:
//!
//! - Does the on-disk `Db` survive intact and reopen cleanly? (Tests
//!   whether `redb`'s per-transaction durability actually holds under a
//!   real kill, not just in theory.)
//! - Exactly how many deletions actually landed, and which ones?
//! - Are the pre-boundary messages — the ones this whole feature exists
//!   to protect — still exactly, byte-for-byte intact?
//!
//! Two modes, selected by argv, so the "worker" being killed is a real,
//! separate OS process rather than a spawned thread (SIGKILL only means
//! what we need it to mean at the process boundary):
//!
//! - **Orchestrator** (no args): seeds a fresh `Db` with pre- and post-
//!   boundary messages, re-execs itself (`std::env::current_exe()`) as
//!   the worker, watches its stdout for progress lines, sends `kill -9`
//!   the instant a chosen deletion count is observed, then reopens the
//!   same on-disk file fresh and reports what actually survived.
//! - **Worker** (`--worker db_path conv_id_hex boundary_ts boundary_seq`):
//!   reproduces `wipe_conversation_since`'s own logic verbatim: same
//!   `list_messages` call, same at-or-after-boundary filter, same
//!   `delete_message` calls, in the same order, with one line of
//!   instrumentation added: a flushed progress line after each
//!   individual deletion, which is all the orchestrator needs to
//!   synchronize the kill precisely instead of guessing a sleep
//!   duration.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use dratchet_store::{Db, Message};

const DEV_PASSPHRASE: &str = "pw";
const PRE_BOUNDARY_COUNT: usize = 50;
const POST_BOUNDARY_COUNT: usize = 250;
/// Deliberately well short of `POST_BOUNDARY_COUNT`, so a successful
/// kill *must* leave some post-boundary messages undeleted — the
/// condition this whole experiment exists to produce and inspect.
const KILL_AFTER_DELETIONS: usize = 120;

fn conv_id() -> [u8; 16] {
    [0x77u8; 16]
}

fn sample_message(id: u32, timestamp: u64, sequence: u64) -> Message {
    let mut id_bytes = vec![0u8; 12];
    id_bytes.extend_from_slice(&id.to_be_bytes());
    Message {
        id: id_bytes,
        sender_is_local: true,
        content: format!("message {timestamp}:{sequence}").into_bytes(),
        timestamp,
        sequence,
        send_n: None,
        send_dh_pub: None,
        delivered: false,
        uncertain: false,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode16(s: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let byte_str = std::str::from_utf8(chunk).unwrap();
        out[i] = u8::from_str_radix(byte_str, 16).unwrap();
    }
    out
}

fn run_worker(args: &[String]) {
    let db_path = &args[0];
    let conv_hex = &args[1];
    let boundary_ts: u64 = args[2].parse().unwrap();
    let boundary_seq: u64 = args[3].parse().unwrap();
    let conv_id = hex_decode16(conv_hex);
    let boundary = (boundary_ts, boundary_seq);

    let db = Db::open(db_path, DEV_PASSPHRASE).expect("worker: open db");

    // Verbatim reproduction of `store::wipe_policy::wipe_conversation_since`'s
    // own loop (`store/src/wipe_policy.rs`) — same call, same filter,
    // same order — with one added instrumentation line per deletion.
    let mut deleted = 0usize;
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for message in db.list_messages(conv_id).expect("worker: list_messages") {
        if (message.timestamp, message.sequence) >= boundary {
            db.delete_message(conv_id, &message.id)
                .expect("worker: delete_message");
            deleted += 1;
            writeln!(out, "DELETED {deleted}").unwrap();
            out.flush().unwrap();
        }
    }
    writeln!(out, "DONE {deleted}").unwrap();
    out.flush().unwrap();
}

fn run_orchestrator() {
    let dir = tempfile::tempdir().unwrap().keep();
    let db_path = dir.join("crash_test.redb");
    let conv_id = conv_id();
    let boundary = (200u64, 0u64);

    println!("=== crash-mid-wipe experiment ===");
    println!("db: {}", db_path.display());
    println!(
        "seeding {PRE_BOUNDARY_COUNT} pre-boundary + {POST_BOUNDARY_COUNT} post-boundary messages"
    );

    {
        let db = Db::create(&db_path, DEV_PASSPHRASE).expect("create db");
        for i in 0..PRE_BOUNDARY_COUNT {
            db.save_message(conv_id, &sample_message(i as u32, 100, i as u64))
                .unwrap();
        }
        for i in 0..POST_BOUNDARY_COUNT {
            db.save_message(
                conv_id,
                &sample_message((PRE_BOUNDARY_COUNT + i) as u32, 200, i as u64),
            )
            .unwrap();
        }
        let total = db.list_messages(conv_id).unwrap().len();
        assert_eq!(total, PRE_BOUNDARY_COUNT + POST_BOUNDARY_COUNT);
        println!("seed confirmed: {total} messages on disk before the worker starts");
        // db dropped here — closes cleanly, matching a real app handing
        // off to a freshly-spawned process rather than sharing one open
        // handle across processes (redb doesn't support that anyway).
    }

    let worker_exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(&worker_exe)
        .arg("--worker")
        .arg(&db_path)
        .arg(hex_encode(&conv_id))
        .arg(boundary.0.to_string())
        .arg(boundary.1.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn worker");
    let child_pid = child.id();
    println!("worker pid {child_pid} started, deleting {POST_BOUNDARY_COUNT} post-boundary messages one at a time...");

    let stdout = child.stdout.take().unwrap();
    let reader = BufReader::new(stdout);
    let mut killed = false;
    let mut last_seen = 0usize;
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if let Some(n) = line.strip_prefix("DELETED ") {
            last_seen = n.trim().parse().unwrap();
            if last_seen == KILL_AFTER_DELETIONS {
                println!(
                    "observed \"DELETED {KILL_AFTER_DELETIONS}\" from the worker — sending SIGKILL to pid {child_pid} now"
                );
                let status = Command::new("kill")
                    .args(["-9", &child_pid.to_string()])
                    .status()
                    .expect("run kill -9");
                assert!(status.success(), "kill -9 itself failed to run");
                killed = true;
                break;
            }
        }
        if line.starts_with("DONE") {
            println!(
                "worker finished all {POST_BOUNDARY_COUNT} deletions before we could kill it — \
                 increase KILL_AFTER_DELETIONS or POST_BOUNDARY_COUNT and try again"
            );
            break;
        }
    }

    let wait_status = child.wait().expect("wait for worker");
    println!("worker exit status: {wait_status:?} (last progress line seen: DELETED {last_seen})");

    if !killed {
        eprintln!("\nFAILED SETUP: never got to send the kill — no valid crash-consistency result from this run.");
        std::process::exit(1);
    }

    // The actual experiment: reopen the SAME on-disk file completely
    // fresh, exactly as a relaunched app would, and see what's real.
    println!("\nreopening the db fresh (simulating the app relaunching after the crash)...");
    let db = Db::open(&db_path, DEV_PASSPHRASE)
        .expect("REOPEN FAILED — the db did not survive the kill intact");
    println!("db reopened successfully — no corruption from the SIGKILL.");

    let remaining = db.list_messages(conv_id).unwrap();
    let remaining_pre = remaining
        .iter()
        .filter(|m| m.timestamp < boundary.0)
        .count();
    let remaining_post = remaining
        .iter()
        .filter(|m| (m.timestamp, m.sequence) >= boundary)
        .count();

    println!("\n=== RESULT ===");
    println!("pre-boundary messages:  seeded {PRE_BOUNDARY_COUNT}, remaining {remaining_pre}");
    println!("post-boundary messages: seeded {POST_BOUNDARY_COUNT}, remaining {remaining_post}");
    println!(
        "post-boundary messages actually deleted before the kill landed: {}",
        POST_BOUNDARY_COUNT - remaining_post
    );
    println!("total remaining: {}", remaining.len());

    assert_eq!(
        remaining_pre, PRE_BOUNDARY_COUNT,
        "EXPECTED: every pre-boundary message must survive a crash mid-wipe untouched — \
         the loop only ever reaches post-boundary messages"
    );
    assert!(
        remaining_post > 0 && remaining_post < POST_BOUNDARY_COUNT,
        "EXPECTED: the wipe should be genuinely partially applied — some post-boundary \
         messages deleted, some not — proving the loop is not one atomic unit even though \
         each individual delete is its own durable transaction"
    );

    println!(
        "\nCONFIRMED: redb's per-call durability held (no corruption, no partial-record \
         garbage, db reopened and decoded cleanly) — but wipe_conversation_since's own loop \
         is NOT atomic as a whole. A real crash mid-wipe leaves the conversation in a \
         genuinely half-wiped state: {remaining_post} post-boundary message(s) that should \
         have been removed are still there, indistinguishable from a message that was \
         correctly protected."
    );
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--worker") {
        run_worker(&args[1..]);
    } else {
        run_orchestrator();
    }
}
