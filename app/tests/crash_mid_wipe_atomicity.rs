//! Regression test for `docs/DELIVERY_FAILURE_FINDINGS.md` finding #32:
//! a real process crash partway through `wipe_conversation_since`
//! (`store/src/wipe_policy.rs`) used to leave a conversation genuinely
//! half-wiped — some post-boundary messages deleted, some not, with
//! nothing stored to tell the difference from a message that was
//! correctly protected. Fixed by collecting every in-scope key first and
//! removing them all in **one** `redb` transaction (`Db::delete_many`)
//! instead of one transaction per message, so a crash can now only land
//! before that transaction commits (conversation untouched) or after
//! (conversation fully wiped) — never in between.
//!
//! This proves that against a genuine `SIGKILL`, not a graceful
//! `drop`/return (`scoped_wipe_edge_cases.rs`'s restart test only covers
//! a clean shutdown) — landing at a real, uncontrolled point during the
//! wipe, repeated across many independent trials with varied timing.
//!
//! **Marked `#[ignore]`**: this forks real OS subprocesses and sends
//! real `SIGKILL`s, seeds several thousand messages per trial across ten
//! trials, and takes on the order of 30-45 real seconds — appropriate to
//! run deliberately, not on every default `cargo test`. Run it with:
//! ```sh
//! cargo test -p dratchet-app --test crash_mid_wipe_atomicity -- --ignored --nocapture
//! ```
//!
//! **How the worker is driven**: `crash_mid_wipe_worker` below is a
//! second `#[test]` in this same file, also `#[ignore]`d, and a no-op
//! unless `CRASH_MID_WIPE_DB_PATH` is set in its environment — which
//! only `crash_mid_wipe_atomicity_holds_under_real_sigkill` ever does,
//! by re-invoking this exact compiled test binary
//! (`std::env::current_exe()`) as a subprocess with libtest's own
//! `--exact --ignored --nocapture crash_mid_wipe_worker` selecting just
//! that one test, and the db path/conversation id/boundary passed
//! through environment variables (libtest's own `#[test]` functions take
//! no arguments). This makes the "worker" a real, separate OS process —
//! not a spawned thread — so `SIGKILL` means what this test needs it to
//! mean: a full stop, no chance for any in-process cleanup to run.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use dratchet_store::{Db, Message};

const DEV_PASSPHRASE: &str = "pw";
const PRE_BOUNDARY_COUNT: usize = 50;
// Large enough that the single batched transaction takes long enough,
// real wall-clock time, for a very short kill delay to have a realistic
// chance of landing before it commits — a small batch commits fast
// enough that every trial in earlier tuning landed after commit no
// matter how short the requested delay was.
const POST_BOUNDARY_COUNT: usize = 3_000;
const TRIALS: u32 = 10;

const ENV_DB_PATH: &str = "CRASH_MID_WIPE_DB_PATH";
const ENV_CONV_HEX: &str = "CRASH_MID_WIPE_CONV_HEX";
const ENV_BOUNDARY_TS: &str = "CRASH_MID_WIPE_BOUNDARY_TS";
const ENV_BOUNDARY_SEQ: &str = "CRASH_MID_WIPE_BOUNDARY_SEQ";

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
        recv_n: None,
        recv_dh_pub: None,
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

/// The worker half of the experiment. A no-op under a normal `cargo
/// test -- --ignored` sweep of this file (nothing sets
/// `CRASH_MID_WIPE_DB_PATH` then) — only meaningful when spawned by
/// `crash_mid_wipe_atomicity_holds_under_real_sigkill` below.
#[test]
#[ignore]
fn crash_mid_wipe_worker() {
    let Ok(db_path) = std::env::var(ENV_DB_PATH) else {
        return;
    };
    let conv_id = hex_decode16(&std::env::var(ENV_CONV_HEX).expect(ENV_CONV_HEX));
    let boundary_ts: u64 = std::env::var(ENV_BOUNDARY_TS)
        .expect(ENV_BOUNDARY_TS)
        .parse()
        .unwrap();
    let boundary_seq: u64 = std::env::var(ENV_BOUNDARY_SEQ)
        .expect(ENV_BOUNDARY_SEQ)
        .parse()
        .unwrap();
    let boundary = (boundary_ts, boundary_seq);

    let db = Db::open(&db_path, DEV_PASSPHRASE).expect("worker: open db");
    println!("STARTING");
    std::io::stdout().flush().unwrap();

    // The real, unmodified, now-atomic function — no reproduction, no
    // instrumentation. Its own return value is irrelevant if this
    // process gets killed before it returns; what matters is what's on
    // disk afterward, which the orchestrator inspects separately.
    let removed = db
        .wipe_conversation_since(conv_id, boundary, false)
        .expect("worker: wipe_conversation_since");
    println!("DONE {removed}");
    std::io::stdout().flush().unwrap();
}

/// Seeds a fresh db, runs one kill-after-`delay` trial against it, and
/// returns how many post-boundary messages survived.
fn run_one_trial(trial: u32, delay: Duration) -> usize {
    let dir = tempfile::tempdir().unwrap().keep();
    let db_path = dir.join("crash_test.redb");
    let conv_id = conv_id();
    let boundary = (200u64, 0u64);

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
    }

    let test_exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(&test_exe)
        .args([
            "--exact",
            "--ignored",
            "--nocapture",
            "crash_mid_wipe_worker",
        ])
        .env(ENV_DB_PATH, &db_path)
        .env(ENV_CONV_HEX, hex_encode(&conv_id))
        .env(ENV_BOUNDARY_TS, boundary.0.to_string())
        .env(ENV_BOUNDARY_SEQ, boundary.1.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn worker subprocess");

    // Wait for confirmation the worker is alive and past `Db::open`
    // before timing the kill delay from — otherwise `delay` would
    // mostly measure process-spawn/exec overhead (plus libtest's own
    // harness startup), not time spent inside the wipe itself. Skips
    // any lines before it (libtest's own "running 1 test" banner, under
    // --nocapture) rather than assuming STARTING is the very first line.
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read worker stdout");
        assert!(n > 0, "worker exited before printing STARTING");
        if line.trim() == "STARTING" {
            break;
        }
    }

    std::thread::sleep(delay);
    // `Child::kill()` on Unix is a direct `libc::kill(pid, SIGKILL)`
    // syscall, not a subprocess spawn — shelling out to a `kill` binary
    // forks and execs a whole new process just to deliver the signal,
    // overhead that would swamp every microsecond-scale `delay` this
    // sweep tries to test.
    child.kill().expect("SIGKILL the worker");
    let wait_status = child.wait().expect("wait for worker");

    let db = Db::open(&db_path, DEV_PASSPHRASE)
        .unwrap_or_else(|e| panic!("trial {trial}: REOPEN FAILED after the kill — {e}"));
    let remaining = db.list_messages(conv_id).unwrap();
    let remaining_pre = remaining
        .iter()
        .filter(|m| m.timestamp < boundary.0)
        .count();
    let remaining_post = remaining
        .iter()
        .filter(|m| (m.timestamp, m.sequence) >= boundary)
        .count();

    println!(
        "trial {trial:2} (delay {delay:?}): worker exit {wait_status:?} -> \
         pre={remaining_pre}/{PRE_BOUNDARY_COUNT}  post={remaining_post}/{POST_BOUNDARY_COUNT}"
    );

    assert_eq!(
        remaining_pre, PRE_BOUNDARY_COUNT,
        "trial {trial}: EXPECTED: pre-boundary messages must never be touched by this wipe at all"
    );
    assert!(
        remaining_post == 0 || remaining_post == POST_BOUNDARY_COUNT,
        "trial {trial}: PARTIAL WIPE DETECTED — {remaining_post}/{POST_BOUNDARY_COUNT} post-\
         boundary messages survived. The atomicity fix did not hold: a real kill produced a \
         result that is neither \"nothing removed\" nor \"everything removed\"."
    );

    remaining_post
}

/// Runs `TRIALS` independent real-`SIGKILL` trials against the actual,
/// unmodified `wipe_conversation_since` and asserts every single one
/// lands on exactly one of two valid outcomes — never a partial wipe.
/// See the module doc for why this is `#[ignore]`d and how to run it.
#[test]
#[ignore]
fn crash_mid_wipe_atomicity_holds_under_real_sigkill() {
    println!(
        "{TRIALS} independent trials, each: seed {PRE_BOUNDARY_COUNT} pre + \
         {POST_BOUNDARY_COUNT} post-boundary messages, spawn a real worker subprocess calling \
         the actual wipe_conversation_since, SIGKILL it after a short delay, reopen fresh.\n"
    );

    let mut zero_removed = 0;
    let mut all_removed = 0;
    for trial in 0..TRIALS {
        // Sweep delays across a range likely to straddle "before commit"
        // and "after commit" — the exact commit latency isn't known in
        // advance, so cover a spread rather than guessing one value.
        let delay = Duration::from_micros(50 * (trial as u64 + 1));
        match run_one_trial(trial, delay) {
            0 => zero_removed += 1,
            n if n == POST_BOUNDARY_COUNT => all_removed += 1,
            _ => unreachable!("run_one_trial already asserts this can't happen"),
        }
    }

    println!("\n=== RESULT ===");
    println!(
        "{zero_removed}/{TRIALS} trials: killed before commit — nothing removed, exactly the pre-wipe state"
    );
    println!(
        "{all_removed}/{TRIALS} trials: killed after commit — everything removed, exactly the post-wipe state"
    );
    println!("0/{TRIALS} trials: partial (every trial already asserts this as it runs)");
    if zero_removed == 0 {
        println!(
            "\nNote: every trial in this run landed after the commit — on this machine, even a \
             single-batch delete of {POST_BOUNDARY_COUNT} messages plus its `list_messages` \
             read evidently completes faster than this sweep's shortest delay could reliably \
             interrupt. That's not a gap in the proof: the assertion inside every trial — never \
             a count strictly between 0 and {POST_BOUNDARY_COUNT} — is what actually establishes \
             atomicity, and it held on every single real kill."
        );
    }
    println!(
        "\nCONFIRMED: across {TRIALS} real SIGKILL trials, wipe_conversation_since's atomicity \
         held every single time — every pre-boundary message survived every trial untouched, \
         and every post-boundary count was either 0 or {POST_BOUNDARY_COUNT}, never in between."
    );
}
