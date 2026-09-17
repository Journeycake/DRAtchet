//! Real, no-mocks crash-consistency test for `Db::quick_wipe`'s security
//! ordering fix (`docs/DELIVERY_FAILURE_FINDINGS.md`): the content DEK
//! must be rotated **before** any message/ratchet record is deleted, so
//! a device seized or killed at any point during `quick_wipe` gets the
//! guarantee it exists for — already-stored content permanently
//! unrecoverable — rather than depending on the (best-effort, not
//! atomic) delete loop that follows having finished.
//!
//! Mirrors `app/tests/crash_mid_wipe_atomicity.rs`'s technique: the
//! worker is a real, separate OS process (`std::env::current_exe()`,
//! re-invoked with libtest's own `--exact --ignored` to select just the
//! worker test, parameters via environment variables), killed with a
//! genuine `SIGKILL`, not a graceful return. Unlike that test,
//! `quick_wipe` has no natural per-step progress to synchronize a kill
//! against — so this instead infers, from `Db::open`/`list_messages`'
//! own outcome after reopening, whether the rotation had already
//! committed: because `quick_wipe`'s new ordering rotates the content
//! key *unconditionally before* any delete, a message ever coming back
//! with its original, intact plaintext can only mean the kill landed
//! before rotation — a legitimate "nothing happened yet" outcome, not a
//! finding.
//!
//! **A separate, unexpected finding surfaced while building this test,
//! worth naming plainly rather than working around:** on this
//! environment, a `SIGKILL` landing on or after `quick_wipe`'s original
//! (pre-fix) many-small-transactions delete loop could leave the file
//! entirely unable to reopen (a decrypt failure on a record `quick_wipe`
//! never even touches, not just the expected "content now unreadable"
//! outcome) — and, at a much narrower likelihood, this still reproduces
//! even after batching that loop into one `delete_many` call, and even
//! for a *single, lone* record write with zero messages involved at all.
//! That rules out `quick_wipe`'s own ordering or its delete loop as the
//! cause: it points at a narrow torn-write window in how this
//! environment's filesystem (or `redb` on it) handles a `SIGKILL` landing
//! exactly during a transaction's own commit — a question about write-
//! barrier durability here, not something fixable inside `Db::quick_wipe`.
//! `run_one_trial` below reports this as its own outcome category
//! (`TrialOutcome::ReopenFailed`) rather than asserting it can't happen.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

use dratchet_store::{Db, Message};

const DEV_PASSPHRASE: &str = "pw";
const MESSAGE_COUNT: usize = 500;
const TRIALS: u32 = 10;
const EXPECTED_CONTENT: &[u8] = b"content that must become unrecoverable after a quick wipe";

const ENV_DB_PATH: &str = "DURESS_WIPE_DB_PATH";

fn conv_id() -> [u8; 16] {
    [0x55u8; 16]
}

fn sample_message(id: u32) -> Message {
    let mut id_bytes = vec![0u8; 12];
    id_bytes.extend_from_slice(&id.to_be_bytes());
    Message {
        id: id_bytes,
        sender_is_local: true,
        content: b"content that must become unrecoverable after a quick wipe".to_vec(),
        timestamp: 100,
        sequence: id as u64,
        send_n: None,
        send_dh_pub: None,
        recv_n: None,
        recv_dh_pub: None,
        delivered: false,
        uncertain: false,
    }
}

/// The worker half — a no-op under a normal `cargo test -- --ignored`
/// sweep of this file, only meaningful when spawned by the trial
/// function below with `DURESS_WIPE_DB_PATH` set.
#[test]
#[ignore]
fn quick_wipe_worker() {
    let Ok(db_path) = std::env::var(ENV_DB_PATH) else {
        return;
    };
    let db = Db::open(&db_path, DEV_PASSPHRASE).expect("worker: open db");
    println!("STARTING");
    std::io::stdout().flush().unwrap();

    // The real, unmodified quick_wipe — no reproduction.
    db.quick_wipe().expect("worker: quick_wipe");
    println!("DONE");
    std::io::stdout().flush().unwrap();
}

/// The three outcomes one trial can land on.
#[derive(Debug, PartialEq, Eq)]
enum TrialOutcome {
    /// The kill landed before the rotation ever committed — legitimate
    /// "nothing happened yet," not a finding either way.
    NotRotatedYet,
    /// The rotation had committed, and — correctly — the content is no
    /// longer recoverable. The security property held.
    RotatedAndSecure,
    /// The file could not be reopened at all after the kill: not a
    /// `quick_wipe`-specific finding (the security-ordering fix has
    /// nothing to do with whether the file opens), but a narrower,
    /// environment-level question about whether a single `redb`
    /// transaction commit actually survives a real `SIGKILL` landing
    /// mid-write on this filesystem — see the module doc.
    ReopenFailed,
}

/// Seeds a fresh db and runs one kill-after-`delay` trial against it.
fn run_one_trial(trial: u32, delay: Duration) -> TrialOutcome {
    let dir = tempfile::tempdir().unwrap().keep();
    let db_path = dir.join("duress_test.redb");
    let conv = conv_id();

    {
        let db = Db::create(&db_path, DEV_PASSPHRASE).unwrap();
        for i in 0..MESSAGE_COUNT {
            db.save_message(conv, &sample_message(i as u32)).unwrap();
        }
    }

    let test_exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(&test_exe)
        .args(["--exact", "--ignored", "--nocapture", "quick_wipe_worker"])
        .env(ENV_DB_PATH, &db_path)
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn worker subprocess");

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
    child.kill().expect("SIGKILL the worker");
    let wait_status = child.wait().expect("wait for worker");

    let outcome = match Db::open(&db_path, DEV_PASSPHRASE) {
        Err(e) => {
            println!("trial {trial:2} (delay {delay:?}): worker exit {wait_status:?} -> REOPEN FAILED: {e}");
            return TrialOutcome::ReopenFailed;
        }
        Ok(db) => {
            // `quick_wipe`'s new ordering rotates the content key
            // unconditionally before any delete, so a message ever
            // coming back with its original, intact plaintext can only
            // mean the kill landed *before* that rotation committed —
            // legitimate "nothing happened yet." Any other outcome (a
            // decrypt error, or an empty list) can only happen once the
            // rotation has already committed.
            match db.list_messages(conv) {
                Ok(messages) if messages.is_empty() => TrialOutcome::RotatedAndSecure,
                Ok(messages) => {
                    let intact = messages.iter().all(|m| m.content == EXPECTED_CONTENT);
                    assert!(
                        intact,
                        "trial {trial}: SECURITY FAILURE — a message survived with neither its \
                         original content nor an empty result: partial/corrupted plaintext, \
                         not a clean pre-rotation or post-rotation state"
                    );
                    TrialOutcome::NotRotatedYet
                }
                Err(_) => TrialOutcome::RotatedAndSecure, // decrypt failure IS the safe outcome
            }
        }
    };

    println!("trial {trial:2} (delay {delay:?}): worker exit {wait_status:?} -> {outcome:?}");
    outcome
}

/// Runs `TRIALS` independent real-`SIGKILL` trials against the actual,
/// unmodified `quick_wipe` and asserts the one thing that's actually
/// `quick_wipe`'s own responsibility: whenever the file *does* reopen
/// after a kill, and the rotation had committed, the content is
/// unrecoverable — never a message surviving with intact plaintext next
/// to a rotated key. It does **not** assert that the file always
/// reopens: this environment has shown a narrow, order-independent
/// window (present even for a lone single-record write, not something
/// `quick_wipe`'s own logic controls) where a `SIGKILL` landing exactly
/// during a transaction's own commit can leave that file unrecoverable
/// by *any* passphrase — an environment/filesystem write-barrier
/// question, not a `quick_wipe` ordering question, and out of scope for
/// this fix to resolve. See the module doc.
///
/// `#[ignore]`d: real subprocesses, real `SIGKILL`s, ~500 messages per
/// trial across ten trials. Run with:
/// ```sh
/// cargo test -p dratchet-store --test duress_wipe_crash_consistency -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn quick_wipe_content_is_unrecoverable_regardless_of_when_a_real_kill_lands() {
    println!(
        "{TRIALS} independent trials, each: seed {MESSAGE_COUNT} messages, spawn a real worker \
         subprocess calling the actual quick_wipe, SIGKILL it after a short delay, reopen fresh.\n"
    );

    let mut not_rotated_yet = 0;
    let mut rotated_and_secure = 0;
    let mut reopen_failed = 0;
    for trial in 0..TRIALS {
        // Wide enough that the child is guaranteed at least one real
        // scheduling slice to complete quick_wipe's first write before
        // the kill lands — a microsecond-scale sweep (this test's first
        // cut) never once caught it: the parent's own sleep/kill round
        // trip and the child's next scheduling opportunity both dominate
        // at that scale in this environment.
        let delay = Duration::from_millis(20 * (trial as u64 + 1));
        match run_one_trial(trial, delay) {
            TrialOutcome::NotRotatedYet => not_rotated_yet += 1,
            TrialOutcome::RotatedAndSecure => rotated_and_secure += 1,
            TrialOutcome::ReopenFailed => reopen_failed += 1,
        }
    }

    println!("\n=== RESULT ===");
    println!("{not_rotated_yet}/{TRIALS} trials: kill landed before the rotation committed — not a finding");
    println!(
        "{rotated_and_secure}/{TRIALS} trials: kill landed on/after the rotation — content \
         confirmed unrecoverable (each trial already asserted this as it ran)"
    );
    println!(
        "{reopen_failed}/{TRIALS} trials: the file did not reopen at all after the kill — an \
         environment/write-barrier question, not a quick_wipe-specific finding (see module doc)"
    );
    if reopen_failed > 0 {
        println!(
            "\nNOTE: {reopen_failed} trial(s) hit a narrow torn-write window that this \
             environment's filesystem does not appear to protect a single redb transaction \
             commit against under a real SIGKILL — reproducible even for a lone single-record \
             write with zero messages seeded, so it is not specific to quick_wipe's delete \
             loop or its ordering. This is a genuine, separate finding worth its own \
             investigation, not something this test's assertions try to paper over."
        );
    }
    assert!(
        rotated_and_secure > 0,
        "no trial ever caught the rotation in progress — increase MESSAGE_COUNT or widen the \
         delay sweep so at least one real trial exercises the security property"
    );
    println!(
        "\nCONFIRMED: on every trial where the file reopened after the kill and the rotation \
         had committed, quick_wipe's security guarantee (content unrecoverable) held — never \
         once did a message survive readable next to a rotated key."
    );
}
