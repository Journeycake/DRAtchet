//! The test that actually justifies this whole project.
//!
//! `docs/ARCHITECTURE.md` §1 argues that a literal "rotate to a fresh PGP keypair
//! every message" scheme can't survive queue depth: if Alice sends several messages
//! before Bob replies, or messages arrive out of order, a strict alternating-keypair
//! scheme has nothing to encrypt the second message against. §3.3 claims the Double
//! Ratchet's skipped-message-key cache is what actually solves this. This file is
//! where that claim gets checked against real, adversarially-ordered delivery —
//! not just asserted in a design document.

use std::collections::HashMap;

use dratchet_core::envelope::Envelope;
use dratchet_core::payload::{untag_and_unpad, PAYLOAD_CHAT};
use dratchet_core::ratchet::{RatchetState, DEFAULT_MAX_SKIP};
use proptest::prelude::*;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

fn chat(text: &str) -> Vec<u8> {
    dratchet_core::payload::tag_and_pad(PAYLOAD_CHAT, text.as_bytes()).unwrap()
}

fn read_chat(bytes: &[u8]) -> String {
    let (ty, content) = untag_and_unpad(bytes).unwrap();
    assert_eq!(ty, PAYLOAD_CHAT);
    String::from_utf8(content).unwrap()
}

fn matched_pair(max_skip: u32) -> (RatchetState, RatchetState) {
    let conversation_id = [3u8; 16];
    let root_key = [99u8; 32];
    let responder_secret = StaticSecret::random_from_rng(OsRng);
    let responder_public = PublicKey::from(&responder_secret);
    (
        RatchetState::init_as_initiator(conversation_id, root_key, responder_public, max_skip),
        RatchetState::init_as_responder(conversation_id, root_key, responder_secret, max_skip),
    )
}

/// The scenario from the very first design conversation, made concrete: a burst of
/// messages sent before any reply — "queue depth 2" and well beyond — with delivery
/// arriving in an arbitrary order, not the order they were sent in. Every message
/// must still decrypt to exactly what was sent, and to nothing else.
#[test]
fn burst_of_messages_before_any_reply_survives_arbitrary_delivery_order() {
    let (mut alice, mut bob) = matched_pair(DEFAULT_MAX_SKIP);

    let plaintexts: Vec<String> = (0..50).map(|i| format!("queued message {i}")).collect();
    let envelopes: Vec<Envelope> = plaintexts
        .iter()
        .map(|text| alice.encrypt(&chat(text)).unwrap())
        .collect();

    // A deliberately adversarial delivery order: reversed, then interleaved from both
    // ends — nothing about it resembles the order the messages were sent in.
    let mut delivery_order: Vec<usize> = (0..envelopes.len()).collect();
    delivery_order.reverse();
    let (front, back) = delivery_order.split_at(delivery_order.len() / 2);
    let interleaved: Vec<usize> = front
        .iter()
        .zip(back.iter())
        .flat_map(|(a, b)| [*a, *b])
        .collect();

    for &i in &interleaved {
        let plaintext = bob.decrypt_raw(&envelopes[i]).unwrap();
        assert_eq!(read_chat(&plaintext), plaintexts[i]);
    }
}

/// A message queued and delivered *after* the conversation has moved through several
/// DH ratchet steps (i.e. several replies happened in between) must still decrypt —
/// this is the out-of-order-across-a-ratchet-boundary case, at a larger scale than
/// the unit test in `ratchet.rs` covers.
#[test]
fn late_arrival_across_several_ratchet_steps_still_decrypts() {
    let (mut alice, mut bob) = matched_pair(DEFAULT_MAX_SKIP);

    let a0 = alice.encrypt(&chat("a0")).unwrap();
    let stray = alice.encrypt(&chat("stray, delivered very late")).unwrap();

    assert_eq!(read_chat(&bob.decrypt_raw(&a0).unwrap()), "a0");

    // Several turns happen without `stray` ever being delivered.
    for round in 0..5 {
        let from_bob = bob.encrypt(&chat(&format!("bob round {round}"))).unwrap();
        assert_eq!(
            read_chat(&alice.decrypt_raw(&from_bob).unwrap()),
            format!("bob round {round}")
        );
        let from_alice = alice
            .encrypt(&chat(&format!("alice round {round}")))
            .unwrap();
        assert_eq!(
            read_chat(&bob.decrypt_raw(&from_alice).unwrap()),
            format!("alice round {round}")
        );
    }

    // `stray` finally arrives, several DH ratchet steps after it was sent.
    let plaintext = bob.decrypt_raw(&stray).unwrap();
    assert_eq!(read_chat(&plaintext), "stray, delivered very late");
}

/// The bound that keeps the skipped-key cache from being an unbounded-memory attack
/// surface: a queue deeper than `MAX_SKIP` is refused, not silently accepted into an
/// ever-growing cache.
#[test]
fn queue_depth_beyond_max_skip_is_refused_deterministically() {
    let max_skip = 20;
    let (mut alice, mut bob) = matched_pair(max_skip);

    let mut last = None;
    for i in 0..(max_skip + 10) {
        last = Some(alice.encrypt(&chat(&format!("m{i}"))).unwrap());
    }
    assert!(bob.decrypt_raw(&last.unwrap()).is_err());
}

proptest! {
    /// Property version of the burst test above: for *any* random subset and *any*
    /// random delivery order of messages sent in a single burst (within MAX_SKIP),
    /// every delivered message decrypts to exactly what was sent at that index, and
    /// nothing decrypts to the wrong plaintext. This is the queue-depth claim from
    /// `docs/ARCHITECTURE.md` §1/§3.3, generalized across many random orderings
    /// instead of the one or two hand-picked ones in the unit/integration tests.
    #[test]
    fn arbitrary_burst_and_delivery_order_always_decrypts_correctly(
        burst_size in 1usize..60,
        seed in any::<u64>(),
    ) {
        let (mut alice, mut bob) = matched_pair(DEFAULT_MAX_SKIP);

        let plaintexts: Vec<String> = (0..burst_size).map(|i| format!("m{i}-{seed}")).collect();
        let envelopes: Vec<Envelope> = plaintexts
            .iter()
            .map(|text| alice.encrypt(&chat(text)).unwrap())
            .collect();

        // Deterministic pseudo-shuffle from `seed`, so failures are reproducible
        // without needing proptest's own shrinker to explain the ordering.
        let mut order: Vec<usize> = (0..burst_size).collect();
        let mut state = seed;
        for i in (1..order.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (state >> 33) as usize % (i + 1);
            order.swap(i, j);
        }

        let mut decrypted: HashMap<usize, String> = HashMap::new();
        for &i in &order {
            let plaintext = bob.decrypt_raw(&envelopes[i])
                .expect("every message within MAX_SKIP must decrypt regardless of delivery order");
            decrypted.insert(i, read_chat(&plaintext));
        }

        for (i, expected) in plaintexts.iter().enumerate() {
            prop_assert_eq!(decrypted.get(&i), Some(expected));
        }
    }
}
