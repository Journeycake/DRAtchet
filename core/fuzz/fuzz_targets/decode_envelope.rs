//! Fuzz target for `Envelope::decode` — the entry point for every byte that arrives
//! off the wire (Tier 0 DataChannel, Tier 1 mailbox fetch) before any authentication
//! has happened. It must never panic on adversarial input; a malformed or truncated
//! envelope should always come back as `Err`, never a crash.
#![no_main]

use dratchet_core::envelope::Envelope;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(envelope) = Envelope::decode(data) else {
        return;
    };

    // Anything that successfully decoded must re-encode to the exact same bytes that
    // were consumed, and decoding that back must reproduce the same envelope —
    // decode/encode round-trip idempotency, not just "didn't crash."
    let re_encoded = envelope.encode();
    assert_eq!(
        re_encoded, data,
        "decode() accepted input that doesn't round-trip through encode()"
    );
    let re_decoded = Envelope::decode(&re_encoded).expect("re-encoding a decoded envelope must decode again");
    assert_eq!(re_decoded.version, envelope.version);
    assert_eq!(re_decoded.conversation_id, envelope.conversation_id);
    assert_eq!(re_decoded.dh_pub, envelope.dh_pub);
    assert_eq!(re_decoded.pn, envelope.pn);
    assert_eq!(re_decoded.n, envelope.n);
    assert_eq!(re_decoded.ciphertext, envelope.ciphertext);
});
