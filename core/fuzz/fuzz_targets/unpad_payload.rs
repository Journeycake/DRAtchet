//! Fuzz target for `payload::untag_and_unpad` — runs on whatever comes out of AEAD
//! decryption, which (unlike the envelope header) an attacker can't forge without
//! already having broken the AEAD tag. Still parses a length-prefixed, attacker-
//! influenced-in-the-corrupted-tag-bypassed-case structure, so it must never panic.
#![no_main]

use dratchet_core::payload::{tag_and_pad, untag_and_unpad};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok((payload_type, content)) = untag_and_unpad(data) else {
        return;
    };

    // Re-tagging/re-padding the extracted content can legitimately fail (content
    // above MAX_PADDED_LEN, reachable when the fuzzer hands us oversized input) —
    // that's an expected `Err`, not a bug. What must never happen is a panic, and if
    // it *does* succeed, the round trip must reproduce the same content.
    let Ok(re_padded) = tag_and_pad(payload_type, &content) else {
        return;
    };
    let (re_type, re_content) = untag_and_unpad(&re_padded).expect("re-padded output must re-parse");
    assert_eq!(re_type, payload_type);
    assert_eq!(re_content, content);
});
