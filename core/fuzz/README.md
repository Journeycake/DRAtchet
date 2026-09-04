# DRAtchet fuzz targets

Two [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) targets, one for
each function in `dratchet-core` that parses bytes an attacker controls
directly — before any AEAD authentication has happened:

- **`decode_envelope`** — `Envelope::decode`, run on every byte that arrives
  off the wire (Tier 0 DataChannel, Tier 1 mailbox fetch). Also checks that
  anything that successfully decodes round-trips through `encode()` back to
  the exact same bytes.
- **`unpad_payload`** — `payload::untag_and_unpad`, run on whatever AEAD
  decryption produces. Also checks the tag/pad → untag/unpad round trip.

Neither target asserts anything about *security* properties (that's what
`core/src/ratchet.rs`'s own test suite, especially
`garbage_envelope_does_not_desync_the_ratchet`, is for) — only that these
two parsers never panic on adversarial input and are internally consistent
when they do accept it.

## Running

Requires nightly Rust and `cargo-fuzz` (`cargo install cargo-fuzz`):

```
cd core
cargo +nightly fuzz run decode_envelope -- -max_total_time=60
cargo +nightly fuzz run unpad_payload -- -max_total_time=60
```

CI (`.github/workflows/ci.yml`, job `fuzz-smoke`) runs both for 60 seconds
on every push/PR — enough to catch a regression, not a substitute for a
longer run. Worth running each for several minutes (`-max_total_time=600`
or more) locally before or after changing either parser.

A crash writes a reproducing input to `artifacts/<target>/`; rerun with
`cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>` to
debug it, and `cargo +nightly fuzz fmt <target> <crash-file>` to see the
input in a more readable form.
