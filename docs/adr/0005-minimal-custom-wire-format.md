# A minimal custom wire format instead of OpenPGP packets

Key material is CBOR and the ratchet envelope is a fixed binary layout (MESSAGE_SCHEMA.md), not OpenPGP packets, which an early version used for keys and considered for messages (ARCHITECTURE.md §3.5). OpenPGP framing offered only cosmetic interoperability (no stock client can decrypt a ratchet-derived key) at the cost of size, a larger parser to attack, and nowhere natural to put ratchet headers. Revisit only if a concrete interoperability requirement appears.
