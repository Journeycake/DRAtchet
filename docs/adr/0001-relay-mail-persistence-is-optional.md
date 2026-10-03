# Relay mail persistence is optional, encrypted and fragmented

The relay holds queued mail in memory only by default, so a seized server disk yields no stored mail, and a restart that loses mail is signalled to senders by a new Server Epoch so they can Retry (DRA-0064). Operators can turn persistence on in `dratchet.cfg`; it is on by default only on hosts with under 2 GB of usable RAM, where an unpersisted memory area is the bigger risk. When on, each queued message is stored as a Sealed Message encrypted under an operator-supplied key (never kept in the config file) and split into Fragments across at least two storage locations, with an encrypted index holding each Sealed Message's checksum; the relay refuses to start persistence without a key and two locations.

## Consequences

- The single checkmark (Accepted) waits until the message is on disk, so saves run every 0–15 s (default 10 s) and early when the memory area reaches half its limit (default one tenth of usable RAM); clients wait that interval plus their normal timeout for the checkmark.
- A clean shutdown that completes its last save keeps the Server Epoch; a start without that, a rebuild that drops a Sealed Message, or a lost or replaced store advances it.
- When the relay refuses mail it doesn't say why, so its memory state can't be probed.
- Changing the key on a live server, limits on mail for long-absent recipients, and Fragment storage off the relay host are deferred to v1.5 planning.
