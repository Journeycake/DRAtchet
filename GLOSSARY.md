# DRAtchet

End-to-end encrypted one-to-one chat: an X3DH handshake and Double Ratchet between two people's devices, with a relay that holds encrypted mail it cannot read until the recipient collects it.

## Language

### Mail delivery

**Bootstrap Inbox**:
The relay mailbox derived from a person's identity, where anyone who hasn't yet switched to a Conversation Mailbox with them writes. One per identity, shared by all such contacts.
_Avoid_: bootstrap mailbox, pre-transition inbox, old inbox, identity inbox

**Conversation Mailbox**:
The relay mailbox for one pairing, derived from both sides' routing ids and used by both directions once each side has switched to it.
_Avoid_: routing-id mailbox, routing-id-derived address, shared symmetric address

**Server Epoch**:
A numbered span of the relay's life over which its queued mail is known to be intact. It advances whenever queued mail may have been lost, such as a restart before all queued mail was saved, and a client that sees it advance offers Retry for its undelivered messages.
_Avoid_: boot id, server restart (as the name for the event)

**Sealed Message**:
One piece of queued mail as the relay stores it on disk (the encrypted envelope with its mailbox, writer and expiry), encrypted under the operator's key.
_Avoid_: stored entry, persisted message

**Fragment**:
One of the pieces a Sealed Message is split into, each kept in its own file in a different storage location; every Fragment is needed to rebuild it.
_Avoid_: shard, chunk

### Sent messages

**Accepted**:
A sent message the relay has confirmed it is holding (once persistence is on, only after the message is on disk), shown to the sender as a single checkmark.
_Avoid_: sent (as a state), single checkmark, acked

**Delivered**:
A sent message whose arrival the recipient's device has confirmed.
_Avoid_: received, read

**Retry**:
Sending one of your own messages again under a fresh key, carrying the same Message ID, so the recipient shows it only once.
_Avoid_: resend as new, duplicate

**Retry Reason**:
Why a sent, undelivered message is offered for Retry: it never reached the relay, it expired at the relay, or the relay lost it.
_Avoid_: uncertain, unconfirmed (as a state)

**Message ID**:
The sender-chosen identifier carried inside a message's encrypted content, identical across every Retry of that message.
_Avoid_: entry id, chain position
