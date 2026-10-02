# Messages on the device are deleted on request, never on a timer

Local history is removed only when the user asks: a purge (messages) or an emergency purge (messages and the conversation's session), both per conversation, plus the duress wipes (ARCHITECTURE.md §11.5, §11.9). A disappearing-message timer in the style of Signal or WhatsApp was drafted and rejected, and its code removed rather than left dormant. A reader expecting time-based expiry in a privacy-focused messenger should know its absence is deliberate.
