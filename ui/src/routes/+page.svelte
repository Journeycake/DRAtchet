<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import { onMount } from "svelte";

  type ContactDto = {
    fingerprint: string;
    handle: string;
    initials: string;
    verified: boolean;
    pending: boolean;
  };

  type MessageDto = {
    id: string;
    sender_is_local: boolean;
    content: string;
    timestamp: number;
  };

  const INBOX_UPDATED_EVENT = "dratchet://inbox-updated";
  const FULL_WIPE_CONFIRM_PHRASE = "DELETE";

  let contacts = $state<ContactDto[]>([]);
  let selected = $state<ContactDto | null>(null);
  let messages = $state<MessageDto[]>([]);
  let loadError = $state("");
  let draft = $state("");
  let sendError = $state("");
  let sending = $state(false);

  let settingsOpen = $state(false);
  let quickWipeArmed = $state(false);
  let quickWipeBusy = $state(false);
  let quickWipeResult = $state("");
  let quickWipeError = $state("");
  let fullWipeConfirmText = $state("");
  let fullWipeBusy = $state(false);
  let fullWipeError = $state("");

  async function selectContact(contact: ContactDto) {
    selected = contact;
    messages = [];
    sendError = "";
    if (!contact.verified) return;
    try {
      messages = await invoke<MessageDto[]>("list_messages", {
        fingerprint: contact.fingerprint,
      });
    } catch (e) {
      loadError = String(e);
    }
  }

  async function refetch() {
    const previouslySelected = selected?.fingerprint;
    try {
      contacts = await invoke<ContactDto[]>("list_contacts");
    } catch (e) {
      loadError = String(e);
      return;
    }
    const stillThere = contacts.find((c) => c.fingerprint === previouslySelected);
    if (stillThere) {
      await selectContact(stillThere);
    } else if (contacts.length > 0) {
      await selectContact(contacts[0]);
    }
  }

  async function sendMessage(event: Event) {
    event.preventDefault();
    if (!selected || !draft.trim() || sending) return;
    sending = true;
    sendError = "";
    try {
      const sent = await invoke<MessageDto>("send_message", {
        fingerprint: selected.fingerprint,
        content: draft,
      });
      messages = [...messages, sent];
      draft = "";
    } catch (e) {
      sendError = String(e);
    } finally {
      sending = false;
    }
  }

  function openSettings() {
    settingsOpen = true;
    quickWipeArmed = false;
    quickWipeResult = "";
    quickWipeError = "";
    fullWipeConfirmText = "";
    fullWipeError = "";
  }

  function closeSettings() {
    settingsOpen = false;
  }

  // docs/ARCHITECTURE.md §11.9's quick wipe: crypto-shreds message
  // history and cached ratchet/session state (not just this instance's
  // view of it — the actual on-disk data), leaving the account and
  // contact list untouched. A two-click confirm ("Wipe..." then "Confirm
  // wipe") rather than a native confirm() dialog, so it reads consistently
  // with the rest of this dark-themed UI.
  async function quickWipe() {
    if (!quickWipeArmed) {
      quickWipeArmed = true;
      return;
    }
    quickWipeBusy = true;
    quickWipeError = "";
    quickWipeResult = "";
    try {
      const removed = await invoke<number>("quick_wipe");
      quickWipeResult = `Erased ${removed} record${removed === 1 ? "" : "s"}.`;
      quickWipeArmed = false;
      await refetch();
    } catch (e) {
      quickWipeError = String(e);
    } finally {
      quickWipeBusy = false;
    }
  }

  // §11.9's full wipe: additionally destroys the identity itself and
  // restarts the whole app. Gated behind typing a literal confirmation
  // phrase — deliberately a stronger, separate confirmation from quick
  // wipe's two-click pattern, matching the doc's "explicit, separate
  // confirmation" requirement for the irreversible tier.
  async function fullWipe() {
    if (fullWipeConfirmText !== FULL_WIPE_CONFIRM_PHRASE) return;
    fullWipeBusy = true;
    fullWipeError = "";
    try {
      // The app process restarts as part of this call succeeding — this
      // invoke may never resolve from the frontend's point of view, which
      // is fine: fullWipeBusy staying true until the restart lands is the
      // correct UI state to show.
      await invoke("full_wipe");
    } catch (e) {
      fullWipeError = String(e);
      fullWipeBusy = false;
    }
  }

  onMount(() => {
    refetch();
    const unlisten = listen(INBOX_UPDATED_EVENT, refetch);
    return () => {
      unlisten.then((f) => f());
    };
  });
</script>

<div class="shell">
  <aside class="sidebar">
    <div class="brand-row">
      <div class="brand">DRAtchet</div>
      <button class="settings-button" onclick={openSettings} aria-label="Settings">⚙</button>
    </div>
    <div class="search">Search conversations</div>
    <ul class="conversations">
      {#each contacts as contact (contact.fingerprint)}
        <li>
          <button
            class="conversation"
            class:active={selected?.fingerprint === contact.fingerprint}
            onclick={() => selectContact(contact)}
          >
            <span class="avatar">{contact.initials}</span>
            <span class="conversation-text">
              <span class="handle">{contact.handle}</span>
              <span class="preview">
                {contact.pending ? "Pending verification" : "Verified"}
              </span>
            </span>
          </button>
        </li>
      {/each}
    </ul>
  </aside>

  <main class="pane">
    {#if loadError}
      <div class="error">{loadError}</div>
    {:else if !selected}
      <div class="empty">No conversations yet.</div>
    {:else if selected.pending}
      <div class="gate">
        <div class="gate-title">Verification required</div>
        <p class="gate-body">
          You can't exchange messages with <strong>{selected.handle}</strong> until
          you verify their identity — scan their QR code in person, or use a
          remote pairing code.
        </p>
        <button class="gate-action" disabled>Verify {selected.handle}</button>
      </div>
    {:else}
      <div class="conversation-header">{selected.handle}</div>
      <div class="messages">
        {#each messages as message (message.id)}
          <div class="bubble" class:local={message.sender_is_local}>
            {message.content}
          </div>
        {/each}
      </div>
      <form class="composer" onsubmit={sendMessage}>
        {#if sendError}
          <div class="send-error">{sendError}</div>
        {/if}
        <input
          class="composer-input"
          placeholder="Message {selected.handle}"
          bind:value={draft}
          disabled={sending}
        />
      </form>
    {/if}
  </main>
</div>

{#if settingsOpen}
  <div
    class="modal-backdrop"
    role="presentation"
    onclick={(e) => {
      if (e.target === e.currentTarget) closeSettings();
    }}
    onkeydown={(e) => {
      if (e.key === "Escape") closeSettings();
    }}
  >
    <div class="modal" role="dialog" aria-modal="true" aria-label="Settings">
      <div class="modal-header">
        <span>Settings</span>
        <button class="modal-close" onclick={closeSettings} aria-label="Close">✕</button>
      </div>

      <div class="danger-zone">
        <div class="danger-title">Danger Zone</div>
        <p class="danger-note">
          Both actions below only affect <strong>this device</strong> — they
          never reach the other person's copy of any conversation. There is
          no way to delete something from someone else's device.
        </p>

        <div class="danger-row">
          <div class="danger-row-text">
            <div class="danger-row-title">Quick wipe</div>
            <p class="danger-row-body">
              Erases all message history and every conversation's session
              state on this device. Your identity and contact list are kept
              — the app keeps working — but each conversation will need to
              be re-paired before you can send to it again.
            </p>
          </div>
          <button
            class="danger-button"
            class:armed={quickWipeArmed}
            disabled={quickWipeBusy}
            onclick={quickWipe}
          >
            {#if quickWipeBusy}
              Wiping…
            {:else if quickWipeArmed}
              Confirm wipe
            {:else}
              Quick wipe
            {/if}
          </button>
        </div>
        {#if quickWipeResult}
          <div class="danger-result">{quickWipeResult}</div>
        {/if}
        {#if quickWipeError}
          <div class="danger-error">{quickWipeError}</div>
        {/if}

        <div class="danger-row">
          <div class="danger-row-text">
            <div class="danger-row-title">Full wipe</div>
            <p class="danger-row-body">
              Additionally destroys your identity itself and restarts the
              app. Irreversible — every contact will see your identity as
              changed the next time you reach them. Type
              <strong>{FULL_WIPE_CONFIRM_PHRASE}</strong> to confirm.
            </p>
            <input
              class="danger-confirm-input"
              placeholder={FULL_WIPE_CONFIRM_PHRASE}
              bind:value={fullWipeConfirmText}
              disabled={fullWipeBusy}
            />
          </div>
          <button
            class="danger-button full"
            disabled={fullWipeBusy || fullWipeConfirmText !== FULL_WIPE_CONFIRM_PHRASE}
            onclick={fullWipe}
          >
            {fullWipeBusy ? "Wiping…" : "Full wipe"}
          </button>
        </div>
        {#if fullWipeError}
          <div class="danger-error">{fullWipeError}</div>
        {/if}
      </div>
    </div>
  </div>
{/if}

<style>
  :root {
    --bg: #14161b;
    --bg-raised: #1b1e25;
    --bg-sunken: #101216;
    --ink: #e7e9ed;
    --ink-soft: #9aa1ad;
    --ink-faint: #6b7280;
    --line: #2a2e37;
    --line-soft: #21252c;
    --brass: #d7a85b;
    --brass-strong: #e9bd78;
    --brass-dim: rgba(215, 168, 91, 0.14);
    --teal: #5fb8a6;
    --teal-dim: rgba(95, 184, 166, 0.16);
    --amber: #c98a3e;
    --amber-dim: rgba(201, 138, 62, 0.16);
    --red: #d9695c;
    --display: "JetBrains Mono", ui-monospace, "SFMono-Regular", Menlo, monospace;
    --sans: "Public Sans", -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
  }

  :global(body) {
    margin: 0;
    background: var(--bg);
    color: var(--ink);
    font-family: var(--sans);
  }

  .shell {
    display: grid;
    grid-template-columns: 280px 1fr;
    height: 100vh;
  }

  .sidebar {
    background: var(--bg-sunken);
    border-right: 1px solid var(--line);
    display: flex;
    flex-direction: column;
  }

  .brand-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--line);
    padding-right: 8px;
  }

  .brand {
    font-family: var(--display);
    font-weight: 600;
    color: var(--brass-strong);
    padding: 18px 16px;
  }

  .settings-button {
    background: transparent;
    border: none;
    color: var(--ink-faint);
    font-size: 16px;
    line-height: 1;
    padding: 8px;
    border-radius: 6px;
    cursor: pointer;
  }

  .settings-button:hover {
    background: var(--bg-raised);
    color: var(--ink);
  }

  .search {
    margin: 12px 16px;
    padding: 8px 10px;
    background: var(--bg-raised);
    border: 1px solid var(--line-soft);
    border-radius: 6px;
    color: var(--ink-faint);
    font-size: 13px;
  }

  .conversations {
    list-style: none;
    margin: 0;
    padding: 0;
    overflow-y: auto;
  }

  .conversation {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 10px 16px;
    background: transparent;
    border: none;
    border-left: 2px solid transparent;
    color: inherit;
    text-align: left;
    cursor: pointer;
    font: inherit;
  }

  .conversation:hover {
    background: var(--bg-raised);
  }

  .conversation.active {
    background: var(--brass-dim);
    border-left-color: var(--brass);
  }

  .avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background: var(--teal-dim);
    color: var(--teal);
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--display);
    font-size: 12px;
    flex-shrink: 0;
  }

  .conversation-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .handle {
    font-family: var(--display);
    font-size: 13px;
    color: var(--ink);
  }

  .preview {
    font-size: 12px;
    color: var(--ink-faint);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .pane {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .empty,
  .error {
    margin: auto;
    color: var(--ink-faint);
  }

  .error {
    color: var(--red);
  }

  .conversation-header {
    padding: 16px 20px;
    border-bottom: 1px solid var(--line);
    font-family: var(--display);
  }

  .messages {
    flex: 1;
    overflow-y: auto;
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .bubble {
    max-width: 60%;
    padding: 8px 12px;
    border-radius: 10px;
    background: var(--bg-raised);
    align-self: flex-start;
  }

  .bubble.local {
    background: var(--teal-dim);
    color: var(--ink);
    align-self: flex-end;
  }

  .composer {
    padding: 16px 20px;
    border-top: 1px solid var(--line);
  }

  .send-error {
    color: var(--red);
    font-size: 12px;
    margin-bottom: 6px;
  }

  .composer-input {
    width: 100%;
    box-sizing: border-box;
    padding: 10px 12px;
    background: var(--bg-raised);
    border: 1px solid var(--line-soft);
    border-radius: 6px;
    color: var(--ink);
    font: inherit;
  }

  .gate {
    margin: auto;
    max-width: 380px;
    text-align: center;
    padding: 24px;
    background: var(--amber-dim);
    border: 1px solid var(--amber);
    border-radius: 10px;
  }

  .gate-title {
    font-family: var(--display);
    color: var(--amber);
    font-weight: 600;
    margin-bottom: 10px;
  }

  .gate-body {
    color: var(--ink-soft);
    font-size: 14px;
    line-height: 1.5;
  }

  .gate-action {
    margin-top: 14px;
    padding: 8px 16px;
    background: var(--brass);
    color: var(--bg-sunken);
    border: none;
    border-radius: 6px;
    font-weight: 600;
    cursor: not-allowed;
    opacity: 0.7;
  }

  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10;
  }

  .modal {
    width: 480px;
    max-width: calc(100vw - 40px);
    max-height: calc(100vh - 40px);
    overflow-y: auto;
    background: var(--bg-raised);
    border: 1px solid var(--line);
    border-radius: 10px;
  }

  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    border-bottom: 1px solid var(--line);
    font-family: var(--display);
    font-weight: 600;
  }

  .modal-close {
    background: transparent;
    border: none;
    color: var(--ink-faint);
    font-size: 14px;
    cursor: pointer;
    padding: 4px 8px;
  }

  .modal-close:hover {
    color: var(--ink);
  }

  .danger-zone {
    padding: 20px;
  }

  .danger-title {
    font-family: var(--display);
    color: var(--red);
    font-weight: 600;
    margin-bottom: 8px;
  }

  .danger-note {
    color: var(--ink-soft);
    font-size: 13px;
    line-height: 1.5;
    margin: 0 0 20px;
  }

  .danger-row {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    padding: 14px 0;
    border-top: 1px solid var(--line-soft);
  }

  .danger-row-text {
    flex: 1;
    min-width: 0;
  }

  .danger-row-title {
    font-family: var(--display);
    font-size: 14px;
    color: var(--ink);
    margin-bottom: 4px;
  }

  .danger-row-body {
    color: var(--ink-faint);
    font-size: 12px;
    line-height: 1.5;
    margin: 0;
  }

  .danger-confirm-input {
    margin-top: 8px;
    width: 100%;
    box-sizing: border-box;
    padding: 6px 10px;
    background: var(--bg-sunken);
    border: 1px solid var(--line-soft);
    border-radius: 6px;
    color: var(--ink);
    font: inherit;
    font-size: 12px;
  }

  .danger-button {
    flex-shrink: 0;
    padding: 8px 14px;
    background: var(--bg-sunken);
    border: 1px solid var(--red);
    color: var(--red);
    border-radius: 6px;
    font-weight: 600;
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
  }

  .danger-button:hover:not(:disabled) {
    background: var(--red);
    color: var(--bg-sunken);
  }

  .danger-button.armed {
    background: var(--red);
    color: var(--bg-sunken);
  }

  .danger-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .danger-result {
    color: var(--teal);
    font-size: 12px;
    margin-top: 4px;
  }

  .danger-error {
    color: var(--red);
    font-size: 12px;
    margin-top: 4px;
  }
</style>
