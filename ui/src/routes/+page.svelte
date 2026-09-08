<script lang="ts">
  import { invoke } from "@tauri-apps/api/core";
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

  let contacts = $state<ContactDto[]>([]);
  let selected = $state<ContactDto | null>(null);
  let messages = $state<MessageDto[]>([]);
  let loadError = $state("");

  async function selectContact(contact: ContactDto) {
    selected = contact;
    messages = [];
    if (!contact.verified) return;
    try {
      messages = await invoke<MessageDto[]>("list_messages", {
        fingerprint: contact.fingerprint,
      });
    } catch (e) {
      loadError = String(e);
    }
  }

  onMount(async () => {
    try {
      contacts = await invoke<ContactDto[]>("list_contacts");
      if (contacts.length > 0) {
        await selectContact(contacts[0]);
      }
    } catch (e) {
      loadError = String(e);
    }
  });
</script>

<div class="shell">
  <aside class="sidebar">
    <div class="brand">DRAtchet</div>
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
      <div class="composer">
        <input class="composer-input" placeholder="Message {selected.handle}" disabled />
      </div>
    {/if}
  </main>
</div>

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

  .brand {
    font-family: var(--display);
    font-weight: 600;
    color: var(--brass-strong);
    padding: 18px 16px;
    border-bottom: 1px solid var(--line);
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
</style>
