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
    wipe_ask_before_delete: boolean;
    wipe_include_session: boolean;
    wipe_request_pending: boolean;
  };

  type MessageDto = {
    id: string;
    sender_is_local: boolean;
    content: string;
    timestamp: number;
    delivered: boolean;
  };

  type OwnProfileDto = {
    handle: string;
    username: string;
    discriminator: number;
  };

  type PairingCodeDto = {
    code: string;
    expires_at: number;
  };

  // §6.1: surfaced once at startup when `reconcile_own_profile` had to
  // fall back to a new discriminator because the directory forgot this
  // device owned its old one (a server restart) and someone else claimed
  // it first.
  type OwnDiscriminatorChangeNoticeDto = {
    old_handle: string;
    new_handle: string;
  };

  // §6.1: a verified contact's handle changed, learned via a
  // `ProfileAnnounce` control message over the existing ratchet — no
  // key/ratchet impact, purely a display-label update.
  type PeerProfileChangeNoticeDto = {
    fingerprint: string;
    old_handle: string;
    new_handle: string;
  };

  const INBOX_UPDATED_EVENT = "dratchet://inbox-updated";
  const CONNECTION_STATUS_EVENT = "dratchet://connection-status";
  const FULL_WIPE_CONFIRM_PHRASE = "DELETE";

  // Live connection health (`docs/DELIVERY_FAILURE_FINDINGS.md` scenario
  // 23): `poll_loop` now reconnects on its own after a transport failure,
  // but silently — this is the only signal the user gets that it's
  // happening, rather than wondering why messages stopped arriving.
  type ConnectionStatusDto = "connected" | "reconnecting";
  let connectionStatus = $state<ConnectionStatusDto>("connected");

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

  // docs/ARCHITECTURE.md §6.1: this device's own username#NNNN.
  let ownProfile = $state<OwnProfileDto | null>(null);
  let profileUsernameInput = $state("");
  let profileBusy = $state(false);
  let profileError = $state("");
  let renamingProfile = $state(false);

  // §6.4: the pairing code this device generates to gate an incoming
  // add-contact attempt — read out over an already-trusted channel.
  let pairingCode = $state<PairingCodeDto | null>(null);
  let pairingCodeBusy = $state(false);
  let pairingCodeError = $state("");
  let nowTick = $state(Date.now());
  let pairingCodeRemaining = $derived(
    pairingCode ? Math.max(0, pairingCode.expires_at - Math.floor(nowTick / 1000)) : 0,
  );

  // §6.4: the initiator side — username#NNNN plus the code the peer read
  // out to add them.
  let addUsername = $state("");
  let addDiscriminator = $state("");
  let addCode = $state("");
  let addBusy = $state(false);
  let addError = $state("");
  let addResult = $state("");

  // Transient, auto-dismissing notices — own-handle-changed and
  // peer-handle-changed both surface here (§6.1). Not persisted; a missed
  // toast is recoverable by re-reading the contact's current handle, which
  // is why these don't block on user acknowledgement.
  type Toast = { id: number; text: string };
  let toasts = $state<Toast[]>([]);
  let nextToastId = 0;

  function pushToast(text: string) {
    const id = nextToastId++;
    toasts = [...toasts, { id, text }];
    setTimeout(() => {
      toasts = toasts.filter((t) => t.id !== id);
    }, 10000);
  }

  let conversationMenuOpen = $state(false);
  let clearArmed = $state(false);
  let clearBusy = $state(false);
  let clearResult = $state("");
  let clearError = $state("");
  let policyBusy = $state(false);
  let policyError = $state("");
  let pendingWipeBusy = $state(false);
  let pendingWipeError = $state("");

  async function selectContact(contact: ContactDto) {
    selected = contact;
    messages = [];
    sendError = "";
    conversationMenuOpen = false;
    clearArmed = false;
    clearResult = "";
    clearError = "";
    policyError = "";
    pendingWipeError = "";
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

  function toggleConversationMenu() {
    conversationMenuOpen = !conversationMenuOpen;
    clearArmed = false;
    clearResult = "";
    clearError = "";
    policyError = "";
  }

  // docs/ARCHITECTURE.md §11.9a: this side's own preference for the two
  // per-conversation wipe axes — announced to the peer immediately so the
  // effective (merged) policy stays in sync on both sides.
  async function setWipePolicy(askBeforeDelete: boolean, includeSession: boolean) {
    if (!selected) return;
    policyBusy = true;
    policyError = "";
    try {
      await invoke("set_wipe_policy", {
        fingerprint: selected.fingerprint,
        askBeforeDelete,
        includeSession,
      });
      selected = {
        ...selected,
        wipe_ask_before_delete: askBeforeDelete,
        wipe_include_session: includeSession,
      };
    } catch (e) {
      policyError = String(e);
    } finally {
      policyBusy = false;
    }
  }

  // §11.9a's "delete for everyone" — same two-click armed-confirm pattern
  // as the Danger Zone's quick wipe, for UI consistency.
  async function clearConversation() {
    if (!selected) return;
    if (!clearArmed) {
      clearArmed = true;
      return;
    }
    clearBusy = true;
    clearError = "";
    clearResult = "";
    try {
      const removed = await invoke<number>("request_conversation_wipe", {
        fingerprint: selected.fingerprint,
      });
      clearResult = `Cleared ${removed} record${removed === 1 ? "" : "s"}.`;
      clearArmed = false;
      await selectContact(selected);
    } catch (e) {
      clearError = String(e);
    } finally {
      clearBusy = false;
    }
  }

  async function allowPendingWipe() {
    if (!selected) return;
    pendingWipeBusy = true;
    pendingWipeError = "";
    try {
      await invoke("confirm_pending_wipe", { fingerprint: selected.fingerprint });
      await refetch();
    } catch (e) {
      pendingWipeError = String(e);
    } finally {
      pendingWipeBusy = false;
    }
  }

  async function declinePendingWipe() {
    if (!selected) return;
    pendingWipeBusy = true;
    pendingWipeError = "";
    try {
      await invoke("decline_pending_wipe", { fingerprint: selected.fingerprint });
      await refetch();
    } catch (e) {
      pendingWipeError = String(e);
    } finally {
      pendingWipeBusy = false;
    }
  }

  async function loadOwnProfile() {
    try {
      ownProfile = await invoke<OwnProfileDto | null>("get_own_profile");
    } catch (e) {
      profileError = String(e);
    }
  }

  // §6.1: checked once at startup — `reconcile_own_profile` only runs
  // once, during connect, before the UI is up at all, so this just drains
  // whatever it left behind.
  async function checkOwnDiscriminatorChangeNotice() {
    try {
      const notice = await invoke<OwnDiscriminatorChangeNoticeDto | null>(
        "take_own_discriminator_change_notice",
      );
      if (notice) {
        pushToast(
          `Your handle changed from ${notice.old_handle} to ${notice.new_handle} — ` +
            `someone else claimed your old handle after a server restart.`,
        );
      }
    } catch (e) {
      void e;
    }
  }

  // §6.1: checked alongside every `refetch` — the poll loop only emits
  // `INBOX_UPDATED_EVENT` when it actually queued a notice, so this never
  // runs against an empty queue in practice, but draining unconditionally
  // is simpler than threading a second signal through the event payload.
  async function checkPeerProfileChangeNotices() {
    let notices: PeerProfileChangeNoticeDto[] = [];
    try {
      notices = await invoke<PeerProfileChangeNoticeDto[]>("take_peer_profile_change_notices");
    } catch (e) {
      void e;
      return;
    }
    for (const notice of notices) {
      pushToast(`${notice.old_handle} is now ${notice.new_handle}.`);
    }
  }

  // §6.1: first-run self-registration, or a rename — both are the same
  // call (`register_own_profile` republishes under a new username exactly
  // like a fresh registration does).
  async function saveProfileUsername() {
    if (!profileUsernameInput.trim() || profileBusy) return;
    profileBusy = true;
    profileError = "";
    try {
      ownProfile = await invoke<OwnProfileDto>(
        ownProfile ? "rename_own_profile" : "register_own_profile",
        ownProfile
          ? { newUsername: profileUsernameInput.trim() }
          : { username: profileUsernameInput.trim() },
      );
      profileUsernameInput = "";
      renamingProfile = false;
    } catch (e) {
      profileError = String(e);
    } finally {
      profileBusy = false;
    }
  }

  function startRenameProfile() {
    renamingProfile = true;
    profileUsernameInput = "";
    profileError = "";
  }

  function cancelRenameProfile() {
    renamingProfile = false;
    profileUsernameInput = "";
    profileError = "";
  }

  async function generatePairingCode() {
    pairingCodeBusy = true;
    pairingCodeError = "";
    try {
      pairingCode = await invoke<PairingCodeDto>("generate_pairing_code");
    } catch (e) {
      pairingCodeError = String(e);
    } finally {
      pairingCodeBusy = false;
    }
  }

  async function addContact(event: Event) {
    event.preventDefault();
    const discriminator = Number(addDiscriminator);
    if (!addUsername.trim() || !Number.isInteger(discriminator) || !addCode.trim() || addBusy) {
      return;
    }
    addBusy = true;
    addError = "";
    addResult = "";
    try {
      const contact = await invoke<ContactDto>("add_contact", {
        username: addUsername.trim(),
        discriminator,
        pairingCode: addCode.trim(),
      });
      addResult = `Added ${contact.handle}.`;
      addUsername = "";
      addDiscriminator = "";
      addCode = "";
      await refetch();
    } catch (e) {
      // Deliberately the same message whether the username doesn't exist,
      // the code was wrong, or it expired — see docs/ARCHITECTURE.md §6.4:
      // that distinction is exactly the oracle this design avoids leaking.
      addError = "Couldn't add that contact — check the username and code.";
      void e;
    } finally {
      addBusy = false;
    }
  }

  function openSettings() {
    settingsOpen = true;
    quickWipeArmed = false;
    quickWipeResult = "";
    quickWipeError = "";
    fullWipeConfirmText = "";
    fullWipeError = "";
    profileError = "";
    renamingProfile = false;
    pairingCodeError = "";
    addError = "";
    addResult = "";
    loadOwnProfile();
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

  async function loadConnectionStatus() {
    try {
      connectionStatus = await invoke<ConnectionStatusDto>("get_connection_status");
    } catch (e) {
      void e;
    }
  }

  onMount(() => {
    refetch();
    loadOwnProfile();
    checkOwnDiscriminatorChangeNotice();
    loadConnectionStatus();
    const unlisten = listen(INBOX_UPDATED_EVENT, () => {
      refetch();
      checkPeerProfileChangeNotices();
    });
    const unlistenConnection = listen<ConnectionStatusDto>(CONNECTION_STATUS_EVENT, (event) => {
      connectionStatus = event.payload;
    });
    const tickInterval = setInterval(() => {
      nowTick = Date.now();
    }, 1000);
    return () => {
      unlisten.then((f) => f());
      unlistenConnection.then((f) => f());
      clearInterval(tickInterval);
    };
  });
</script>

{#if toasts.length > 0}
  <div class="toast-stack">
    {#each toasts as toast (toast.id)}
      <div class="toast">{toast.text}</div>
    {/each}
  </div>
{/if}

<div class="shell">
  <aside class="sidebar">
    <div class="brand-row">
      <div class="brand-with-status">
        <div class="brand">DRAtchet</div>
        {#if connectionStatus === "reconnecting"}
          <span class="connection-badge" title="The connection to the server dropped — retrying automatically.">
            <span class="connection-dot"></span>Reconnecting…
          </span>
        {/if}
      </div>
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
      <div class="conversation-header">
        <span>{selected.handle}</span>
        <div class="conversation-menu-wrap">
          <button
            class="conversation-menu-button"
            onclick={toggleConversationMenu}
            aria-label="Conversation settings"
          >
            ⋯
          </button>
          {#if conversationMenuOpen}
            <div class="conversation-menu">
              <label class="menu-toggle">
                <input
                  type="checkbox"
                  checked={selected.wipe_ask_before_delete}
                  disabled={policyBusy}
                  onchange={(e) =>
                    setWipePolicy((e.target as HTMLInputElement).checked, selected!.wipe_include_session)}
                />
                Ask before deleting when {selected.handle} clears this chat
              </label>
              <label class="menu-toggle">
                <input
                  type="checkbox"
                  checked={selected.wipe_include_session}
                  disabled={policyBusy}
                  onchange={(e) =>
                    setWipePolicy(selected!.wipe_ask_before_delete, (e.target as HTMLInputElement).checked)}
                />
                Also end the session when clearing this chat
              </label>
              {#if policyError}
                <div class="menu-error">{policyError}</div>
              {/if}
              <div class="menu-divider"></div>
              <button
                class="menu-clear-button"
                class:armed={clearArmed}
                disabled={clearBusy}
                onclick={clearConversation}
              >
                {#if clearBusy}
                  Clearing…
                {:else if clearArmed}
                  Confirm clear
                {:else}
                  Clear conversation
                {/if}
              </button>
              {#if clearResult}
                <div class="menu-result">{clearResult}</div>
              {/if}
              {#if clearError}
                <div class="menu-error">{clearError}</div>
              {/if}
            </div>
          {/if}
        </div>
      </div>
      {#if selected.wipe_request_pending}
        <div class="wipe-request-banner">
          <span>{selected.handle} wants to clear this conversation.</span>
          <div class="wipe-request-actions">
            <button disabled={pendingWipeBusy} onclick={allowPendingWipe}>Allow</button>
            <button disabled={pendingWipeBusy} onclick={declinePendingWipe}>Decline</button>
          </div>
          {#if pendingWipeError}
            <div class="menu-error">{pendingWipeError}</div>
          {/if}
        </div>
      {/if}
      <div class="messages">
        {#each messages as message (message.id)}
          <div class="bubble" class:local={message.sender_is_local}>
            {message.content}
            {#if message.sender_is_local}
              <span class="delivery-status" class:delivered={message.delivered}>
                {message.delivered ? "✓✓" : "✓"}
              </span>
            {/if}
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

      <div class="profile-section">
        <div class="section-title">My Profile</div>
        {#if !ownProfile}
          <p class="section-note">
            Choose a username to register with the directory — needed before
            anyone can add you as a contact.
          </p>
          <form
            class="profile-form"
            onsubmit={(e) => {
              e.preventDefault();
              saveProfileUsername();
            }}
          >
            <input
              class="profile-input"
              placeholder="username"
              bind:value={profileUsernameInput}
              disabled={profileBusy}
            />
            <button
              class="profile-button"
              disabled={profileBusy || !profileUsernameInput.trim()}
            >
              {profileBusy ? "Registering…" : "Register"}
            </button>
          </form>
        {:else if renamingProfile}
          <form
            class="profile-form"
            onsubmit={(e) => {
              e.preventDefault();
              saveProfileUsername();
            }}
          >
            <input
              class="profile-input"
              placeholder="new username"
              bind:value={profileUsernameInput}
              disabled={profileBusy}
            />
            <button
              class="profile-button"
              disabled={profileBusy || !profileUsernameInput.trim()}
            >
              {profileBusy ? "Saving…" : "Save"}
            </button>
            <button
              type="button"
              class="profile-button-secondary"
              disabled={profileBusy}
              onclick={cancelRenameProfile}
            >
              Cancel
            </button>
          </form>
        {:else}
          <div class="profile-row">
            <span class="profile-handle">{ownProfile.handle}</span>
            <button class="profile-button-secondary" onclick={startRenameProfile}>
              Change username
            </button>
          </div>
        {/if}
        {#if profileError}
          <div class="danger-error">{profileError}</div>
        {/if}
      </div>

      <div class="profile-section">
        <div class="section-title">My Pairing Code</div>
        <p class="section-note">
          Generate a one-time code and read it out to someone over a channel
          you already trust (in person, a phone call, an existing verified
          chat) so they can add you as a contact. A leaked or guessed
          username alone is never enough to reach you.
        </p>
        {#if pairingCode && pairingCodeRemaining > 0}
          <div class="pairing-code-display">{pairingCode.code}</div>
          <p class="section-note">Expires in {pairingCodeRemaining}s.</p>
        {/if}
        <button class="profile-button" disabled={pairingCodeBusy} onclick={generatePairingCode}>
          {pairingCodeBusy ? "Generating…" : "Generate a new code"}
        </button>
        {#if pairingCodeError}
          <div class="danger-error">{pairingCodeError}</div>
        {/if}
      </div>

      <div class="profile-section">
        <div class="section-title">Add a Contact</div>
        <p class="section-note">
          Enter their username and the code they read out to you.
        </p>
        <form class="add-contact-form" onsubmit={addContact}>
          <div class="add-contact-row">
            <input
              class="profile-input"
              placeholder="username"
              bind:value={addUsername}
              disabled={addBusy}
            />
            <span class="add-contact-hash">#</span>
            <input
              class="profile-input add-contact-discriminator"
              placeholder="0000"
              bind:value={addDiscriminator}
              disabled={addBusy}
            />
          </div>
          <input
            class="profile-input"
            placeholder="6-digit code"
            bind:value={addCode}
            disabled={addBusy}
          />
          <button class="profile-button" disabled={addBusy || !ownProfile}>
            {addBusy ? "Adding…" : "Add contact"}
          </button>
          {#if !ownProfile}
            <p class="section-note">Register your own username first.</p>
          {/if}
        </form>
        {#if addResult}
          <div class="danger-result">{addResult}</div>
        {/if}
        {#if addError}
          <div class="danger-error">{addError}</div>
        {/if}
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

  .brand-with-status {
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 0;
  }

  .brand {
    font-family: var(--display);
    font-weight: 600;
    color: var(--brass-strong);
    padding: 18px 16px;
  }

  .connection-badge {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 3px 9px;
    border: 1px solid var(--amber);
    border-radius: 999px;
    color: var(--amber);
    font-size: 11px;
    white-space: nowrap;
  }

  .connection-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--amber);
    animation: connection-pulse 1.4s ease-in-out infinite;
  }

  @media (prefers-reduced-motion: reduce) {
    .connection-dot {
      animation: none;
    }
  }

  @keyframes connection-pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.35;
    }
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
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    border-bottom: 1px solid var(--line);
    font-family: var(--display);
  }

  .conversation-menu-wrap {
    position: relative;
  }

  .conversation-menu-button {
    background: transparent;
    border: none;
    color: var(--ink-faint);
    font-size: 16px;
    line-height: 1;
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
  }

  .conversation-menu-button:hover {
    background: var(--bg-raised);
    color: var(--ink);
  }

  .conversation-menu {
    position: absolute;
    top: 100%;
    right: 0;
    margin-top: 6px;
    width: 300px;
    background: var(--bg-raised);
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 14px;
    z-index: 5;
    font-family: var(--sans);
  }

  .menu-toggle {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    font-size: 12px;
    color: var(--ink-soft);
    line-height: 1.4;
    margin-bottom: 10px;
    cursor: pointer;
  }

  .menu-toggle input {
    margin-top: 2px;
  }

  .menu-divider {
    border-top: 1px solid var(--line-soft);
    margin: 10px 0;
  }

  .menu-clear-button {
    width: 100%;
    padding: 8px 10px;
    background: var(--bg-sunken);
    border: 1px solid var(--red);
    color: var(--red);
    border-radius: 6px;
    font-weight: 600;
    font-size: 12px;
    cursor: pointer;
  }

  .menu-clear-button:hover:not(:disabled) {
    background: var(--red);
    color: var(--bg-sunken);
  }

  .menu-clear-button.armed {
    background: var(--red);
    color: var(--bg-sunken);
  }

  .menu-clear-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .menu-result {
    color: var(--teal);
    font-size: 12px;
    margin-top: 6px;
  }

  .menu-error {
    color: var(--red);
    font-size: 12px;
    margin-top: 6px;
  }

  .toast-stack {
    position: fixed;
    top: 16px;
    right: 16px;
    z-index: 100;
    display: flex;
    flex-direction: column;
    gap: 8px;
    max-width: 360px;
  }

  .toast {
    padding: 12px 14px;
    background: var(--bg-raised);
    border: 1px solid var(--amber);
    border-radius: 8px;
    color: var(--ink);
    font-size: 13px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.35);
  }

  .wipe-request-banner {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 20px;
    background: var(--amber-dim);
    border-bottom: 1px solid var(--amber);
    color: var(--ink);
    font-size: 13px;
  }

  .wipe-request-actions {
    display: flex;
    gap: 8px;
    flex-shrink: 0;
  }

  .wipe-request-actions button {
    padding: 6px 12px;
    background: var(--bg-sunken);
    border: 1px solid var(--line-soft);
    color: var(--ink);
    border-radius: 6px;
    font-size: 12px;
    cursor: pointer;
  }

  .wipe-request-actions button:hover:not(:disabled) {
    background: var(--bg-raised);
  }

  .wipe-request-actions button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
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

  .delivery-status {
    margin-left: 6px;
    font-size: 11px;
    opacity: 0.5;
    letter-spacing: -1px;
  }

  .delivery-status.delivered {
    opacity: 0.85;
    color: var(--teal);
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

  .profile-section {
    padding: 20px;
    border-bottom: 1px solid var(--line-soft);
  }

  .section-title {
    font-family: var(--display);
    color: var(--brass-strong);
    font-weight: 600;
    margin-bottom: 8px;
  }

  .section-note {
    color: var(--ink-faint);
    font-size: 12px;
    line-height: 1.5;
    margin: 0 0 10px;
  }

  .profile-form,
  .add-contact-form {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .add-contact-row {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .add-contact-hash {
    color: var(--ink-faint);
    font-family: var(--display);
  }

  .add-contact-discriminator {
    flex: 0 0 80px;
  }

  .profile-input {
    flex: 1;
    box-sizing: border-box;
    padding: 8px 10px;
    background: var(--bg-sunken);
    border: 1px solid var(--line-soft);
    border-radius: 6px;
    color: var(--ink);
    font: inherit;
    font-size: 13px;
  }

  .profile-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .profile-handle {
    font-family: var(--display);
    color: var(--ink);
    font-size: 14px;
  }

  .profile-button {
    flex-shrink: 0;
    padding: 8px 14px;
    background: var(--brass-dim);
    border: 1px solid var(--brass);
    color: var(--brass-strong);
    border-radius: 6px;
    font-weight: 600;
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
  }

  .profile-button:hover:not(:disabled) {
    background: var(--brass);
    color: var(--bg-sunken);
  }

  .profile-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .profile-button-secondary {
    flex-shrink: 0;
    padding: 6px 12px;
    background: transparent;
    border: 1px solid var(--line-soft);
    color: var(--ink-soft);
    border-radius: 6px;
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
  }

  .profile-button-secondary:hover:not(:disabled) {
    background: var(--bg-sunken);
    color: var(--ink);
  }

  .pairing-code-display {
    font-family: var(--display);
    font-size: 28px;
    font-weight: 600;
    letter-spacing: 4px;
    color: var(--teal);
    background: var(--bg-sunken);
    border: 1px solid var(--teal-dim);
    border-radius: 8px;
    padding: 12px;
    text-align: center;
    margin-bottom: 8px;
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
