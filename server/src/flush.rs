//! Saving queued mail to the mail store (`docs/adr/0001`).
//!
//! A background task saves every unsaved entry each `save_interval`, or
//! sooner when woken (a write with a zero interval, or memory at half its
//! limit). A save writes the batch durably, removes stored entries that
//! have since been collected or expired, then marks the batch saved --
//! dropping their envelopes from memory -- and publishes its sequence
//! number, which is what releases those writers' acknowledgements.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::SystemTime;

use crate::mailstore::{PendingEntry, StoreError};
use crate::state::AppState;

/// Save everything unsaved now. A no-op without a mail store.
pub async fn flush_now(state: &Arc<AppState>) -> Result<(), StoreError> {
    let Some(store) = state.mail_store.clone() else {
        return Ok(());
    };
    let _serial = state.flush_lock.lock().await;
    let (seq, batch, live) = {
        let mut inner = state.inner.write().await;
        let seq = inner.next_flush_seq;
        inner.next_flush_seq += 1;
        let now = SystemTime::now();
        let mut batch = Vec::new();
        let mut live = HashSet::new();
        for (mailbox_id, entries) in &inner.mailboxes {
            for e in entries.iter().filter(|e| e.expires_at > now) {
                live.insert(e.entry_id);
                if !e.saved {
                    batch.push(PendingEntry {
                        mailbox_id: *mailbox_id,
                        entry_id: e.entry_id,
                        envelope: e.envelope.clone(),
                        expires_at: e
                            .expires_at
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0),
                        written_by: e.written_by,
                    });
                }
            }
        }
        (seq, batch, live)
    };
    let saved_ids: HashSet<[u8; 16]> = batch.iter().map(|e| e.entry_id).collect();
    let io_store = store.clone();
    tokio::task::spawn_blocking(move || -> Result<(), StoreError> {
        io_store.save(&batch)?;
        io_store.retain(&live)?;
        Ok(())
    })
    .await
    .expect("mail store save task panicked")?;

    let mut inner = state.inner.write().await;
    for entries in inner.mailboxes.values_mut() {
        for e in entries
            .iter_mut()
            .filter(|e| saved_ids.contains(&e.entry_id))
        {
            e.saved = true;
            e.envelope = Vec::new();
        }
    }
    inner.recount_memory();
    drop(inner);
    state.flushed.send_replace(seq);
    Ok(())
}

/// Run the save loop for as long as the process lives.
pub fn spawn_flusher(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if state.mail_store.is_none() {
            return;
        }
        loop {
            if state.save_interval.is_zero() {
                state.flush_notify.notified().await;
            } else {
                tokio::select! {
                    _ = tokio::time::sleep(state.save_interval) => {}
                    _ = state.flush_notify.notified() => {}
                }
            }
            if let Err(e) = flush_now(&state).await {
                tracing::error!("mail store: save failed, will retry: {e}");
            }
        }
    })
}

/// On a graceful shutdown: save what's left and, only if that worked,
/// record a clean shutdown so the next start keeps the same Server Epoch.
pub async fn shutdown(state: &Arc<AppState>) {
    let Some(store) = state.mail_store.clone() else {
        return;
    };
    match flush_now(state).await {
        Ok(()) => match store.mark_clean_shutdown() {
            Ok(()) => tracing::info!("mail store: final save complete"),
            Err(e) => tracing::error!("mail store: could not record a clean shutdown: {e}"),
        },
        Err(e) => tracing::error!(
            "mail store: final save failed; the next start will begin a new server epoch: {e}"
        ),
    }
}
