//! Thin WebSocket wrapper over the wire protocol
//! (`dratchet_server::protocol`) — connect, authenticate (self-certifying,
//! `server/src/ws.rs`'s module doc), send/receive typed frames. Mirrors
//! `server/tests/common/mod.rs::TestClient`'s shape deliberately: same
//! protocol, same framing, just application code instead of a test double.

use dratchet_core::account::Account;
use dratchet_server::protocol::*;
use futures_util::{SinkExt, StreamExt};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

pub type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub struct Connection {
    ws: WsStream,
}

impl Connection {
    pub async fn connect(url: &str) -> Result<Self, String> {
        let (ws, _resp) = connect_async(url)
            .await
            .map_err(|e| format!("failed to connect to {url}: {e}"))?;
        Ok(Connection { ws })
    }

    pub async fn send<T: Serialize>(&mut self, tag: FrameTag, body: &T) -> Result<(), String> {
        let frame = encode(tag, body);
        self.ws
            .send(WsMessage::Binary(frame))
            .await
            .map_err(|e| format!("send failed: {e}"))
    }

    /// Wait for the next binary frame, skipping any non-binary control
    /// frames the underlying transport surfaces.
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>, String> {
        loop {
            match self.ws.next().await {
                Some(Ok(WsMessage::Binary(b))) => return Ok(b),
                Some(Ok(_)) => continue,
                Some(Err(e)) => return Err(format!("connection error: {e}")),
                None => return Err("connection closed".to_string()),
            }
        }
    }

    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<(FrameTag, T), String> {
        let raw = self.recv_raw().await?;
        let (tag, body) = split_tag(&raw).map_err(|e| e.to_string())?;
        let parsed: T = decode_body(body).map_err(|e| e.to_string())?;
        Ok((tag, parsed))
    }

    /// Full self-certifying auth handshake: receive the challenge the
    /// server always sends first, sign it, send it back. Never requires a
    /// prior `PublishBundle` (`server/src/ws.rs`'s module doc).
    pub async fn authenticate(&mut self, account: &Account) -> Result<(), String> {
        let (tag, challenge): (_, AuthChallenge) = self.recv().await?;
        if tag != FrameTag::AuthChallenge {
            return Err(format!("expected AuthChallenge, got {tag:?}"));
        }
        let signature = account
            .identity
            .sign(&challenge.nonce)
            .map_err(|e| e.to_string())?;
        let identity_key = account
            .identity
            .export_public_key()
            .map_err(|e| e.to_string())?;
        self.send(
            FrameTag::AuthResponse,
            &AuthResponse {
                identity_key,
                signature,
            },
        )
        .await?;
        let (tag, ack): (_, Ack) = self.recv().await?;
        if tag != FrameTag::Ack || !ack.ok {
            return Err("authentication was not acknowledged".to_string());
        }
        Ok(())
    }
}
