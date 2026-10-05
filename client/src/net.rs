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

/// DRA-0058: why a [`Connection`] call failed, as a value callers can
/// branch on. These used to be plain `String`s, and the app filed every
/// one of them as a lost connection -- so a server refusal (rate limited,
/// not the owner) tore down a healthy connection and reconnected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetError {
    /// The transport itself failed: couldn't connect, a send failed, or
    /// the socket errored or closed. Reconnecting is the right response.
    Connection(String),
    /// The server received the request and refused it. The connection is
    /// fine; `code` says why (`ErrorCode::is_rate_limit` for "slow down").
    Refused { code: ErrorCode, message: String },
    /// A frame arrived that didn't match what the protocol allows here --
    /// malformed, or an unexpected type. Not a transport failure.
    Protocol(String),
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Connection(msg) => write!(f, "{msg}"),
            NetError::Refused { message, .. } => {
                write!(f, "server refused the request: {message}")
            }
            NetError::Protocol(msg) => write!(f, "protocol error: {msg}"),
        }
    }
}

impl std::error::Error for NetError {}

/// Lets the CLI (`src/main.rs`), whose functions still return `String`,
/// keep using `?` on these calls.
impl From<NetError> for String {
    fn from(e: NetError) -> Self {
        e.to_string()
    }
}

/// DRA-0061: the longest a single send, or a wait for the server's reply,
/// may take before the connection is treated as lost. Every exchange on a
/// `Connection` is request/response, so a healthy server answers well
/// within this; without it, a stalled network (packets dropped, connection
/// never closed) left a caller waiting until the OS gave up on the socket,
/// holding whatever lock guarded the connection the whole time.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

pub struct Connection {
    ws: WsStream,
    request_timeout: std::time::Duration,
    server_boot_id: Vec<u8>,
    /// DRA-0065: set once a send or receive fails at the transport level.
    lost: bool,
    /// DRA-0069: frames the server pushed unprompted, set aside so they're
    /// never taken as a reply. Bounded; the oldest are dropped first.
    pushes: std::collections::VecDeque<Vec<u8>>,
}

/// DRA-0069: most unprompted frames kept for [`Connection::take_pushes`].
pub const MAX_HELD_PUSHES: usize = 64;

/// DRA-0069: frame types the server sends without being asked -- relayed
/// rendezvous frames and presence updates. Never a reply to a request.
pub fn is_server_push(tag: FrameTag) -> bool {
    matches!(
        tag,
        FrameTag::RendezvousOffer | FrameTag::RendezvousAnswer | FrameTag::PresenceUpdate
    )
}

impl Connection {
    pub async fn connect(url: &str) -> Result<Self, NetError> {
        Self::connect_with_timeout(url, REQUEST_TIMEOUT).await
    }

    /// DRA-0068: [`connect`](Self::connect), giving up after `timeout`. A
    /// server that accepts the TCP connection but never answers (a hung
    /// process: the kernel still completes the handshake) otherwise left
    /// the caller waiting indefinitely.
    pub async fn connect_with_timeout(
        url: &str,
        timeout: std::time::Duration,
    ) -> Result<Self, NetError> {
        let (ws, _resp) = tokio::time::timeout(timeout, connect_async(url))
            .await
            .map_err(|_| {
                NetError::Connection(format!(
                    "no response from {url} within {}s",
                    timeout.as_secs_f32()
                ))
            })?
            .map_err(|e| NetError::Connection(format!("failed to connect to {url}: {e}")))?;
        Ok(Connection {
            ws,
            request_timeout: REQUEST_TIMEOUT,
            server_boot_id: Vec::new(),
            lost: false,
            pushes: std::collections::VecDeque::new(),
        })
    }

    /// Override [`REQUEST_TIMEOUT`] for this connection (tests use a short
    /// one).
    pub fn set_request_timeout(&mut self, timeout: std::time::Duration) {
        self.request_timeout = timeout;
    }

    /// DRA-0064: the server process's boot id from its `AuthChallenge`
    /// (empty before [`authenticate`](Self::authenticate), or from a server
    /// that predates it). A change since the last connection means the
    /// server restarted and lost every queued message.
    /// DRA-0069: the frames the server pushed unprompted since the last
    /// call, oldest first (at most [`MAX_HELD_PUSHES`]).
    pub fn take_pushes(&mut self) -> Vec<Vec<u8>> {
        self.pushes.drain(..).collect()
    }

    pub fn server_boot_id(&self) -> &[u8] {
        &self.server_boot_id
    }

    /// DRA-0065: whether this connection has already failed. A lost
    /// connection is never usable again (after a timeout, a late reply
    /// could be mistaken for the next request's), so every further
    /// [`send`](Self::send) and [`recv_raw`](Self::recv_raw) fails at once.
    /// Callers check this before spending anything on a send that can't
    /// succeed -- a ratchet chain position in particular.
    pub fn is_lost(&self) -> bool {
        self.lost
    }

    fn already_lost() -> NetError {
        NetError::Connection("connection already lost".to_string())
    }

    fn timed_out(&self) -> NetError {
        NetError::Connection(format!(
            "no response from the server within {}s",
            self.request_timeout.as_secs_f32()
        ))
    }

    pub async fn send<T: Serialize>(&mut self, tag: FrameTag, body: &T) -> Result<(), NetError> {
        if self.lost {
            return Err(Self::already_lost());
        }
        let frame = encode(tag, body);
        let result = match tokio::time::timeout(
            self.request_timeout,
            self.ws.send(WsMessage::Binary(frame)),
        )
        .await
        {
            Ok(sent) => sent.map_err(|e| NetError::Connection(format!("send failed: {e}"))),
            Err(_) => Err(self.timed_out()),
        };
        self.lost = result.is_err();
        result
    }

    /// Wait for the next binary frame, skipping any non-binary control
    /// frames the underlying transport surfaces.
    ///
    /// DRA-0069: frames the server pushes unprompted ([`is_server_push`])
    /// are set aside for [`take_pushes`](Self::take_pushes), never returned
    /// here, so they can't be read as the reply to a request. The timeout
    /// covers the whole wait, however many such frames arrive meanwhile.
    pub async fn recv_raw(&mut self) -> Result<Vec<u8>, NetError> {
        if self.lost {
            return Err(Self::already_lost());
        }
        let deadline = tokio::time::Instant::now() + self.request_timeout;
        let failure = loop {
            let Ok(next) = tokio::time::timeout_at(deadline, self.ws.next()).await else {
                break self.timed_out();
            };
            match next {
                Some(Ok(WsMessage::Binary(b))) => {
                    if split_tag(&b).is_ok_and(|(tag, _)| is_server_push(tag)) {
                        if self.pushes.len() == MAX_HELD_PUSHES {
                            self.pushes.pop_front();
                        }
                        self.pushes.push_back(b);
                        continue;
                    }
                    return Ok(b);
                }
                Some(Ok(_)) => continue,
                Some(Err(e)) => break NetError::Connection(format!("connection error: {e}")),
                None => break NetError::Connection("connection closed".to_string()),
            }
        };
        self.lost = true;
        Err(failure)
    }

    /// DRA-0052 (`docs/DELIVERY_FAILURE_FINDINGS.md`): if the server
    /// replied with `FrameTag::Error`, that is reported as such —
    /// carrying its real `ErrorFrame.message` — instead of being handed
    /// to `decode_body::<T>`, which would simply fail to parse an
    /// `ErrorFrame`'s bytes as whatever type the caller expected and
    /// report a generic, indistinguishable-from-corruption decode
    /// failure. A genuine, expected server refusal (rate limited, not
    /// the resource owner, anything else `Error` covers) must never look
    /// the same to a caller as the wire protocol being broken.
    ///
    /// DRA-0058: a refusal comes back as [`NetError::Refused`] carrying the
    /// server's [`ErrorCode`], and an undecodable frame as
    /// [`NetError::Protocol`] -- neither is a lost connection.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<(FrameTag, T), NetError> {
        let raw = self.recv_raw().await?;
        let (tag, body) = split_tag(&raw).map_err(|e| NetError::Protocol(e.to_string()))?;
        if tag == FrameTag::Error {
            let err: ErrorFrame =
                decode_body(body).map_err(|e| NetError::Protocol(e.to_string()))?;
            return Err(NetError::Refused {
                code: err.code,
                message: err.message,
            });
        }
        let parsed: T = decode_body(body).map_err(|e| NetError::Protocol(e.to_string()))?;
        Ok((tag, parsed))
    }

    /// Full self-certifying auth handshake: receive the challenge the
    /// server always sends first, sign it, send it back. Never requires a
    /// prior `PublishBundle` (`server/src/ws.rs`'s module doc).
    pub async fn authenticate(&mut self, account: &Account) -> Result<(), NetError> {
        let (tag, challenge): (_, AuthChallenge) = self.recv().await?;
        self.server_boot_id = challenge.server_boot_id.clone();
        if tag != FrameTag::AuthChallenge {
            return Err(NetError::Protocol(format!(
                "expected AuthChallenge, got {tag:?}"
            )));
        }
        // DRA-0039: domain-separated -- never sign a server-chosen value
        // verbatim, or the client becomes a signing oracle for the prekey
        // context (see `Identity::sign_auth_challenge`).
        let signature = account
            .identity
            .sign_auth_challenge(&challenge.nonce)
            .map_err(|e| NetError::Protocol(e.to_string()))?;
        let identity_key = account
            .identity
            .export_public_key()
            .map_err(|e| NetError::Protocol(e.to_string()))?;
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
            return Err(NetError::Protocol(
                "authentication was not acknowledged".to_string(),
            ));
        }
        Ok(())
    }
}
