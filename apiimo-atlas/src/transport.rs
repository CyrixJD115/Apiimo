//! Loopback WebSocket transport (reference: `HomelandLocalWebSocket`).
//!
//! Exact loopback URL, no discovery scan, credential query string or
//! redirects; 5-second receive timeout that closes the socket; 8 MiB maximum
//! message. The native frame handler consumes JSON text, not a guessed binary
//! envelope.

use crate::types::Failure;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use tokio::net::TcpStream;

const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MESSAGE_SIZE: usize = 8 * 1024 * 1024;

pub struct HomelandLocalWebSocket {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl HomelandLocalWebSocket {
    pub async fn connect(port: u16) -> Result<Self, Failure> {
        if port == 0 {
            return Err(Failure::InvalidEndpoint);
        }
        let url = format!("ws://127.0.0.1:{port}/");
        let (stream, _) = connect_async(url)
            .await
            .map_err(|_| Failure::TransportClosed)?;
        Ok(Self { stream })
    }

    pub async fn send(&mut self, data: &[u8]) -> Result<(), Failure> {
        let text = std::str::from_utf8(data).map_err(|_| Failure::InvalidReply)?;
        if text.len() > MAX_MESSAGE_SIZE {
            return Err(Failure::InvalidRequest);
        }
        self.stream
            .send(tokio_tungstenite::tungstenite::Message::Text(text.to_owned()))
            .await
            .map_err(ws_close)
    }

    /// Receive with the fixed timeout. A timeout closes the actual socket and
    /// reports that fact rather than leaving callers with a falsely healthy
    /// connection (reference: the Swift task-group race + cancel).
    pub async fn receive(&mut self) -> Result<Vec<u8>, Failure> {
        loop {
            let msg = tokio::time::timeout(RECEIVE_TIMEOUT, self.stream.next())
                .await
                .map_err(|_| Failure::Timeout)?;
            let msg = msg.ok_or(Failure::TransportClosed)?;
            match msg.map_err(ws_close)? {
                tokio_tungstenite::tungstenite::Message::Text(text) => {
                    if text.len() > MAX_MESSAGE_SIZE {
                        return Err(Failure::InvalidReply);
                    }
                    return Ok(text.into_bytes());
                }
                tokio_tungstenite::tungstenite::Message::Binary(data) => {
                    if data.len() > MAX_MESSAGE_SIZE {
                        return Err(Failure::InvalidReply);
                    }
                    return Ok(data);
                }
                tokio_tungstenite::tungstenite::Message::Ping(_) | tokio_tungstenite::tungstenite::Message::Pong(_) => {
                    continue;
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    return Err(Failure::TransportClosed);
                }
                tokio_tungstenite::tungstenite::Message::Frame(_) => {
                    continue;
                }
            }
        }
    }

    pub async fn close(&mut self) {
        let _ = self
            .stream
            .send(tokio_tungstenite::tungstenite::Message::Close(None))
            .await;
        let _ = futures_util::SinkExt::close(&mut self.stream).await;
    }
}

fn ws_close(_: tokio_tungstenite::tungstenite::Error) -> Failure {
    Failure::TransportClosed
}
