//! Request/response over QUIC bidirectional streams.
//!
//! A transaction is: the requester opens a bidirectional stream, writes a
//! stream-kind byte plus one framed request, then reads one framed response. The
//! responder reads the request, hands it to a caller-supplied handler, and writes
//! the response back.
//!
//! [`send_transaction`] uses the [`Transaction`] trait, which pins the response
//! type to the request type. The request and response types are [`Message`]s;
//! the [`crate::packet::Packet`] envelope enforces the protocol signature on both
//! sides.

use quinn::{Connection, RecvStream};

use crate::error::{Error, Result};
use crate::framing::{StreamKind, prepend_kind_length};
use crate::packet::{Command, Packet};

/// The maximum size of a single framed message accepted from a peer.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// A request that pins its own response type.
///
/// Implementing this for a request type makes the request→response pairing a
/// compile-time guarantee: [`send_transaction`] returns `Self::Response`, so the
/// caller cannot mistake which response belongs to which request.
pub trait Transaction: Command {
    /// The exact response type this request produces.
    type Response: Command;
}

/// Sends a single transaction over `conn` and awaits its typed response.
pub async fn send_transaction<Req>(conn: &Connection, request: &Req) -> Result<Req::Response>
where
    Req: Transaction,
{
    let (mut send, mut recv) = conn.open_bi().await?;
    let body = Packet::encode(request)?.to_bytes()?;
    let frame = prepend_kind_length(StreamKind::Transaction, &body);
    send.write_all(&frame).await?;
    send.finish()?;

    let (kind, resp_body) = read_kind_frame(&mut recv, MAX_FRAME).await?;
    if kind != StreamKind::Transaction {
        return Err(Error::UnknownStreamKind(kind as u8));
    }
    let packet = Packet::from_bytes(&resp_body)?;
    Ok(packet.decode()?)
}

/// Reads a single length-prefixed frame from a receive stream.
pub async fn read_frame(recv: &mut RecvStream, max: usize) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(Error::FrameTooLarge(len));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    Ok(body)
}

/// Reads a stream-kind byte plus a length-prefixed frame from a receive stream.
///
/// Returns the kind and the decoded packet body (length prefix already stripped).
pub async fn read_kind_frame(recv: &mut RecvStream, max: usize) -> Result<(StreamKind, Vec<u8>)> {
    let mut kind_buf = [0u8; 1];
    recv.read_exact(&mut kind_buf).await?;
    let kind = StreamKind::from_byte(kind_buf[0]).ok_or(Error::UnknownStreamKind(kind_buf[0]))?;

    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > max {
        return Err(Error::FrameTooLarge(len));
    }
    let mut body = vec![0u8; len];
    recv.read_exact(&mut body).await?;
    Ok((kind, body))
}