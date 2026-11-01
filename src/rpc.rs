//! Generic request/response over QUIC bidirectional streams.
//!
//! A request/response exchange is: the requester opens a bidirectional stream,
//! writes one length-prefixed request frame, then reads one length-prefixed
//! response frame. The responder reads the request, hands it to a caller
//! supplied handler, and writes the response back.
//!
//! The request and response types are generic [`Message`]s supplied by the
//! caller; the [`crate::packet::Packet`] envelope enforces the protocol
//! signature on both sides.

use quinn::{Connection, RecvStream, SendStream};

use crate::error::{Error, Result};
use crate::packet::{Message, Packet};

/// The maximum size of a single framed message accepted from a peer.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Sends a single request over `conn` and awaits the response.
pub async fn request<Req, Res>(conn: &Connection, request: &Req) -> Result<Res>
where
    Req: Message,
    Res: Message,
{
    let (mut send, mut recv) = conn.open_bi().await?;
    let frame = Packet::frame(request)?;
    send.write_all(&frame).await?;
    send.finish()?;

    let resp_frame = recv.read_to_end(MAX_FRAME).await?;
    let packet = Packet::from_frame(&resp_frame)?;
    Ok(packet.decode()?)
}

/// Reads one length-prefixed request frame from a receive stream and decodes it.
pub async fn read_request<Req>(recv: &mut RecvStream) -> Result<Req>
where
    Req: Message,
{
    let body = read_frame(recv, MAX_FRAME).await?;
    // `read_frame` already stripped the length prefix, so parse the body.
    let packet = Packet::from_bytes(&body)?;
    Ok(packet.decode()?)
}

/// Writes a single framed response to the send stream.
pub async fn write_response<Res>(send: &mut SendStream, response: &Res) -> Result<()>
where
    Res: Message,
{
    let frame = Packet::frame(response)?;
    send.write_all(&frame).await?;
    send.finish()?;
    Ok(())
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