//! src/transport.rs
//!
//! Dev 1: Inbound TCP Server & Wire Framing.
//!
//! Owns the persistent listener on `0.0.0.0:9000`, generates the secret
//! provider seed rP, negotiates the H(rP) commitment handshake with each
//! connecting client, captures the resulting `SessionConfig`, and
//! (de)serializes SPMP binary frames.
//!
//! Wire format (my choice — flag if this needs to match something already
//! agreed elsewhere):
//!
//!   [4 bytes]  magic    = SPMP_MAGIC, big-endian (spells "SPMP" on the wire)
//!   [1 byte ]  msg_type = MsgType as u8
//!   [4 bytes]  len      = u32 little-endian, length of payload that follows
//!   [len bytes] payload
//!
//! Payload layouts by MsgType:
//!
//!   HandshakeInit : 32 bytes -> provider_commitment (H(rP))
//!   HandshakeAck  : 32 bytes channel_id || 20 bytes client_address
//!                   (this is how the server learns the session identity —
//!                   adjust if the client is meant to send this elsewhere)
//!   TicketRequest : ABI-encoded Ticket (288 bytes, 9 static 32-byte slots)
//!                   || u32_le sig_len || sig_len bytes signature
//!                   || u32_le payload_len || payload_len bytes prompt_payload
//!   ComputeResp   : 1 byte is_finished (0/1) || remaining bytes = token payload

use alloy_primitives::{keccak256, Address, B256};
use anyhow::{anyhow, bail, Context};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::types::{IncomingTicketFrame, MsgType, SessionConfig, SPMP_MAGIC};

const TICKET_ABI_LEN: usize = 9 * 32; // Ticket has 9 static (non-dynamic) fields
const CHANNEL_ID_LEN: usize = 32;
const ADDRESS_LEN: usize = 20;

pub struct TCPServer {
    listen_addr: String,
    provider_seed: B256,       // rP (kept secret in RAM only)
    provider_commitment: B256, // H(rP) = keccak256(rP)
}

impl TCPServer {
    /// Generates a fresh CSPRNG seed rP and derives the public commitment
    /// H(rP) = keccak256(rP).
    pub fn new(addr: &str) -> Self {
        let mut seed_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed_bytes);
        let provider_seed = B256::from(seed_bytes);
        let provider_commitment = keccak256(provider_seed.as_slice());

        Self {
            listen_addr: addr.to_string(),
            provider_seed,
            provider_commitment,
        }
    }

    pub fn provider_commitment(&self) -> B256 {
        self.provider_commitment
    }

    /// Binds the listener and accepts connections forever, spawning a
    /// task per client.
    pub async fn start(&self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&self.listen_addr)
            .await
            .with_context(|| format!("failed to bind {}", self.listen_addr))?;

        info!(addr = %self.listen_addr, "TCP server listening");

        loop {
            let (mut stream, peer) = listener.accept().await?;
            info!(%peer, "accepted connection");

            let provider_seed = self.provider_seed;
            let provider_commitment = self.provider_commitment;

            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_client(&mut stream, provider_seed, provider_commitment).await
                {
                    warn!(%peer, error = %e, "connection closed with error");
                }
            });
        }
    }

    /// Per-connection driver: handshake -> read ticket requests in a loop
    /// until the client disconnects. Handing decoded frames off to Dev 2's
    /// verifier / Dev 3's worker is the daemon's orchestration layer, not
    /// this module's job — this just demonstrates the intended call shape.
    async fn handle_client(
        stream: &mut TcpStream,
        provider_seed: B256,
        provider_commitment: B256,
    ) -> anyhow::Result<()> {
        let mut session = Self::handle_handshake_inner(stream, provider_seed, provider_commitment)
            .await
            .context("handshake failed")?;

        loop {
            let frame_buf = match Self::read_frame(stream).await? {
                Some(buf) => buf,
                None => return Ok(()), // clean EOF
            };

            match Self::decode_ticket_frame(&frame_buf) {
                Ok(incoming) => {
                    info!(
                        nonce = incoming.ticket.nonce,
                        expected_next = session.last_nonce + 1,
                        "decoded ticket request"
                    );
                    // Watermark bump is provisional here — Dev 2's verifier
                    // is the actual source of truth on whether this nonce
                    // was valid; this just keeps `session` demonstrably wired.
                    session.last_nonce = incoming.ticket.nonce;
                }
                Err(e) => {
                    warn!(error = %e, "failed to decode ticket frame");
                }
            }
        }
    }

    /// Sends `MsgType::HandshakeInit` containing `provider_commitment` and
    /// awaits `MsgType::HandshakeAck` from the client, returning the
    /// resulting `SessionConfig`.
    pub async fn handle_handshake(&self, stream: &mut TcpStream) -> anyhow::Result<SessionConfig> {
        Self::handle_handshake_inner(stream, self.provider_seed, self.provider_commitment).await
    }

    async fn handle_handshake_inner(
        stream: &mut TcpStream,
        provider_seed: B256,
        provider_commitment: B256,
    ) -> anyhow::Result<SessionConfig> {
        let init_frame = Self::build_frame(MsgType::HandshakeInit, provider_commitment.as_slice());
        stream
            .write_all(&init_frame)
            .await
            .context("failed to send HandshakeInit")?;

        let ack_buf = Self::read_frame(stream)
            .await?
            .ok_or_else(|| anyhow!("connection closed before HandshakeAck"))?;

        let (msg_type, payload) = Self::split_frame(&ack_buf)?;
        if msg_type != MsgType::HandshakeAck {
            bail!("expected HandshakeAck, got {msg_type:?}");
        }
        if payload.len() != CHANNEL_ID_LEN + ADDRESS_LEN {
            bail!(
                "malformed HandshakeAck payload: expected {} bytes, got {}",
                CHANNEL_ID_LEN + ADDRESS_LEN,
                payload.len()
            );
        }

        let channel_id = B256::from_slice(&payload[..CHANNEL_ID_LEN]);
        let client_address = Address::from_slice(&payload[CHANNEL_ID_LEN..]);

        info!(%client_address, "handshake complete");

        Ok(SessionConfig {
            channel_id,
            client_address,
            provider_seed,
            provider_commitment,
            last_nonce: 0,
        })
    }

    /// Parses a raw frame buffer (as returned by `read_frame`, i.e.
    /// magic || type || payload) into a `Ticket`, its signature, and the
    /// raw prompt payload bytes.
    pub fn decode_ticket_frame(buf: &[u8]) -> anyhow::Result<IncomingTicketFrame> {
        let (msg_type, payload) = Self::split_frame(buf)?;
        if msg_type != MsgType::TicketRequest {
            bail!("expected TicketRequest, got {msg_type:?}");
        }

        if payload.len() < TICKET_ABI_LEN + 4 {
            bail!("ticket frame payload too short for Ticket + sig_len");
        }

        let (ticket_bytes, rest) = payload.split_at(TICKET_ABI_LEN);
        let ticket = crate::types::decode_ticket(ticket_bytes)
            .context("failed to ABI-decode Ticket from frame")?;

        let (sig_len_bytes, rest) = rest.split_at(4);
        let sig_len = u32::from_le_bytes(sig_len_bytes.try_into().unwrap()) as usize;
        if rest.len() < sig_len + 4 {
            bail!("ticket frame truncated: missing signature or payload_len");
        }
        let (sig_bytes, rest) = rest.split_at(sig_len);
        let signature = sig_bytes.to_vec();

        let (payload_len_bytes, rest) = rest.split_at(4);
        let payload_len = u32::from_le_bytes(payload_len_bytes.try_into().unwrap()) as usize;
        if rest.len() < payload_len {
            bail!(
                "ticket frame declared payload_len={} but only {} bytes remain",
                payload_len,
                rest.len()
            );
        }
        let prompt_payload = rest[..payload_len].to_vec();

        Ok(IncomingTicketFrame {
            ticket,
            signature,
            prompt_payload,
        })
    }

    /// Packages a compute token chunk into a standard `MsgType::ComputeResp`
    /// frame: [magic][type][len][is_finished byte][token bytes].
    pub fn encode_response_frame(token_chunk: &str, is_finished: bool) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1 + token_chunk.len());
        payload.push(is_finished as u8);
        payload.extend_from_slice(token_chunk.as_bytes());

        Self::build_frame(MsgType::ComputeResp, &payload)
    }

    // -------------------------------------------------------------
    // Low-level frame helpers
    // -------------------------------------------------------------

    /// Builds a full wire frame: magic || type || u32_le(len) || payload.
    fn build_frame(msg_type: MsgType, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 4 + payload.len());
        out.extend_from_slice(&SPMP_MAGIC.to_be_bytes()); // spells "SPMP"
        out.push(msg_type as u8);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Splits a frame body (magic || type || payload, as returned by
    /// `read_frame`) into `(msg_type, payload)`, validating magic.
    fn split_frame(buf: &[u8]) -> anyhow::Result<(MsgType, &[u8])> {
        if buf.len() < 5 {
            bail!("frame too short to contain magic + type");
        }
        let (magic_bytes, rest) = buf.split_at(4);
        let magic = u32::from_be_bytes(magic_bytes.try_into().unwrap());
        if magic != SPMP_MAGIC {
            bail!("invalid SPMP_MAGIC: 0x{magic:08x}");
        }
        let msg_type = MsgType::from_u8(rest[0])?;
        Ok((msg_type, &rest[1..]))
    }

    /// Reads one length-delimited frame off the stream and returns it as
    /// `magic || type || payload` (the outer length prefix is consumed
    /// but not included), or `None` on clean EOF.
    async fn read_frame(stream: &mut TcpStream) -> anyhow::Result<Option<Vec<u8>>> {
        let mut header = [0u8; 9]; // 4 magic + 1 type + 4 len
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }

        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        if magic != SPMP_MAGIC {
            bail!("invalid SPMP_MAGIC in frame header: 0x{magic:08x}");
        }
        let msg_type_byte = header[4];
        let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;

        let mut payload = vec![0u8; len];
        if len > 0 {
            stream
                .read_exact(&mut payload)
                .await
                .context("failed reading frame payload")?;
        }

        let mut out = Vec::with_capacity(4 + 1 + payload.len());
        out.extend_from_slice(&header[0..4]);
        out.push(msg_type_byte);
        out.extend_from_slice(&payload);
        Ok(Some(out))
    }
}

// Note: `MsgType::from_u8` and `crate::types::decode_ticket` are assumed
// to live in types.rs alongside the enum/struct defs you pasted — add
// them there if they're not already present:
//
//   impl MsgType {
//       pub fn from_u8(byte: u8) -> anyhow::Result<Self> {
//           match byte {
//               0x01 => Ok(MsgType::HandshakeInit),
//               0x02 => Ok(MsgType::HandshakeAck),
//               0x03 => Ok(MsgType::TicketRequest),
//               0x04 => Ok(MsgType::ComputeResp),
//               0x05 => Ok(MsgType::WinNotify),
//               0xFF => Ok(MsgType::ErrorHalt),
//               other => Err(anyhow::anyhow!("unknown MsgType byte: 0x{other:02x}")),
//           }
//       }
//   }
//
//   pub fn decode_ticket(buf: &[u8]) -> anyhow::Result<Ticket> {
//       use alloy_sol_types::SolValue;
//       Ticket::abi_decode(buf, true).map_err(|e| anyhow::anyhow!("bad Ticket abi: {e}"))
//   }

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener as TestListener;

    #[tokio::test]
    async fn handshake_commitment_matches_keccak_of_seed_and_captures_session() {
        let listener = TestListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = TCPServer::new(&addr.to_string());
        let expected_commitment = server.provider_commitment();

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            server.handle_handshake(&mut stream).await.unwrap()
        });

        let mut client = TcpStream::connect(addr).await.unwrap();

        let mut header = [0u8; 9];
        client.read_exact(&mut header).await.unwrap();
        let magic = u32::from_be_bytes(header[0..4].try_into().unwrap());
        assert_eq!(magic, SPMP_MAGIC);
        assert_eq!(header[4], MsgType::HandshakeInit as u8);
        let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
        assert_eq!(len, 32);

        let mut commitment_buf = vec![0u8; len];
        client.read_exact(&mut commitment_buf).await.unwrap();
        assert_eq!(commitment_buf.as_slice(), expected_commitment.as_slice());

        let fake_channel_id = [7u8; 32];
        let fake_client_addr = [9u8; 20];
        let mut ack_payload = Vec::with_capacity(52);
        ack_payload.extend_from_slice(&fake_channel_id);
        ack_payload.extend_from_slice(&fake_client_addr);

        let mut ack_frame = Vec::new();
        ack_frame.extend_from_slice(&SPMP_MAGIC.to_be_bytes());
        ack_frame.push(MsgType::HandshakeAck as u8);
        ack_frame.extend_from_slice(&(ack_payload.len() as u32).to_le_bytes());
        ack_frame.extend_from_slice(&ack_payload);

        client.write_all(&ack_frame).await.unwrap();

        let session = server_task.await.unwrap();
        assert_eq!(session.channel_id.as_slice(), &fake_channel_id);
        assert_eq!(session.client_address.as_slice(), &fake_client_addr);
        assert_eq!(session.last_nonce, 0);
    }

    #[test]
    fn encode_response_frame_roundtrips_header() {
        let frame = TCPServer::encode_response_frame("hello", false);
        let magic = u32::from_be_bytes(frame[0..4].try_into().unwrap());
        assert_eq!(magic, SPMP_MAGIC);
        assert_eq!(frame[4], MsgType::ComputeResp as u8);
        let len = u32::from_le_bytes(frame[5..9].try_into().unwrap()) as usize;
        assert_eq!(len, 1 + "hello".len());
        assert_eq!(frame[9], 0u8);
        assert_eq!(&frame[10..], b"hello");
    }
}