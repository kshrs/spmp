// Developer 4 Module: Wire Protocol & TCP Client
use alloy_primitives::B256;
use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::types::{MsgType, SignedTicket, SPMP_MAGIC};

pub struct TCPClient {
    stream: Mutex<Option<TcpStream>>,
    provider_addr: String,
    provider_commitment: Mutex<B256>,
}

impl TCPClient {
    pub fn new(provider_addr: String) -> Self {
        Self {
            stream: Mutex::new(None),
            provider_addr,
            provider_commitment: Mutex::new(B256::ZERO),
        }
    }

    pub fn encode_ticket_frame(ticket: &SignedTicket, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();

        // [Magic 4B] | [MsgType 1B] | [Flags 1B] | [Reserved 2B]
        buf.extend_from_slice(&SPMP_MAGIC.to_be_bytes()); 
        buf.push(MsgType::TicketRequest as u8); // Uses 0x03 from types.rs
        buf.push(0); // Flags
        buf.extend_from_slice(&[0u8; 2]); // Reserved

        // [Nonce 8B] | [ChannelID 32B] | [ClientSeed 32B] | [ProviderCommitment 32B]
        buf.extend_from_slice(&ticket.payload.nonce.to_be_bytes());
        buf.extend_from_slice(ticket.payload.channel_id.as_slice());
        buf.extend_from_slice(ticket.payload.client_seed.as_slice());
        buf.extend_from_slice(ticket.payload.provider_commitment.as_slice());

        // [FaceValue 16B] - Extract lower 16 bytes from U256
        let face_value_bytes: [u8; 32] = ticket.payload.face_value.to_be_bytes();
        buf.extend_from_slice(&face_value_bytes[16..32]);

        // [Num 4B] | [Denom 4B] | [Expiry 8B]
        buf.extend_from_slice(&ticket.payload.win_prob_numerator.to_be_bytes());
        buf.extend_from_slice(&ticket.payload.win_prob_denominator.to_be_bytes());
        buf.extend_from_slice(&ticket.payload.expiry.to_be_bytes());

        // [Sig R 32B] | [Sig S 32B] | [Sig V 1B]
        if ticket.signature.len() == 65 {
            buf.extend_from_slice(&ticket.signature);
        } else {
            buf.extend_from_slice(&[0u8; 65]);
        }

        // [PayloadLen 4B] | [PayloadData NB]
        let payload_len = payload.len() as u32;
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(payload);

        buf
    }

    pub fn decode_response_frame(buf: &[u8]) -> Result<(String, bool)> {
        // [MsgType 1B] [IsDone 1B] [PayloadLen 4B] [Payload NB]
        if buf.len() < 6 {
            return Err(anyhow!("Response buffer too small to decode"));
        }

        if buf[0] != MsgType::ComputeResp as u8 {
            return Err(anyhow!("Unexpected message type received: expected ComputeResp"));
        }

        let is_done = buf[1] != 0;
        let len_bytes: [u8; 4] = buf[2..6].try_into()?;
        let payload_len = u32::from_be_bytes(len_bytes) as usize;

        if buf.len() < 6 + payload_len {
            return Err(anyhow!("Incomplete payload received"));
        }

        let text = String::from_utf8(buf[6..6 + payload_len].to_vec())?;
        Ok((text, is_done))
    }

    pub async fn connect(&self) -> Result<()> {
        let stream = TcpStream::connect(&self.provider_addr).await?;
        let mut guard = self.stream.lock().await;
        *guard = Some(stream);
        Ok(())
    }

    pub async fn perform_handshake(&self, channel_id: B256) -> Result<()> {
        let mut guard = self.stream.lock().await;
        if let Some(stream) = guard.as_mut() {
            
            let mut buf = Vec::new();
            buf.extend_from_slice(&SPMP_MAGIC.to_be_bytes());
            buf.push(MsgType::HandshakeInit as u8); // Uses 0x01 from types.rs
            buf.extend_from_slice(channel_id.as_slice());

            stream.write_all(&buf).await?;

            // Await the HandshakeAck (assuming it sends back the 32B Provider Commitment)
            let mut commitment_buf = [0u8; 32];
            stream.read_exact(&mut commitment_buf).await?;
            
            let mut pc_guard = self.provider_commitment.lock().await;
            *pc_guard = B256::from_slice(&commitment_buf);

            Ok(())
        } else {
            Err(anyhow!("Cannot handshake: TCP stream not connected"))
        }
    }

    pub async fn send_ticket_and_prompt(
        &self,
        ticket: &SignedTicket,
        prompt: &str,
    ) -> Result<(String, bool)> {
        let frame = Self::encode_ticket_frame(ticket, prompt.as_bytes());
        
        let mut guard = self.stream.lock().await;
        if let Some(stream) = guard.as_mut() {
            stream.write_all(&frame).await?;

            // Expecting [MsgType 1B] [IsDone 1B] [Len 4B]
            let mut header = [0u8; 6];
            stream.read_exact(&mut header).await?;
            
            if header[0] != MsgType::ComputeResp as u8 {
                return Err(anyhow!("Unexpected response message type"));
            }

            let is_done = header[1] != 0;
            let len = u32::from_be_bytes(header[2..6].try_into()?) as usize;
            
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).await?;
            
            let text = String::from_utf8(payload)?;
            Ok((text, is_done))
        } else {
            Err(anyhow!("Cannot send frame: TCP stream not connected"))
        }
    }
}