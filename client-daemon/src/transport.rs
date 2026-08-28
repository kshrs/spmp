use alloy_primitives::{Address, B256};
use alloy_sol_types::SolValue; // <-- Added this import to bring abi_encode() into scope
use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex as AsyncMutex;

use crate::types::{MsgType, SignedTicket, Ticket, SPMP_MAGIC};

pub struct TCPClient {
    stream: AsyncMutex<Option<TcpStream>>,
    provider_addr: String,
    provider_commitment: std::sync::Mutex<B256>,
}

impl TCPClient {
    pub fn new(provider_addr: String) -> Self {
        Self {
            stream: AsyncMutex::new(None),
            provider_addr,
            provider_commitment: std::sync::Mutex::new(B256::ZERO),
        }
    }

    pub fn get_provider_commitment(&self) -> B256 {
        *self.provider_commitment.lock().unwrap()
    }

    pub fn encode_ticket_frame(ticket: &SignedTicket, payload: &[u8]) -> Vec<u8> {
        // Construct the Alloy Solidity struct directly
        let ticket_sol = Ticket {
            channelId: ticket.payload.channel_id,
            provider: ticket.payload.provider,
            nonce: ticket.payload.nonce,
            // Face value in Ticket is uint128, mapping to Rust u128
            faceValue: ticket.payload.face_value.try_into().unwrap_or_default(),
            winProbNumerator: ticket.payload.win_prob_numerator,
            winProbDenominator: ticket.payload.win_prob_denominator,
            expiry: ticket.payload.expiry,
            clientSeed: ticket.payload.client_seed,
            providerCommitment: ticket.payload.provider_commitment,
        };

        // Leverage Alloy's built-in abi_encode() (Exactly 288 bytes)
        let ticket_bytes = ticket_sol.abi_encode();

        let mut frame_payload = Vec::new();
        frame_payload.extend_from_slice(&ticket_bytes);

        // [u32_le sig_len] || [sig_bytes]
        let sig_len = ticket.signature.len() as u32;
        frame_payload.extend_from_slice(&sig_len.to_le_bytes());
        frame_payload.extend_from_slice(&ticket.signature);

        // [u32_le payload_len] || [prompt_bytes]
        let payload_len = payload.len() as u32;
        frame_payload.extend_from_slice(&payload_len.to_le_bytes());
        frame_payload.extend_from_slice(payload);

        // Compute total payload length for the 9-byte standard header
        let total_payload_len = frame_payload.len() as u32;

        let mut buf = Vec::new();
        // 9-Byte Header: [Magic 4B BE] | [MsgType 1B] | [PayloadLen 4B LE]
        buf.extend_from_slice(&SPMP_MAGIC.to_be_bytes()); 
        buf.push(MsgType::TicketRequest as u8);
        buf.extend_from_slice(&total_payload_len.to_le_bytes());
        
        // Append the encoded payload
        buf.extend_from_slice(&frame_payload);

        buf
    }

    pub fn decode_response_frame(buf: &[u8]) -> Result<(String, bool)> {
        // Minimum size: 9-Byte Header + [IsDone 1B]
        if buf.len() < 10 {
            return Err(anyhow!("Response buffer too small to decode"));
        }

        let magic = u32::from_be_bytes(buf[0..4].try_into()?);
        if magic != SPMP_MAGIC {
            return Err(anyhow!("Invalid magic bytes"));
        }

        if buf[4] != MsgType::ComputeResp as u8 {
            return Err(anyhow!("Unexpected message type received: expected ComputeResp"));
        }

        let payload_len = u32::from_le_bytes(buf[5..9].try_into()?) as usize;
        
        if buf.len() < 9 + payload_len {
            return Err(anyhow!("Incomplete payload received"));
        }

        let payload_buf = &buf[9..9 + payload_len];
        if payload_buf.is_empty() {
            return Err(anyhow!("Compute response payload is empty"));
        }

        let is_done = payload_buf[0] != 0;
        let text = String::from_utf8(payload_buf[1..].to_vec())?;
        
        Ok((text, is_done))
    }

    pub async fn connect(&self) -> Result<()> {
        let stream = TcpStream::connect(&self.provider_addr).await?;
        let mut guard = self.stream.lock().await;
        *guard = Some(stream);
        Ok(())
    }

    pub async fn perform_handshake(&self, channel_id: B256, client_address: Address) -> Result<()> {
        let mut guard = self.stream.lock().await;
        if let Some(stream) = guard.as_mut() {
            
            // 1. Read Provider's HandshakeInit: [9-Byte Header] + [32B Commitment]
            let mut header = [0u8; 9];
            stream.read_exact(&mut header).await?;

            let magic = u32::from_be_bytes(header[0..4].try_into()?);
            if magic != SPMP_MAGIC {
                return Err(anyhow!("Handshake failed: Invalid magic bytes"));
            }

            if header[4] != MsgType::HandshakeInit as u8 {
                return Err(anyhow!("Expected HandshakeInit (0x01), got 0x{:02x}", header[4]));
            }

            let mut commitment_buf = [0u8; 32];
            stream.read_exact(&mut commitment_buf).await?;

            {
                let mut pc_guard = self.provider_commitment.lock().unwrap();
                *pc_guard = B256::from_slice(&commitment_buf);
            }

            // 2. Client responds with HandshakeAck
            // Payload: [32B channel_id || 20B client_address]
            let mut ack_payload = Vec::new();
            ack_payload.extend_from_slice(channel_id.as_slice());
            ack_payload.extend_from_slice(client_address.as_slice());

            let mut ack_frame = Vec::new();
            ack_frame.extend_from_slice(&SPMP_MAGIC.to_be_bytes()); // 4B BE
            ack_frame.push(MsgType::HandshakeAck as u8); // 1B
            ack_frame.extend_from_slice(&(ack_payload.len() as u32).to_le_bytes()); // 4B LE
            ack_frame.extend_from_slice(&ack_payload);

            stream.write_all(&ack_frame).await?;

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

            // Read the 9-byte response header
            let mut header = [0u8; 9];
            stream.read_exact(&mut header).await?;
            
            let magic = u32::from_be_bytes(header[0..4].try_into()?);
            if magic != SPMP_MAGIC {
                return Err(anyhow!("Response invalid: Invalid magic bytes"));
            }

            if header[4] != MsgType::ComputeResp as u8 {
                return Err(anyhow!("Unexpected response message type"));
            }

            let len = u32::from_le_bytes(header[5..9].try_into()?) as usize;
            
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).await?;
            
            if payload.is_empty() {
                return Err(anyhow!("Empty compute response payload"));
            }

            let is_done = payload[0] != 0;
            let text = String::from_utf8(payload[1..].to_vec())?;
            
            Ok((text, is_done))
        } else {
            Err(anyhow!("Cannot send frame: TCP stream not connected"))
        }
    }
}

// TODO: Uncomment once orchestrator module is merged (PR #4)
// #[async_trait::async_trait]
// impl crate::orchestrator::TransportTrait for TCPClient {
//     fn get_provider_commitment(&self) -> B256 {
//         self.get_provider_commitment()
//     }
// 
//     async fn send_ticket_and_prompt(
//         &self,
//         ticket: &crate::types::SignedTicket,
//         prompt_chunk: &str,
//     ) -> anyhow::Result<(String, bool)> {
//         self.send_ticket_and_prompt(ticket, prompt_chunk).await
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TicketPayload;
    use alloy_primitives::{address, b256, U256};

    #[test]
    fn test_encode_and_decode_frames() {
        let ticket = SignedTicket {
            payload: TicketPayload {
                channel_id: b256!("1111111111111111111111111111111111111111111111111111111111111111"),
                provider: address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
                nonce: 42,
                face_value: U256::from(50_000),
                win_prob_numerator: 1,
                win_prob_denominator: 50,
                expiry: 1700000000,
                client_seed: b256!("2222222222222222222222222222222222222222222222222222222222222222"),
                provider_commitment: b256!("3333333333333333333333333333333333333333333333333333333333333333"),
            },
            signature: vec![0u8; 65],
        };

        let encoded = TCPClient::encode_ticket_frame(&ticket, b"Hello SPMP");
        // Verify 9-byte Header values
        assert_eq!(&encoded[0..4], &SPMP_MAGIC.to_be_bytes());
        assert_eq!(encoded[4], MsgType::TicketRequest as u8);

        // Test decode response frame
        let mut mock_resp = Vec::new();
        mock_resp.extend_from_slice(&SPMP_MAGIC.to_be_bytes());
        mock_resp.push(MsgType::ComputeResp as u8);
        
        let text_bytes = b"TokenOutput";
        let payload_len: u32 = 1 + text_bytes.len() as u32; 
        mock_resp.extend_from_slice(&payload_len.to_le_bytes()); // 4B LE Length
        
        mock_resp.push(1u8); // IsDone = true
        mock_resp.extend_from_slice(text_bytes);

        let (decoded_text, is_done) = TCPClient::decode_response_frame(&mock_resp).unwrap();
        assert_eq!(decoded_text, "TokenOutput");
        assert!(is_done);
    }
}