//! src/transport.rs
//!
//! Dev 1 + Dev 2: Inbound TCP Server, Wire Framing & Fast Gatekeeper Integration.
//!
//! Owns the persistent listener on `0.0.0.0:9000`, generates the secret
//! provider seed rP, negotiates the H(rP) commitment handshake with each
//! connecting client, captures the resulting `SessionConfig`, and
//! routes incoming tickets directly through Developer 2's sub-millisecond
//! in-memory `TicketVerifier`.
//!
//! Wire format:
//!   [4 bytes]  magic    = SPMP_MAGIC, big-endian ("SPMP")
//!   [1 byte ]  msg_type = MsgType as u8
//!   [4 bytes]  len      = u32 little-endian, length of payload that follows
//!   [len bytes] payload

use alloy_primitives::{keccak256, Address, B256};
use anyhow::{anyhow, bail, Context};
use futures::StreamExt;
use rand::RngCore;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{info, warn};

use crate::settlement::ClaimTask;
use crate::types::{
    GatekeeperDecision, IncomingTicketFrame, MsgType, SessionConfig, SPMP_MAGIC,
};
use crate::verifier::TicketVerifier;
use crate::worker::LLMBackend;

const TICKET_ABI_LEN: usize = 9 * 32; // Ticket has 9 static (non-dynamic) fields
const CHANNEL_ID_LEN: usize = 32;
const ADDRESS_LEN: usize = 20;

const MAX_FRAME_SIZE: usize = 64 * 1024; // 64KB max payload size
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5); // 5s budget for init + ack

pub struct TCPServer {
    listen_addr: String,
    provider_address: Address,
    contract_address: Address,
    chain_id: u64,
    provider_seed: B256,       // rP (kept secret in RAM only)
    provider_commitment: B256, // H(rP) = keccak256(rP)
    settlement_tx: Option<mpsc::Sender<ClaimTask>>,
    backend: Option<Arc<dyn LLMBackend>>,
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
            provider_address: Address::ZERO,
            contract_address: Address::ZERO,
            chain_id: 31337,
            provider_seed,
            provider_commitment,
            settlement_tx: None,
            backend: None,
        }
    }

    pub fn with_chain_config(
        mut self,
        provider_address: Address,
        contract_address: Address,
        chain_id: u64,
    ) -> Self {
        self.provider_address = provider_address;
        self.contract_address = contract_address;
        self.chain_id = chain_id;
        self
    }

    pub fn with_settlement(mut self, tx: mpsc::Sender<ClaimTask>) -> Self {
        self.settlement_tx = Some(tx);
        self
    }

    pub fn with_backend(mut self, backend: Arc<dyn LLMBackend>) -> Self {
        self.backend = Some(backend);
        self
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

            let provider_address = self.provider_address;
            let contract_address = self.contract_address;
            let chain_id = self.chain_id;
            let provider_seed = self.provider_seed;
            let provider_commitment = self.provider_commitment;
            let settlement_tx = self.settlement_tx.clone();
            let backend = self.backend.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(
                    &mut stream,
                    provider_address,
                    contract_address,
                    chain_id,
                    provider_seed,
                    provider_commitment,
                    settlement_tx,
                    backend,
                )
                .await
                {
                    warn!(%peer, error = %e, "connection closed with error");
                }
            });
        }
    }

    /// Per-connection driver: handshake -> evaluate ticket requests in a loop
    /// using Developer 2's Fast Gatekeeper engine until the client disconnects or is rejected.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_client(
        stream: &mut TcpStream,
        provider_address: Address,
        contract_address: Address,
        chain_id: u64,
        provider_seed: B256,
        provider_commitment: B256,
        settlement_tx: Option<mpsc::Sender<ClaimTask>>,
        backend: Option<Arc<dyn LLMBackend>>,
    ) -> anyhow::Result<()> {
        let mut session = Self::handle_handshake_inner(stream, provider_seed, provider_commitment)
            .await
            .context("handshake failed")?;

        // Instantiate Developer 2's Fast Gatekeeper verifier with session secrets
        let mut verifier = TicketVerifier::new(
            provider_address,
            contract_address,
            chain_id,
            session.provider_seed,
        );

        loop {
            let frame_buf = match Self::read_frame(stream).await? {
                Some(buf) => buf,
                None => return Ok(()), // clean EOF
            };

            let incoming = match Self::decode_ticket_frame(&frame_buf) {
                Ok(frame) => frame,
                Err(e) => {
                    warn!(error = %e, "failed to decode ticket frame");
                    let err_frame = Self::build_frame(MsgType::ErrorHalt, b"malformed ticket frame");
                    let _ = stream.write_all(&err_frame).await;
                    bail!("malformed ticket frame: {e}");
                }
            };

            // Dev 2 Gatekeeper sub-millisecond zero-copy evaluation
            let decision = verifier.evaluate_and_gate(
                &incoming.ticket,
                &incoming.signature,
                session.client_address,
                session.last_nonce,
            );

            match decision {
                GatekeeperDecision::ServeLosing => {
                    session.last_nonce = incoming.ticket.nonce;
                    Self::process_compute_payload(stream, &incoming.prompt_payload, backend.as_deref())
                        .await?;
                }
                GatekeeperDecision::ClaimAndRotateWinning => {
                    session.last_nonce = incoming.ticket.nonce;
                    info!(
                        nonce = incoming.ticket.nonce,
                        face_value = incoming.ticket.faceValue,
                        "WINNING TICKET! Enqueuing settlement task and rotating provider seed."
                    );

                    // 1. Enqueue task for Developer 4's on-chain settlement worker
                    if let Some(ref tx) = settlement_tx {
                        if let Err(e) = tx
                            .send(ClaimTask {
                                ticket: incoming.ticket.clone(),
                                signature: incoming.signature.clone(),
                                provider_seed: verifier.provider_seed,
                            })
                            .await
                        {
                            warn!(error = %e, "failed to dispatch winning ticket to settlement queue");
                        }
                    }

                    // 2. Rotate provider seed per protocol spec
                    let mut new_seed_bytes = [0u8; 32];
                    rand::thread_rng().fill_bytes(&mut new_seed_bytes);
                    let new_seed = B256::from(new_seed_bytes);
                    verifier.rotate_seed(new_seed);
                    session.provider_seed = verifier.provider_seed;
                    session.provider_commitment = verifier.provider_commitment;

                    // 3. Serve compute chunk
                    Self::process_compute_payload(stream, &incoming.prompt_payload, backend.as_deref())
                        .await?;
                }
                GatekeeperDecision::Reject(verdict) => {
                    warn!(
                        ?verdict,
                        nonce = incoming.ticket.nonce,
                        "Gatekeeper rejected ticket - terminating stream"
                    );
                    let err_msg = format!("REJECTED: {verdict:?}");
                    let err_frame = Self::build_frame(MsgType::ErrorHalt, err_msg.as_bytes());
                    let _ = stream.write_all(&err_frame).await;
                    bail!("ticket verification rejected: {verdict:?}");
                }
            }
        }
    }

    /// Serves LLM tokens or returns a chunk acknowledgment to the client.
    async fn process_compute_payload(
        stream: &mut TcpStream,
        prompt_payload: &[u8],
        backend: Option<&(dyn LLMBackend + 'static)>,
    ) -> anyhow::Result<()> {
        if let Some(be) = backend {
            let prompt = String::from_utf8_lossy(prompt_payload);
            if let Ok(mut token_stream) = be.generate_token_stream(&prompt).await {
                while let Some(token) = token_stream.next().await {
                    let resp = Self::encode_response_frame(&token, false);
                    stream.write_all(&resp).await?;
                }
                let end_resp = Self::encode_response_frame("", true);
                stream.write_all(&end_resp).await?;
                return Ok(());
            }
        }

        // Default fallback acknowledgment
        let resp = Self::encode_response_frame("ACK", true);
        stream.write_all(&resp).await?;
        Ok(())
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

        timeout(HANDSHAKE_TIMEOUT, stream.write_all(&init_frame))
            .await
            .context("handshake write timed out")?
            .context("failed to send HandshakeInit")?;

        let ack_buf = timeout(HANDSHAKE_TIMEOUT, Self::read_frame(stream))
            .await
            .context("handshake read timed out")?
            .context("failed to read HandshakeAck")?
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

    /// Builds a full wire frame: magic || type || u32_le(len) || payload.
    pub fn build_frame(msg_type: MsgType, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 1 + 4 + payload.len());
        out.extend_from_slice(&SPMP_MAGIC.to_be_bytes()); // spells "SPMP"
        out.push(msg_type as u8);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Splits a frame body (magic || type || payload, as returned by
    /// `read_frame`) into `(msg_type, payload)`, validating magic.
    pub fn split_frame(buf: &[u8]) -> anyhow::Result<(MsgType, &[u8])> {
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
    pub async fn read_frame(stream: &mut TcpStream) -> anyhow::Result<Option<Vec<u8>>> {
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

        if len > MAX_FRAME_SIZE {
            bail!(
                "frame payload length ({} bytes) exceeds maximum allowed ({} bytes)",
                len,
                MAX_FRAME_SIZE
            );
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Ticket;
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use alloy_sol_types::{SolStruct, SolValue};
    use std::time::{SystemTime, UNIX_EPOCH};
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

    #[tokio::test]
    async fn test_tcp_gatekeeper_integration_serve_losing_and_claim_winning() {
        let listener = TestListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let provider_addr = Address::from([0x11; 20]);
        let contract_addr = Address::from([0x22; 20]);
        let chain_id = 31337u64;

        let (settlement_tx, mut settlement_rx) = mpsc::channel(10);
        let server = TCPServer::new(&addr.to_string())
            .with_chain_config(provider_addr, contract_addr, chain_id)
            .with_settlement(settlement_tx);

        let provider_seed = server.provider_seed;
        let provider_commitment = server.provider_commitment;

        // Spawn server loop
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            TCPServer::handle_client(
                &mut stream,
                provider_addr,
                contract_addr,
                chain_id,
                provider_seed,
                provider_commitment,
                server.settlement_tx,
                None,
            )
            .await
        });

        // Setup client
        let client_signer = PrivateKeySigner::random();
        let client_addr = client_signer.address();
        let channel_id = keccak256([client_addr.as_slice(), provider_addr.as_slice()].concat());

        let mut client = TcpStream::connect(addr).await.unwrap();

        // 1. Handshake Init
        let mut header = [0u8; 9];
        client.read_exact(&mut header).await.unwrap();
        let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
        let mut commitment_buf = vec![0u8; len];
        client.read_exact(&mut commitment_buf).await.unwrap();
        let received_commitment = B256::from_slice(&commitment_buf);

        // 2. Send Handshake Ack
        let mut ack_payload = Vec::with_capacity(52);
        ack_payload.extend_from_slice(channel_id.as_slice());
        ack_payload.extend_from_slice(client_addr.as_slice());
        let ack_frame = TCPServer::build_frame(MsgType::HandshakeAck, &ack_payload);
        client.write_all(&ack_frame).await.unwrap();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // 3. Send Ticket 1: Valid Losing Ticket (num=0, denom=1000)
        let losing_ticket = Ticket {
            channelId: channel_id,
            provider: provider_addr,
            nonce: 1,
            faceValue: 50_000,
            winProbNumerator: 0,
            winProbDenominator: 1000,
            expiry: now + 3600,
            clientSeed: B256::from([0x12; 32]),
            providerCommitment: received_commitment,
        };

        let verifier = TicketVerifier::new(provider_addr, contract_addr, chain_id, provider_seed);
        let digest1 = losing_ticket.eip712_signing_hash(&verifier.domain);
        let sig1 = client_signer.sign_hash(&digest1).await.unwrap();

        let mut ticket1_payload = Vec::new();
        ticket1_payload.extend_from_slice(&losing_ticket.abi_encode());
        ticket1_payload.extend_from_slice(&(sig1.as_bytes().len() as u32).to_le_bytes());
        ticket1_payload.extend_from_slice(sig1.as_bytes().as_ref());
        let prompt_bytes = b"Hello SPMP";
        ticket1_payload.extend_from_slice(&(prompt_bytes.len() as u32).to_le_bytes());
        ticket1_payload.extend_from_slice(prompt_bytes);

        let req_frame1 = TCPServer::build_frame(MsgType::TicketRequest, &ticket1_payload);
        client.write_all(&req_frame1).await.unwrap();

        // Read ComputeResp
        let mut resp_header1 = [0u8; 9];
        client.read_exact(&mut resp_header1).await.unwrap();
        assert_eq!(resp_header1[4], MsgType::ComputeResp as u8);
        let resp_len1 = u32::from_le_bytes(resp_header1[5..9].try_into().unwrap()) as usize;
        let mut resp_body1 = vec![0u8; resp_len1];
        client.read_exact(&mut resp_body1).await.unwrap();
        assert_eq!(resp_body1[0], 1); // is_finished = true
        assert_eq!(&resp_body1[1..], b"ACK");

        // 4. Send Ticket 2: Valid Winning Ticket (num=1000, denom=1000)
        let winning_ticket = Ticket {
            channelId: channel_id,
            provider: provider_addr,
            nonce: 2,
            faceValue: 50_000,
            winProbNumerator: 1000,
            winProbDenominator: 1000,
            expiry: now + 3600,
            clientSeed: B256::from([0x34; 32]),
            providerCommitment: received_commitment,
        };

        let digest2 = winning_ticket.eip712_signing_hash(&verifier.domain);
        let sig2 = client_signer.sign_hash(&digest2).await.unwrap();

        let mut ticket2_payload = Vec::new();
        ticket2_payload.extend_from_slice(&winning_ticket.abi_encode());
        ticket2_payload.extend_from_slice(&(sig2.as_bytes().len() as u32).to_le_bytes());
        ticket2_payload.extend_from_slice(sig2.as_bytes().as_ref());
        ticket2_payload.extend_from_slice(&(prompt_bytes.len() as u32).to_le_bytes());
        ticket2_payload.extend_from_slice(prompt_bytes);

        let req_frame2 = TCPServer::build_frame(MsgType::TicketRequest, &ticket2_payload);
        client.write_all(&req_frame2).await.unwrap();

        // Verify Settlement Worker received ClaimTask
        let task = settlement_rx.recv().await.expect("Expected ClaimTask in queue");
        assert_eq!(task.ticket.nonce, 2);
        assert_eq!(task.ticket.faceValue, 50_000);
        assert_eq!(task.provider_seed, provider_seed);

        // Read ComputeResp for winning ticket
        let mut resp_header2 = [0u8; 9];
        client.read_exact(&mut resp_header2).await.unwrap();
        assert_eq!(resp_header2[4], MsgType::ComputeResp as u8);

        // Clean close
        drop(client);
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn test_tcp_gatekeeper_integration_reject_invalid_nonce() {
        let listener = TestListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let provider_addr = Address::from([0x11; 20]);
        let contract_addr = Address::from([0x22; 20]);
        let chain_id = 31337u64;

        let server = TCPServer::new(&addr.to_string())
            .with_chain_config(provider_addr, contract_addr, chain_id);

        let provider_seed = server.provider_seed;
        let provider_commitment = server.provider_commitment;

        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            TCPServer::handle_client(
                &mut stream,
                provider_addr,
                contract_addr,
                chain_id,
                provider_seed,
                provider_commitment,
                None,
                None,
            )
            .await
        });

        let client_signer = PrivateKeySigner::random();
        let client_addr = client_signer.address();
        let channel_id = keccak256([client_addr.as_slice(), provider_addr.as_slice()].concat());

        let mut client = TcpStream::connect(addr).await.unwrap();

        // Handshake
        let mut header = [0u8; 9];
        client.read_exact(&mut header).await.unwrap();
        let len = u32::from_le_bytes(header[5..9].try_into().unwrap()) as usize;
        let mut commitment_buf = vec![0u8; len];
        client.read_exact(&mut commitment_buf).await.unwrap();
        let received_commitment = B256::from_slice(&commitment_buf);

        let mut ack_payload = Vec::with_capacity(52);
        ack_payload.extend_from_slice(channel_id.as_slice());
        ack_payload.extend_from_slice(client_addr.as_slice());
        let ack_frame = TCPServer::build_frame(MsgType::HandshakeAck, &ack_payload);
        client.write_all(&ack_frame).await.unwrap();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Send Out-of-Order Nonce (nonce 99 instead of 1)
        let invalid_ticket = Ticket {
            channelId: channel_id,
            provider: provider_addr,
            nonce: 99,
            faceValue: 50_000,
            winProbNumerator: 1,
            winProbDenominator: 1000,
            expiry: now + 3600,
            clientSeed: B256::from([0x99; 32]),
            providerCommitment: received_commitment,
        };

        let verifier = TicketVerifier::new(provider_addr, contract_addr, chain_id, provider_seed);
        let digest = invalid_ticket.eip712_signing_hash(&verifier.domain);
        let sig = client_signer.sign_hash(&digest).await.unwrap();

        let mut ticket_payload = Vec::new();
        ticket_payload.extend_from_slice(&invalid_ticket.abi_encode());
        ticket_payload.extend_from_slice(&(sig.as_bytes().len() as u32).to_le_bytes());
        ticket_payload.extend_from_slice(sig.as_bytes().as_ref());
        let prompt_bytes = b"Bad Nonce";
        ticket_payload.extend_from_slice(&(prompt_bytes.len() as u32).to_le_bytes());
        ticket_payload.extend_from_slice(prompt_bytes);

        let req_frame = TCPServer::build_frame(MsgType::TicketRequest, &ticket_payload);
        client.write_all(&req_frame).await.unwrap();

        // Server must return MsgType::ErrorHalt
        let mut err_header = [0u8; 9];
        client.read_exact(&mut err_header).await.unwrap();
        assert_eq!(err_header[4], MsgType::ErrorHalt as u8);

        let err_len = u32::from_le_bytes(err_header[5..9].try_into().unwrap()) as usize;
        let mut err_body = vec![0u8; err_len];
        client.read_exact(&mut err_body).await.unwrap();
        let err_str = String::from_utf8_lossy(&err_body);
        assert!(err_str.contains("InvalidNonce"));

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_err());
    }
}
