use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{sol, SolValue};
use anyhow::anyhow;
use serde::{Deserialize, Serialize};

// Solidity struct definition for exact EIP-712 hashing conformity with SPMPEscrow.sol
sol! {
    #[derive(Debug, Serialize, Deserialize)]
    struct Ticket {
        bytes32 channelId;
        address provider;
        uint64 nonce;
        uint128 faceValue;
        uint32 winProbNumerator;
        uint32 winProbDenominator;
        uint64 expiry;
        bytes32 clientSeed;
        bytes32 providerCommitment;
    }

    #[sol(rpc)]
    interface ISPMPEscrow {
        function claimTicket(
            Ticket calldata ticket,
            bytes calldata signature,
            bytes32 providerSeed
        ) external;
    }
}

/// Dynamic session parameters negotiated during handshake.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub channel_id: B256,
    pub client_address: Address,
    pub provider_seed: B256,       // rP (Secret kept in provider RAM)
    pub provider_commitment: B256, // H(rP) sent to client
    pub last_nonce: u64,           // Nonce watermark tracking
}

/// Parsed incoming ticket container with signature and chunk payload.
#[derive(Debug, Clone)]
pub struct IncomingTicketFrame {
    pub ticket: Ticket,
    pub signature: Vec<u8>,
    pub prompt_payload: Vec<u8>,
}

/// Evaluation verdict computed in-memory by Dev 2's Gatekeeper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketVerdict {
    ValidLosing,
    ValidWinning,
    InvalidSignature,
    InvalidCommitment,
    InvalidNonce,
    Expired,
}

pub const SPMP_MAGIC: u32 = 0x53504D50; // "SPMP" in ASCII

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    HandshakeInit = 0x01,
    HandshakeAck = 0x02,
    TicketRequest = 0x03,
    ComputeResp = 0x04,
    WinNotify = 0x05,
    ErrorHalt = 0xFF,
}

impl MsgType {
    pub fn from_u8(byte: u8) -> anyhow::Result<Self> {
        match byte {
            0x01 => Ok(Self::HandshakeInit),
            0x02 => Ok(Self::HandshakeAck),
            0x03 => Ok(Self::TicketRequest),
            0x04 => Ok(Self::ComputeResp),
            0x05 => Ok(Self::WinNotify),
            0xFF => Ok(Self::ErrorHalt),
            other => Err(anyhow!("unknown MsgType byte: 0x{other:02x}")),
        }
    }
}

pub fn decode_ticket(buf: &[u8]) -> anyhow::Result<Ticket> {
    Ticket::abi_decode(buf, true).map_err(|e| anyhow!("bad Ticket abi: {e}"))
}
