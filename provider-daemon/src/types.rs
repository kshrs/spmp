use alloy_primitives::{uint, Address, B256, U256};
use alloy_sol_types::{sol, SolValue};
use anyhow::anyhow;
use serde::{Deserialize, Serialize};

/// Half-order of secp256k1 curve (n / 2) to protect against ECDSA signature malleability (EIP-2).
pub const SECP256K1_HALF_ORDER: U256 = uint!(
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E735EBE07597DA786400E927ED0_U256
);

/// Secp256k1 curve order n.
pub const SECP256K1_N: U256 = uint!(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_U256
);

// Core Solidity struct definition for exact EIP-712 hashing conformity with SPMPEscrow.sol
sol! {
    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
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

/// Verification verdict returned by Developer 2's Fast Gatekeeper engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TicketVerdict {
    ValidLosing,
    ValidWinning,
    InvalidSignature,
    InvalidCommitment,
    InvalidNonce,
    Expired,
}

/// Discrete operational action returned to Developer 1 and Developer 3/4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GatekeeperDecision {
    /// Ticket is valid losing. Serve compute chunk immediately.
    ServeLosing,
    /// Ticket is valid winning! Submit claim on-chain and trigger provider seed rotation.
    ClaimAndRotateWinning,
    /// Ticket was rejected. Terminate stream or halt connection.
    Reject(TicketVerdict),
}

/// Wire protocol constants
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
