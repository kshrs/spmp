use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

// Solidity struct definition for exact EIP-712 hashing conformity
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
}

/// Economic pricing parameters configured for the streaming session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PricingConfig {
    pub face_value: U256,
    pub win_prob_numerator: u32,
    pub win_prob_denominator: u32,
    pub expiry_duration_sec: u64,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            face_value: U256::from(50_000), // 0.05 USDC (6 decimals)
            win_prob_numerator: 1,
            win_prob_denominator: 50, // 1/50 odds (2% win rate)
            expiry_duration_sec: 86400, // 24 hours
        }
    }
}

/// In-memory metadata of an SPMP Ticket.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TicketPayload {
    pub channel_id: B256,
    pub provider: Address,
    pub nonce: u64,
    pub face_value: U256,
    pub win_prob_numerator: u32,
    pub win_prob_denominator: u32,
    pub expiry: u64,
    pub client_seed: B256,
    pub provider_commitment: B256,
}

/// A signed ticket container holding payload + 65-byte ECDSA signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTicket {
    pub payload: TicketPayload,
    pub signature: Vec<u8>, // 65 bytes [r (32B), s (32B), v (1B)]
}

/// Wire protocol constants.
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
