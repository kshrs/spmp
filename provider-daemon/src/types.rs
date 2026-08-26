use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

// Core Solidity struct definition for exact EIP-712 hashing conformity
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

    interface ISPMPEscrow {
        function claimTicket(
            Ticket calldata ticket,
            bytes calldata signature,
            bytes32 providerSeed
        ) external;
    }
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

/// Wire protocol constants
pub const SPMP_MAGIC: u32 = 0x53504D50;

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
