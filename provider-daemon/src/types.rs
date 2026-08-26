use alloy_primitives::{uint, U256};
use alloy_sol_types::sol;
use serde::{Deserialize, Serialize};

/// Half-order of secp256k1 curve (n / 2) to protect against ECDSA signature malleability (EIP-2).
pub const SECP256K1_HALF_ORDER: U256 = uint!(
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E735EBE07597DA786400E927ED0_U256
);

/// Secp256k1 curve order n.
pub const SECP256K1_N: U256 = uint!(
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_U256
);

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
