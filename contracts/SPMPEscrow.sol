// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/**
 * @title SPMPEscrow
 * @notice Stateless Probabilistic Micropayment Protocol (SPMP) Escrow & Settlement Engine.
 * @dev Manages client deposits, per-provider channels, two-party randomness verification,
 *      EIP-712 ticket validation, replay prevention, and timelocked withdrawals.
 */
contract SPMPEscrow is EIP712, ReentrancyGuard {
    using ECDSA for bytes32;

    IERC20 public immutable token; // Typically USDC (or MockUSDC for testnet/anvil)
    uint256 public constant WITHDRAWAL_DELAY = 1 days; // Delay window to prevent early fund draining

    // TypeHash for EIP-712 structured data signing
    bytes32 public constant TICKET_TYPEHASH = keccak256(
        "Ticket(bytes32 channelId,address provider,uint64 nonce,uint128 faceValue,uint32 winProbNumerator,uint32 winProbDenominator,uint64 expiry,bytes32 clientSeed,bytes32 providerCommitment)"
    );

    struct Channel {
        address client;
        address provider;
        uint256 balance;
        uint64 closeRequestedAt; // 0 if no withdrawal requested
    }

    struct Ticket {
        bytes32 channelId;
        address provider;
        uint64 nonce;
        uint128 faceValue;
        uint32 winProbNumerator;     // e.g. 1
        uint32 winProbDenominator;   // e.g. 1000 for 1/1000 probability
        uint64 expiry;               // Unix timestamp
        bytes32 clientSeed;          // Client's entropy contribution (rR)
        bytes32 providerCommitment;  // Hashed commitment of provider secret: H(rP)
    }

    // Mapping of channelId => Channel state
    mapping(bytes32 => Channel) public channels;

    // Replay protection: mapping of nullifier (hash of channelId + nonce) => claimed status
    mapping(bytes32 => bool) public nullifiers;

    // Events
    event ChannelOpened(bytes32 indexed channelId, address indexed client, address indexed provider, uint256 initialDeposit);
    event ChannelToppedUp(bytes32 indexed channelId, uint256 amount, uint256 newBalance);
    event TicketClaimed(bytes32 indexed channelId, address indexed provider, uint64 nonce, uint128 payout, bytes32 nullifier);
    event CloseRequested(bytes32 indexed channelId, uint64 unlockTimestamp);
    event ChannelWithdrawn(bytes32 indexed channelId, address indexed client, uint256 amountRefunded);

    error InvalidChannel();
    error ChannelAlreadyExists();
    error InsufficientEscrow();
    error TicketExpired();
    error TicketAlreadyClaimed();
    error InvalidTicketSigner();
    error InvalidProviderSeed();
    error NonWinningTicket();
    error CloseAlreadyRequested();
    error CloseNotRequested();
    error WithdrawalLocked();
    error Unauthorized();

    constructor(address _token) EIP712("SPMP_Protocol", "1") {
        require(_token != address(0), "Invalid token address");
        token = IERC20(_token);
    }

    /**
     * @notice Generates a deterministic channelId for a given client and provider pair.
     */
    function getChannelId(address client, address provider) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(client, provider));
    }

    /**
     * @notice Opens a dedicated escrow channel for a specific provider.
     * @param provider The provider's payout address.
     * @param amount The initial token amount to deposit.
     */
    function openChannel(address provider, uint256 amount) external nonReentrant returns (bytes32 channelId) {
        require(provider != address(0), "Invalid provider address");
        require(amount > 0, "Amount must be > 0");

        channelId = getChannelId(msg.sender, provider);
        if (channels[channelId].client != address(0)) revert ChannelAlreadyExists();

        channels[channelId] = Channel({
            client: msg.sender,
            provider: provider,
            balance: amount,
            closeRequestedAt: 0
        });

        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        emit ChannelOpened(channelId, msg.sender, provider, amount);
    }

    /**
     * @notice Adds additional funds to an existing channel.
     * @param channelId Unique identifier of the channel.
     * @param amount Token amount to deposit.
     */
    function deposit(bytes32 channelId, uint256 amount) external nonReentrant {
        Channel storage channel = channels[channelId];
        if (channel.client == address(0)) revert InvalidChannel();
        require(amount > 0, "Amount must be > 0");

        channel.balance += amount;
        require(token.transferFrom(msg.sender, address(this), amount), "Transfer failed");

        emit ChannelToppedUp(channelId, amount, channel.balance);
    }

    /**
     * @notice Claims a winning probabilistic ticket on-chain.
     * @dev Executed by the provider. Verifies EIP-712 signature, two-party randomness, and nullifier.
     * @param ticket The ticket metadata payload.
     * @param signature The EIP-712 ECDSA signature from the client.
     * @param providerSeed The secret seed (rP) revealed by the provider.
     */
    function claimTicket(
        Ticket calldata ticket,
        bytes calldata signature,
        bytes32 providerSeed
    ) external nonReentrant {
        Channel storage channel = channels[ticket.channelId];
        if (channel.client == address(0)) revert InvalidChannel();
        if (channel.provider != msg.sender) revert Unauthorized();
        if (block.timestamp > ticket.expiry) revert TicketExpired();
        if (channel.balance < ticket.faceValue) revert InsufficientEscrow();

        // 1. Replay Protection check
        bytes32 nullifier = keccak256(abi.encodePacked(ticket.channelId, ticket.nonce));
        if (nullifiers[nullifier]) revert TicketAlreadyClaimed();

        // 2. Verify Provider Commitment Integrity: H(providerSeed) == ticket.providerCommitment
        if (keccak256(abi.encodePacked(providerSeed)) != ticket.providerCommitment) {
            revert InvalidProviderSeed();
        }

        // 3. Compute EIP-712 Digest & Verify Signer
        bytes32 structHash = keccak256(
            abi.encode(
                TICKET_TYPEHASH,
                ticket.channelId,
                ticket.provider,
                ticket.nonce,
                ticket.faceValue,
                ticket.winProbNumerator,
                ticket.winProbDenominator,
                ticket.expiry,
                ticket.clientSeed,
                ticket.providerCommitment
            )
        );
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = digest.recover(signature);
        if (signer != channel.client) revert InvalidTicketSigner();

        // 4. Two-Party Randomness Verification (Commit-Reveal)
        // Combined entropy: Hash(digest + clientSeed + providerSeed)
        bytes32 combinedHash = keccak256(
            abi.encodePacked(digest, ticket.clientSeed, providerSeed)
        );

        // Win Threshold Calculation: Target = (type(uint256).max / Denominator) * Numerator
        uint256 target = (type(uint256).max / ticket.winProbDenominator) * ticket.winProbNumerator;
        if (uint256(combinedHash) >= target) revert NonWinningTicket();

        // 5. State Update & Payout
        nullifiers[nullifier] = true;
        channel.balance -= ticket.faceValue;

        require(token.transfer(channel.provider, ticket.faceValue), "Payout transfer failed");

        emit TicketClaimed(ticket.channelId, channel.provider, ticket.nonce, ticket.faceValue, nullifier);
    }

    /**
     * @notice Initiates a timelocked channel close request by the client.
     */
    function requestClose(bytes32 channelId) external {
        Channel storage channel = channels[channelId];
        if (channel.client != msg.sender) revert Unauthorized();
        if (channel.closeRequestedAt != 0) revert CloseAlreadyRequested();

        channel.closeRequestedAt = uint64(block.timestamp);
        emit CloseRequested(channelId, uint64(block.timestamp + WITHDRAWAL_DELAY));
    }

    /**
     * @notice Finalizes channel withdrawal after the delay window expires.
     */
    function withdraw(bytes32 channelId) external nonReentrant {
        Channel storage channel = channels[channelId];
        if (channel.client != msg.sender) revert Unauthorized();
        if (channel.closeRequestedAt == 0) revert CloseNotRequested();
        if (block.timestamp < channel.closeRequestedAt + WITHDRAWAL_DELAY) revert WithdrawalLocked();

        uint256 remaining = channel.balance;
        channel.balance = 0;
        delete channels[channelId];

        if (remaining > 0) {
            require(token.transfer(msg.sender, remaining), "Refund transfer failed");
        }

        emit ChannelWithdrawn(channelId, msg.sender, remaining);
    }
}
