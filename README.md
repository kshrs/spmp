# Stateless Probabilistic Micropayment Protocol (SPMP)

## Description
* A high-frequency off-chain payment and data streaming protocol for Decentralized Physical Infrastructure Networks (DePIN), pay-per-token AI inference, and machine-to-machine compute.
* Converts micro-obligations into cryptographically signed EIP-712 lottery tickets streamed over raw TCP sockets, achieving sub-millisecond local verification latency and reducing on-chain transactions by over 99%.

## Project Structure
```text
.
├── contracts/               # Solidity smart contracts (Foundry)
│   ├── SPMPEscrow.sol       # Core escrow, two-party randomness, and settlement contract
│   └── MockUSDC.sol         # Test ERC-20 stablecoin
├── client-daemon/           # Client sidecar proxy (Rust)
│   └── src/
│       ├── crypto.rs        # EIP-712 signer and CSPRNG entropy generator
│       ├── orchestrator.rs  # Stream pipeline coordinator
│       ├── proxy.rs         # HTTP reverse proxy (OpenAI SSE compatibility)
│       ├── transport.rs     # TCP client and wire frame encoder
│       └── types.rs         # Shared domain types and ticket definitions
├── provider-daemon/         # Worker/GPU sidecar daemon (Rust)
│   └── src/
│       ├── settlement.rs    # Async on-chain settlement worker (Alloy RPC)
│       ├── transport.rs     # Inbound TCP server and wire frame decoder
│       ├── verifier.rs      # In-memory ticket gatekeeper (<0.5ms execution)
│       ├── worker.rs        # LLM stream dispatcher (Ollama/vLLM)
│       └── types.rs         # Shared domain types and contract bindings
├── tests/                   # Developer technical specifications and test guides
└── Cargo.toml               # Cargo workspace configuration
```

## Prerequisites
* Rust toolchain (edition 2021, cargo)
* Foundry (`forge`, `anvil`, `cast`)

## Installation & Usage

### 1. Smart Contracts & Local Testnet

Start local Anvil node:
```bash
anvil
```

Deploy contracts to local Anvil:
```bash
forge create contracts/MockUSDC.sol:MockUSDC \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80

forge create contracts/SPMPEscrow.sol:SPMPEscrow \
  --rpc-url http://127.0.0.1:8545 \
  --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
  --constructor-args <DEPLOYED_MOCK_USDC_ADDRESS>
```

### 2. Build Daemons

Compile the Rust workspace:
```bash
cargo build
```

Run test suite across all crates:
```bash
cargo test
```

### 3. Run Daemons

Start the Provider Daemon (listens on `0.0.0.0:9000`):
```bash
cargo run --bin provider-daemon
```

Start the Client Daemon (listens on `127.0.0.1:8080`):
```bash
cargo run --bin client-daemon
```

### 4. Client Inference Request

Send standard OpenAI-compatible streaming chat completions:
```bash
curl -N http://127.0.0.1:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3",
    "messages": [{"role": "user", "content": "Hello world"}],
    "stream": true
  }'
```
