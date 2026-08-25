use crate::types::{PricingConfig, SignedTicket, Ticket, TicketPayload};
use alloy_primitives::{Address, B256, U256};
use alloy_signer::Signer as AlloySignerTrait;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::{eip712_domain, SolStruct};
use anyhow::{Context, Result};
use rand::RngCore;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Dev 3 Component: Manages key custody, atomic sequential nonces,
/// CSPRNG client entropy generation, and EIP-712 structured data signing.
pub struct Signer {
    signer: PrivateKeySigner,
    client_address: Address,
    channel_id: B256,
    provider_address: Address,
    contract_address: Address,
    chain_id: u64,
    nonce_watermark: AtomicU64,
    domain: alloy_sol_types::Eip712Domain,
}

impl Signer {
    /// Initializes the Signer with a private key hex string, channel ID, addresses, and chain ID.
    pub fn new(
        hex_key: &str,
        channel_id: B256,
        provider_address: Address,
        contract_address: Address,
        chain_id: u64,
    ) -> Result<Self> {
        let clean_key = hex_key.strip_prefix("0x").unwrap_or(hex_key);
        let signer: PrivateKeySigner = clean_key
            .parse()
            .context("Failed to parse secp256k1 private key hex")?;
        
        let client_address = signer.address();

        // EIP-712 Domain matching SPMPEscrow constructor: EIP712("SPMP_Protocol", "1")
        let domain = eip712_domain! {
            name: "SPMP_Protocol",
            version: "1",
            chain_id: chain_id,
            verifying_contract: contract_address,
        };

        Ok(Self {
            signer,
            client_address,
            channel_id,
            provider_address,
            contract_address,
            chain_id,
            nonce_watermark: AtomicU64::new(0),
            domain,
        })
    }

    /// Returns the public Ethereum address of the client signer.
    pub fn client_address(&self) -> Address {
        self.client_address
    }

    /// Returns the active Channel ID.
    pub fn channel_id(&self) -> B256 {
        self.channel_id
    }

    /// Returns the current atomic nonce watermark.
    pub fn current_nonce(&self) -> u64 {
        self.nonce_watermark.load(Ordering::SeqCst)
    }

    /// Generates 32 bytes of cryptographically secure random entropy for clientSeed (rR).
    pub fn generate_client_seed(&self) -> B256 {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        B256::from(seed)
    }

    /// Computes the standard EIP-712 signing digest matching SPMPEscrow.sol.
    pub fn compute_eip712_digest(&self, ticket: &Ticket) -> B256 {
        ticket.eip712_signing_hash(&self.domain)
    }

    /// Constructs the next sequential Ticket, increments the atomic nonce watermark,
    /// generates client entropy, and computes the 65-byte EIP-712 ECDSA signature.
    pub async fn sign_next_ticket(
        &self,
        provider_commitment: B256,
        pricing: &PricingConfig,
    ) -> Result<SignedTicket> {
        // 1. Atomically increment nonce
        let nonce = self.nonce_watermark.fetch_add(1, Ordering::SeqCst) + 1;

        // 2. Generate CSPRNG Client Seed (rR)
        let client_seed = self.generate_client_seed();

        // 3. Compute Expiry Timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("System clock is before UNIX epoch")?
            .as_secs();
        let expiry = now + pricing.expiry_duration_sec;

        // 4. Construct Alloy SolStruct for EIP-712 encoding
        let sol_ticket = Ticket {
            channelId: self.channel_id,
            provider: self.provider_address,
            nonce,
            faceValue: pricing.face_value.to::<u128>(),
            winProbNumerator: pricing.win_prob_numerator,
            winProbDenominator: pricing.win_prob_denominator,
            expiry,
            clientSeed: client_seed,
            providerCommitment: provider_commitment,
        };

        // 5. Compute EIP-712 Digest: keccak256("\x19\x01" || domainSeparator || structHash)
        let digest = self.compute_eip712_digest(&sol_ticket);

        // 6. Sign Digest with local Secp256k1 key
        let signature = self.signer.sign_hash(&digest).await?;
        let sig_bytes = signature.as_bytes().to_vec(); // 65 bytes [r (32B), s (32B), v (1B)]

        // 7. Package into in-memory container
        let payload = TicketPayload {
            channel_id: self.channel_id,
            provider: self.provider_address,
            nonce,
            face_value: pricing.face_value,
            win_prob_numerator: pricing.win_prob_numerator,
            win_prob_denominator: pricing.win_prob_denominator,
            expiry,
            client_seed,
            provider_commitment,
        };

        Ok(SignedTicket {
            payload,
            signature: sig_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};
    use alloy_signer::Signer as AlloySignerTrait;
    use std::sync::Arc;

    const TEST_PRIVATE_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"; // Anvil Account #0
    const TEST_CHANNEL_ID: B256 = b256!("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20");
    const TEST_PROVIDER: Address = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"); // Anvil Account #1
    const TEST_CONTRACT: Address = address!("5FbDB2315678afecb367f032d93F642f64180aa3");
    const TEST_CHAIN_ID: u64 = 31337; // Anvil Chain ID

    #[tokio::test]
    async fn test_signer_initialization() {
        let signer = Signer::new(
            TEST_PRIVATE_KEY,
            TEST_CHANNEL_ID,
            TEST_PROVIDER,
            TEST_CONTRACT,
            TEST_CHAIN_ID,
        )
        .expect("Failed to create signer");

        assert_eq!(
            signer.client_address(),
            address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266") // Anvil Account #0 Address
        );
        assert_eq!(signer.current_nonce(), 0);
    }

    #[tokio::test]
    async fn test_sign_next_ticket_and_recover_address() {
        let signer = Signer::new(
            TEST_PRIVATE_KEY,
            TEST_CHANNEL_ID,
            TEST_PROVIDER,
            TEST_CONTRACT,
            TEST_CHAIN_ID,
        )
        .expect("Failed to create signer");

        let pricing = PricingConfig::default();
        let provider_commitment = b256!("1111111111111111111111111111111111111111111111111111111111111111");

        let signed_ticket = signer
            .sign_next_ticket(provider_commitment, &pricing)
            .await
            .expect("Failed to sign ticket");

        assert_eq!(signed_ticket.payload.nonce, 1);
        assert_eq!(signed_ticket.signature.len(), 65);
        assert_eq!(signer.current_nonce(), 1);

        // Verify EIP-712 signature recovery
        let sol_ticket = Ticket {
            channelId: signed_ticket.payload.channel_id,
            provider: signed_ticket.payload.provider,
            nonce: signed_ticket.payload.nonce,
            faceValue: signed_ticket.payload.face_value.to::<u128>(),
            winProbNumerator: signed_ticket.payload.win_prob_numerator,
            winProbDenominator: signed_ticket.payload.win_prob_denominator,
            expiry: signed_ticket.payload.expiry,
            clientSeed: signed_ticket.payload.client_seed,
            providerCommitment: signed_ticket.payload.provider_commitment,
        };

        let digest = signer.compute_eip712_digest(&sol_ticket);
        let sig = alloy_primitives::Signature::try_from(signed_ticket.signature.as_slice())
            .expect("Failed to parse signature bytes");

        let recovered_address = sig
            .recover_address_from_prehash(&digest)
            .expect("Address recovery failed");

        assert_eq!(recovered_address, signer.client_address());
    }

    #[tokio::test]
    async fn test_nonce_monotonicity_under_concurrency() {
        let signer = Arc::new(
            Signer::new(
                TEST_PRIVATE_KEY,
                TEST_CHANNEL_ID,
                TEST_PROVIDER,
                TEST_CONTRACT,
                TEST_CHAIN_ID,
            )
            .unwrap(),
        );

        let pricing = PricingConfig::default();
        let provider_commitment = b256!("2222222222222222222222222222222222222222222222222222222222222222");

        let mut handles = Vec::new();
        for _ in 0..50 {
            let s = Arc::clone(&signer);
            let p = pricing.clone();
            handles.push(tokio::spawn(async move {
                s.sign_next_ticket(provider_commitment, &p).await.unwrap()
            }));
        }

        let mut nonces = Vec::new();
        for handle in handles {
            let ticket = handle.await.unwrap();
            nonces.push(ticket.payload.nonce);
        }

        nonces.sort();
        assert_eq!(nonces.len(), 50);
        for (i, nonce) in nonces.iter().enumerate() {
            assert_eq!(*nonce, (i + 1) as u64);
        }
        assert_eq!(signer.current_nonce(), 50);
    }
}
