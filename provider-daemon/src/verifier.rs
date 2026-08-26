use alloy_primitives::{keccak256, Address, B256, Signature, U256};
use alloy_sol_types::{Eip712Domain, SolStruct};
use crate::types::{Ticket, TicketVerdict};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TicketVerifier {
    pub contract_address: Address,
    pub chain_id: u64,
    pub provider_address: Address,
    pub provider_seed: B256,
    pub provider_commitment: B256,
    pub domain_separator: B256,
    pub domain: Eip712Domain,
}

impl TicketVerifier {
    pub fn new(provider_address: Address, contract_address: Address, chain_id: u64, provider_seed: B256) -> Self {
        let provider_commitment = keccak256(provider_seed);
        let domain = Eip712Domain {
            name: Some("SPMP_Protocol".into()),
            version: Some("1".into()),
            chain_id: Some(U256::from(chain_id)),
            verifying_contract: Some(contract_address),
            salt: None,
        };
        let domain_separator = domain.hash_struct();

        Self {
            contract_address,
            chain_id,
            provider_address,
            provider_seed,
            provider_commitment,
            domain_separator,
            domain,
        }
    }

    /// Sub-millisecond in-memory cryptographic gatekeeper (<0.5ms).
    /// Evaluates watermarks, commitments, EIP-712 signatures, and two-party entropy.
    #[inline(always)]
    pub fn verify_ticket(
        &self,
        ticket: &Ticket,
        signature_bytes: &[u8],
        client_addr: Address,
        last_nonce: u64,
    ) -> TicketVerdict {
        // 1. Watermark Monotonicity Check
        if ticket.nonce != last_nonce + 1 {
            return TicketVerdict::InvalidNonce;
        }

        // 2. Cryptographic Commitment Integrity Check
        if ticket.providerCommitment != self.provider_commitment {
            return TicketVerdict::InvalidCommitment;
        }

        // 3. Expiry Check
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => return TicketVerdict::Expired,
        };
        if ticket.expiry <= now {
            return TicketVerdict::Expired;
        }

        // 4. Pre-computed Domain EIP-712 Struct Hashing & ECDSA Recovery
        let struct_hash = ticket.eip712_hash_struct();
        let mut digest_buf = [0u8; 66];
        digest_buf[0] = 0x19;
        digest_buf[1] = 0x01;
        digest_buf[2..34].copy_from_slice(self.domain_separator.as_slice());
        digest_buf[34..66].copy_from_slice(struct_hash.as_slice());
        let digest = keccak256(digest_buf);

        let Ok(sig) = Signature::try_from(signature_bytes) else {
            return TicketVerdict::InvalidSignature;
        };

        let Ok(recovered_address) = sig.recover_address_from_prehash(&digest) else {
            return TicketVerdict::InvalidSignature;
        };

        if recovered_address != client_addr {
            return TicketVerdict::InvalidSignature;
        }

        // 5. Two-Party Combined Entropy Evaluation (Zero Heap Allocations)
        let mut combined_buf = [0u8; 96];
        combined_buf[0..32].copy_from_slice(digest.as_slice());
        combined_buf[32..64].copy_from_slice(ticket.clientSeed.as_slice());
        combined_buf[64..96].copy_from_slice(self.provider_seed.as_slice());
        let combined_hash = keccak256(combined_buf);

        if ticket.winProbDenominator == 0 {
            return TicketVerdict::ValidLosing;
        }

        let target = (U256::MAX / U256::from(ticket.winProbDenominator)) * U256::from(ticket.winProbNumerator);
        let combined_val = U256::from_be_bytes(combined_hash.0);

        if combined_val < target {
            TicketVerdict::ValidWinning
        } else {
            TicketVerdict::ValidLosing
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_signer::Signer;
    use alloy_signer_local::PrivateKeySigner;
    use std::time::Instant;

    fn setup_env() -> (TicketVerifier, PrivateKeySigner, Address, B256) {
        let provider_seed = B256::from([0x77; 32]);
        let provider_addr = Address::from([0x11; 20]);
        let contract_addr = Address::from([0x22; 20]);
        let chain_id = 31337u64;

        let verifier = TicketVerifier::new(provider_addr, contract_addr, chain_id, provider_seed);
        let client_signer = PrivateKeySigner::random();
        let client_addr = client_signer.address();
        (verifier, client_signer, client_addr, provider_seed)
    }

    #[tokio::test]
    async fn test_verify_valid_ticket() {
        let (verifier, client_signer, client_addr, _provider_seed) = setup_env();
        let channel_id = keccak256([client_addr.as_slice(), verifier.provider_address.as_slice()].concat());
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let ticket = Ticket {
            channelId: channel_id,
            provider: verifier.provider_address,
            nonce: 1,
            faceValue: 1_000_000,
            winProbNumerator: 1,
            winProbDenominator: 1000,
            expiry: now + 3600,
            clientSeed: B256::from([0xaa; 32]),
            providerCommitment: verifier.provider_commitment,
        };

        let digest = ticket.eip712_signing_hash(&verifier.domain);
        let signature = client_signer.sign_hash(&digest).await.unwrap();
        let sig_bytes = signature.as_bytes();

        let verdict = verifier.verify_ticket(&ticket, &sig_bytes, client_addr, 0);
        assert!(
            verdict == TicketVerdict::ValidLosing || verdict == TicketVerdict::ValidWinning,
            "Expected valid ticket verdict but got {:?}", verdict
        );
    }

    #[tokio::test]
    async fn test_verify_invalid_nonce() {
        let (verifier, client_signer, client_addr, _provider_seed) = setup_env();
        let ticket = Ticket {
            channelId: B256::ZERO,
            provider: verifier.provider_address,
            nonce: 5, // Expected 1 if last_nonce is 0
            faceValue: 1000,
            winProbNumerator: 1,
            winProbDenominator: 1000,
            expiry: 9999999999,
            clientSeed: B256::ZERO,
            providerCommitment: verifier.provider_commitment,
        };

        let digest = ticket.eip712_signing_hash(&verifier.domain);
        let signature = client_signer.sign_hash(&digest).await.unwrap();
        let verdict = verifier.verify_ticket(&ticket, &signature.as_bytes(), client_addr, 0);
        assert_eq!(verdict, TicketVerdict::InvalidNonce);
    }

    #[tokio::test]
    async fn test_verify_invalid_commitment() {
        let (verifier, client_signer, client_addr, _provider_seed) = setup_env();
        let ticket = Ticket {
            channelId: B256::ZERO,
            provider: verifier.provider_address,
            nonce: 1,
            faceValue: 1000,
            winProbNumerator: 1,
            winProbDenominator: 1000,
            expiry: 9999999999,
            clientSeed: B256::ZERO,
            providerCommitment: B256::from([0x99; 32]), // Invalid commitment
        };

        let digest = ticket.eip712_signing_hash(&verifier.domain);
        let signature = client_signer.sign_hash(&digest).await.unwrap();
        let verdict = verifier.verify_ticket(&ticket, &signature.as_bytes(), client_addr, 0);
        assert_eq!(verdict, TicketVerdict::InvalidCommitment);
    }

    #[tokio::test]
    async fn test_verify_invalid_signature() {
        let (verifier, _client_signer, client_addr, _provider_seed) = setup_env();
        let malicious_signer = PrivateKeySigner::random();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let ticket = Ticket {
            channelId: B256::ZERO,
            provider: verifier.provider_address,
            nonce: 1,
            faceValue: 1000,
            winProbNumerator: 1,
            winProbDenominator: 1000,
            expiry: now + 3600,
            clientSeed: B256::ZERO,
            providerCommitment: verifier.provider_commitment,
        };

        let digest = ticket.eip712_signing_hash(&verifier.domain);
        let signature = malicious_signer.sign_hash(&digest).await.unwrap();
        let verdict = verifier.verify_ticket(&ticket, &signature.as_bytes(), client_addr, 0);
        assert_eq!(verdict, TicketVerdict::InvalidSignature);
    }

    #[tokio::test]
    async fn test_verify_expired() {
        let (verifier, client_signer, client_addr, _provider_seed) = setup_env();
        let ticket = Ticket {
            channelId: B256::ZERO,
            provider: verifier.provider_address,
            nonce: 1,
            faceValue: 1000,
            winProbNumerator: 1,
            winProbDenominator: 1000,
            expiry: 100, // Expired timestamp
            clientSeed: B256::ZERO,
            providerCommitment: verifier.provider_commitment,
        };

        let digest = ticket.eip712_signing_hash(&verifier.domain);
        let signature = client_signer.sign_hash(&digest).await.unwrap();
        let verdict = verifier.verify_ticket(&ticket, &signature.as_bytes(), client_addr, 0);
        assert_eq!(verdict, TicketVerdict::Expired);
    }

    #[tokio::test]
    async fn test_sub_millisecond_latency_benchmark() {
        let (verifier, client_signer, client_addr, _provider_seed) = setup_env();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // Pre-generate 1,000 signed tickets to benchmark pure verification engine throughput
        let mut tickets = Vec::with_capacity(1000);
        let mut sigs = Vec::with_capacity(1000);

        for i in 1..=1000u64 {
            let ticket = Ticket {
                channelId: B256::ZERO,
                provider: verifier.provider_address,
                nonce: i,
                faceValue: 1_000_000,
                winProbNumerator: 1,
                winProbDenominator: 1000,
                expiry: now + 86400,
                clientSeed: B256::from([((i % 255) as u8); 32]),
                providerCommitment: verifier.provider_commitment,
            };
            let digest = ticket.eip712_signing_hash(&verifier.domain);
            let signature = client_signer.sign_hash(&digest).await.unwrap();
            tickets.push(ticket);
            sigs.push(signature.as_bytes());
        }

        // Warm-up iteration
        for i in 0..10 {
            let _ = verifier.verify_ticket(&tickets[i], &sigs[i], client_addr, i as u64);
        }

        // Measure batch verification latency
        let start = Instant::now();
        for i in 0..1000 {
            let verdict = verifier.verify_ticket(&tickets[i], &sigs[i], client_addr, i as u64);
            assert!(verdict == TicketVerdict::ValidLosing || verdict == TicketVerdict::ValidWinning);
        }
        let elapsed = start.elapsed();
        let avg_micros = elapsed.as_micros() as f64 / 1000.0;
        let avg_millis = avg_micros / 1000.0;
        println!("1,000 Tickets Verified in: {:?} (Avg: {:.2} µs [{:.3} ms] / ticket)", elapsed, avg_micros, avg_millis);
        assert!(avg_millis < 0.5, "Verification must be < 0.5ms per ticket, got {:.3}ms ({:.2}µs)", avg_millis, avg_micros);
    }
}
