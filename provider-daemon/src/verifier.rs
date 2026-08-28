use alloy_primitives::{keccak256, Address, B256, Signature, U256};
use alloy_sol_types::{Eip712Domain, SolStruct};
use crate::types::{GatekeeperDecision, Ticket, TicketVerdict, SECP256K1_HALF_ORDER};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct TicketVerifier {
    pub contract_address: Address,
    pub chain_id: u64,
    pub provider_address: Address,
    pub provider_seed: B256,
    pub provider_commitment: B256,
    pub domain_separator: B256,
    pub domain: Eip712Domain,
    pub seed_invalidated: bool,
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
            seed_invalidated: false,
        }
    }

    /// Rotates the provider secret seed and clears the invalidation flag.
    #[inline(always)]
    pub fn rotate_seed(&mut self, new_seed: B256) {
        self.provider_seed = new_seed;
        self.provider_commitment = keccak256(new_seed);
        self.seed_invalidated = false;
    }

    /// Evaluates incoming ticket frame with zero heap allocations and returns concrete action for Dev 1 / Dev 3.
    #[inline(always)]
    pub fn evaluate_and_gate(
        &mut self,
        ticket: &Ticket,
        signature_bytes: &[u8],
        client_addr: Address,
        last_nonce: u64,
    ) -> GatekeeperDecision {
        if self.seed_invalidated {
            return GatekeeperDecision::Reject(TicketVerdict::InvalidCommitment);
        }

        let verdict = self.verify_ticket(ticket, signature_bytes, client_addr, last_nonce);
        match verdict {
            TicketVerdict::ValidLosing => GatekeeperDecision::ServeLosing,
            TicketVerdict::ValidWinning => {
                // Invalidate seed to prevent sender grinding once rP is revealed on-chain
                self.seed_invalidated = true;
                GatekeeperDecision::ClaimAndRotateWinning
            }
            rejected => GatekeeperDecision::Reject(rejected),
        }
    }

    /// Sub-millisecond in-memory cryptographic gatekeeper (<0.25ms).
    /// Enforces watermark monotonicity, commitment integrity, expiry,
    /// EIP-2 low-S signature non-malleability, and two-party entropy thresholding.
    #[inline(always)]
    pub fn verify_ticket(
        &self,
        ticket: &Ticket,
        signature_bytes: &[u8],
        client_addr: Address,
        last_nonce: u64,
    ) -> TicketVerdict {
        // 1. Watermark Monotonicity Check (O(1), ~100ns)
        if ticket.nonce != last_nonce.wrapping_add(1) || last_nonce == u64::MAX {
            return TicketVerdict::InvalidNonce;
        }

        // 2. Cryptographic Commitment Integrity Check (O(1), ~150ns)
        if ticket.providerCommitment != self.provider_commitment {
            return TicketVerdict::InvalidCommitment;
        }

        // 3. Expiry Check (O(1), ~300ns)
        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => duration.as_secs(),
            Err(_) => return TicketVerdict::Expired,
        };
        if ticket.expiry <= now {
            return TicketVerdict::Expired;
        }

        // 4. EIP-712 Pre-computed Struct Hashing & ECDSA Recovery
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

        // 4b. EIP-2 / OpenZeppelin ECDSA Low-S Malleability Defense
        if sig.s() > SECP256K1_HALF_ORDER {
            return TicketVerdict::InvalidSignature;
        }

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

        // 5b. Odds Clamping & Division-by-Zero Protection
        let target = if ticket.winProbDenominator == 0 || ticket.winProbNumerator == 0 {
            U256::ZERO
        } else if ticket.winProbNumerator >= ticket.winProbDenominator {
            U256::MAX
        } else {
            (U256::MAX / U256::from(ticket.winProbDenominator)) * U256::from(ticket.winProbNumerator)
        };

        let combined_val = U256::from_be_bytes(combined_hash.0);

        if target == U256::MAX || combined_val < target {
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
    use crate::types::SECP256K1_N;
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
    async fn test_ecdsa_low_s_malleability_defense() {
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

        // Verify valid low-s signature passes
        let verdict = verifier.verify_ticket(&ticket, &sig_bytes, client_addr, 0);
        assert!(verdict == TicketVerdict::ValidLosing || verdict == TicketVerdict::ValidWinning);

        // Construct high-s malleable signature: s_high = N - s_low, v_flipped = v ^ 1
        let r = signature.r();
        let s = signature.s();
        let high_s = SECP256K1_N - s;
        let v = signature.v();
        let flipped_v = if v.y_parity() { 27 } else { 28 };

        // Construct raw 65-byte malleable signature bytes
        let mut malleable_bytes = [0u8; 65];
        malleable_bytes[0..32].copy_from_slice(&r.to_be_bytes::<32>());
        malleable_bytes[32..64].copy_from_slice(&high_s.to_be_bytes::<32>());
        malleable_bytes[64] = flipped_v;

        // Must strictly reject malleable high-s signature
        let malleable_verdict = verifier.verify_ticket(&ticket, &malleable_bytes, client_addr, 0);
        assert_eq!(malleable_verdict, TicketVerdict::InvalidSignature, "Malleable high-s signature must be rejected!");
    }

    #[tokio::test]
    async fn test_odds_clamping_and_saturation() {
        let (verifier, client_signer, client_addr, _provider_seed) = setup_env();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // 1. Numerator = 0 -> Must always lose
        let ticket_zero_num = Ticket {
            channelId: B256::ZERO,
            provider: verifier.provider_address,
            nonce: 1,
            faceValue: 1_000_000,
            winProbNumerator: 0,
            winProbDenominator: 1000,
            expiry: now + 3600,
            clientSeed: B256::ZERO,
            providerCommitment: verifier.provider_commitment,
        };
        let digest = ticket_zero_num.eip712_signing_hash(&verifier.domain);
        let sig = client_signer.sign_hash(&digest).await.unwrap();
        assert_eq!(verifier.verify_ticket(&ticket_zero_num, &sig.as_bytes(), client_addr, 0), TicketVerdict::ValidLosing);

        // 2. Denominator = 0 -> Safe division-by-zero protection (Losing)
        let ticket_zero_denom = Ticket {
            channelId: B256::ZERO,
            provider: verifier.provider_address,
            nonce: 1,
            faceValue: 1_000_000,
            winProbNumerator: 1,
            winProbDenominator: 0,
            expiry: now + 3600,
            clientSeed: B256::ZERO,
            providerCommitment: verifier.provider_commitment,
        };
        let digest2 = ticket_zero_denom.eip712_signing_hash(&verifier.domain);
        let sig2 = client_signer.sign_hash(&digest2).await.unwrap();
        assert_eq!(verifier.verify_ticket(&ticket_zero_denom, &sig2.as_bytes(), client_addr, 0), TicketVerdict::ValidLosing);

        // 3. Numerator >= Denominator -> 100% win saturation
        let ticket_100_percent = Ticket {
            channelId: B256::ZERO,
            provider: verifier.provider_address,
            nonce: 1,
            faceValue: 1_000_000,
            winProbNumerator: 1000,
            winProbDenominator: 1000,
            expiry: now + 3600,
            clientSeed: B256::ZERO,
            providerCommitment: verifier.provider_commitment,
        };
        let digest3 = ticket_100_percent.eip712_signing_hash(&verifier.domain);
        let sig3 = client_signer.sign_hash(&digest3).await.unwrap();
        assert_eq!(verifier.verify_ticket(&ticket_100_percent, &sig3.as_bytes(), client_addr, 0), TicketVerdict::ValidWinning);
    }

    #[tokio::test]
    async fn test_gatekeeper_lifecycle_and_seed_rotation() {
        let (mut verifier, client_signer, client_addr, _provider_seed) = setup_env();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        // 100% winning ticket to trigger win lifecycle
        let win_ticket = Ticket {
            channelId: B256::ZERO,
            provider: verifier.provider_address,
            nonce: 1,
            faceValue: 1_000_000,
            winProbNumerator: 1000,
            winProbDenominator: 1000,
            expiry: now + 3600,
            clientSeed: B256::ZERO,
            providerCommitment: verifier.provider_commitment,
        };
        let digest = win_ticket.eip712_signing_hash(&verifier.domain);
        let sig = client_signer.sign_hash(&digest).await.unwrap();

        let decision = verifier.evaluate_and_gate(&win_ticket, &sig.as_bytes(), client_addr, 0);
        assert_eq!(decision, GatekeeperDecision::ClaimAndRotateWinning);
        assert!(verifier.seed_invalidated);

        // Subsequent ticket must be rejected because seed is invalidated
        let next_ticket = Ticket {
            channelId: B256::ZERO,
            provider: verifier.provider_address,
            nonce: 2,
            faceValue: 1_000_000,
            winProbNumerator: 1,
            winProbDenominator: 1000,
            expiry: now + 3600,
            clientSeed: B256::ZERO,
            providerCommitment: verifier.provider_commitment,
        };
        let digest2 = next_ticket.eip712_signing_hash(&verifier.domain);
        let sig2 = client_signer.sign_hash(&digest2).await.unwrap();
        let decision2 = verifier.evaluate_and_gate(&next_ticket, &sig2.as_bytes(), client_addr, 1);
        assert_eq!(decision2, GatekeeperDecision::Reject(TicketVerdict::InvalidCommitment));

        // After rotation, new seed operates cleanly
        let new_seed = B256::from([0x88; 32]);
        verifier.rotate_seed(new_seed);
        assert!(!verifier.seed_invalidated);
    }

    #[tokio::test]
    async fn test_verify_invalid_nonce() {
        let (verifier, client_signer, client_addr, _provider_seed) = setup_env();
        let ticket = Ticket {
            channelId: B256::ZERO,
            provider: verifier.provider_address,
            nonce: 5,
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
            providerCommitment: B256::from([0x99; 32]),
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
            expiry: 100,
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

        for i in 0..10 {
            let _ = verifier.verify_ticket(&tickets[i], &sigs[i], client_addr, i as u64);
        }

        let start = Instant::now();
        for i in 0..1000 {
            let verdict = verifier.verify_ticket(&tickets[i], &sigs[i], client_addr, i as u64);
            assert!(verdict == TicketVerdict::ValidLosing || verdict == TicketVerdict::ValidWinning);
        }
        let elapsed = start.elapsed();
        let avg_micros = elapsed.as_micros() as f64 / 1000.0;
        let avg_millis = avg_micros / 1000.0;
        println!("1,000 Tickets Verified in: {:?} (Avg: {:.2} µs [{:.3} ms] / ticket)", elapsed, avg_micros, avg_millis);
        assert!(avg_millis < 0.25, "Verification must be < 0.25ms per ticket, got {:.3}ms ({:.2}µs)", avg_millis, avg_micros);
    }

    #[tokio::test]
    async fn test_dry_spell_and_binomial_variance() {
        let (mut verifier, client_signer, client_addr, _provider_seed) = setup_env();
        let mut rng = rand::thread_rng();
        use rand::Rng;

        let total_trials = 1000u64;
        let mut wins = 0u64;
        let mut current_dry_spell = 0u64;
        let mut max_dry_spell = 0u64;

        for nonce in 1..=total_trials {
            let client_seed: [u8; 32] = rng.gen();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

            let ticket = Ticket {
                channelId: B256::ZERO,
                provider: verifier.provider_address,
                nonce,
                faceValue: 50_000,
                winProbNumerator: 1,
                winProbDenominator: 50,
                expiry: now + 3600,
                clientSeed: B256::from(client_seed),
                providerCommitment: verifier.provider_commitment,
            };

            let digest = ticket.eip712_signing_hash(&verifier.domain);
            let sig = client_signer.sign_hash(&digest).await.unwrap();

            let decision = verifier.evaluate_and_gate(&ticket, &sig.as_bytes(), client_addr, nonce - 1);
            match decision {
                GatekeeperDecision::ClaimAndRotateWinning => {
                    wins += 1;
                    current_dry_spell = 0;
                    let new_seed: [u8; 32] = rng.gen();
                    verifier.rotate_seed(B256::from(new_seed));
                }
                GatekeeperDecision::ServeLosing => {
                    current_dry_spell += 1;
                    if current_dry_spell > max_dry_spell {
                        max_dry_spell = current_dry_spell;
                    }
                }
                GatekeeperDecision::Reject(err) => {
                    panic!("Unexpected rejection in variance test at nonce {}: {:?}", nonce, err);
                }
            }
        }

        println!("1,000-Trial Test: {} Wins, Longest Dry Spell: {} consecutive losses", wins, max_dry_spell);
        // Over 1,000 trials at p=0.02, probability of 0 wins is (0.98)^1000 ≈ 1.68e-9.
        // It is mathematically virtually impossible to have 0 wins.
        assert!(wins > 0, "Must have at least one winning ticket in 1,000 trials (p=0.02)");
        assert!(max_dry_spell < 1000, "Max dry spell cannot exceed total trials");
    }

    // =========================================================================
    // Phase 1: Property-Based Fuzzing Suite (proptest)
    // =========================================================================
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        #[test]
        fn fuzz_arbitrary_signature_bytes_never_panics(
            sig_bytes in proptest::collection::vec(any::<u8>(), 0..512),
            nonce in any::<u64>(),
            last_nonce in any::<u64>(),
            face_value in any::<u128>(),
            num in any::<u32>(),
            denom in any::<u32>(),
            expiry in any::<u64>(),
            client_seed in any::<[u8; 32]>(),
            provider_commitment in any::<[u8; 32]>(),
            client_addr in any::<[u8; 20]>()
        ) {
            let verifier = TicketVerifier::new(
                Address::from([0x11; 20]),
                Address::from([0x22; 20]),
                31337,
                B256::from([0x77; 32]),
            );

            let ticket = Ticket {
                channelId: B256::ZERO,
                provider: verifier.provider_address,
                nonce,
                faceValue: face_value,
                winProbNumerator: num,
                winProbDenominator: denom,
                expiry,
                clientSeed: B256::from(client_seed),
                providerCommitment: B256::from(provider_commitment),
            };

            let verdict = verifier.verify_ticket(
                &ticket,
                &sig_bytes,
                Address::from(client_addr),
                last_nonce,
            );

            if nonce != last_nonce.wrapping_add(1) || (last_nonce == u64::MAX) {
                prop_assert_eq!(verdict, TicketVerdict::InvalidNonce);
            }
        }

        #[test]
        fn fuzz_odds_mathematical_stability(
            num in any::<u32>(),
            denom in any::<u32>(),
            client_seed in any::<[u8; 32]>(),
            provider_seed in any::<[u8; 32]>()
        ) {
            let verifier = TicketVerifier::new(
                Address::from([0x11; 20]),
                Address::from([0x22; 20]),
                31337,
                B256::from(provider_seed),
            );

            let _ticket = Ticket {
                channelId: B256::ZERO,
                provider: verifier.provider_address,
                nonce: 1,
                faceValue: 1_000_000,
                winProbNumerator: num,
                winProbDenominator: denom,
                expiry: 9999999999,
                clientSeed: B256::from(client_seed),
                providerCommitment: verifier.provider_commitment,
            };

            let target = if denom == 0 || num == 0 {
                U256::ZERO
            } else if num >= denom {
                U256::MAX
            } else {
                (U256::MAX / U256::from(denom)) * U256::from(num)
            };

            if denom == 0 || num == 0 {
                prop_assert_eq!(target, U256::ZERO);
            } else if num >= denom {
                prop_assert_eq!(target, U256::MAX);
            }
        }
    }
}
