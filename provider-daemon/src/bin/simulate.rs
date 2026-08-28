use alloy_primitives::{keccak256, Address, B256};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolStruct;
use provider_daemon::types::{GatekeeperDecision, Ticket, TicketVerdict, SECP256K1_N};
use provider_daemon::verifier::TicketVerifier;
use rand::Rng;
use std::collections::VecDeque;
use std::env;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let mut num = 1u32;
    let mut denom = 50u32; // Default SPMP micro-odds: 1/50 (2.0%)
    let mut face_value = 50_000u128; // $0.05 USDC
    let mut nonce = 1u64;
    let mut last_nonce = 0u64;
    let mut tamper_sig = false;
    let mut malleable_s = false;
    let mut tamper_nonce = false;
    let mut tamper_commitment = false;
    let mut expired = false;
    let mut iterations = 1usize;
    let mut run_variance_audit = false;
    let mut audit_tickets = 10_000usize;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--num" if i + 1 < args.len() => {
                num = args[i + 1].parse().unwrap_or(1);
                i += 1;
            }
            "--denom" if i + 1 < args.len() => {
                denom = args[i + 1].parse().unwrap_or(50);
                i += 1;
            }
            "--face-value" if i + 1 < args.len() => {
                face_value = args[i + 1].parse().unwrap_or(50_000);
                i += 1;
            }
            "--nonce" if i + 1 < args.len() => {
                nonce = args[i + 1].parse().unwrap_or(1);
                i += 1;
            }
            "--last-nonce" if i + 1 < args.len() => {
                last_nonce = args[i + 1].parse().unwrap_or(0);
                i += 1;
            }
            "--tamper-sig" => tamper_sig = true,
            "--malleable-s" => malleable_s = true,
            "--tamper-nonce" => tamper_nonce = true,
            "--tamper-commitment" => tamper_commitment = true,
            "--expired" => expired = true,
            "--iterations" if i + 1 < args.len() => {
                iterations = args[i + 1].parse().unwrap_or(1);
                i += 1;
            }
            "--variance-audit" | "--audit" => {
                run_variance_audit = true;
                if i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    audit_tickets = args[i + 1].parse().unwrap_or(10_000);
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("SPMP Fast Gatekeeper CLI Simulator & Variance Fact-Checker");
                println!("Usage: cargo run --bin simulate -- [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --variance-audit [N]    Execute live Binomial variance audit (default: 10,000 tickets)");
                println!("  --num <u32>             Probability numerator (default: 1)");
                println!("  --denom <u32>           Probability denominator (default: 50)");
                println!("  --face-value <u128>      Face value in micro-units (default: 50000 = $0.05)");
                println!("  --iterations <usize>    Run single-ticket benchmark loop for N trials (default: 1)");
                println!("  --malleable-s           Inject malleable high-s signature (EIP-2 attack vector)");
                println!("  --tamper-sig            Inject corrupted signature bytes");
                println!("  --tamper-nonce          Mutate nonce out-of-order");
                println!("  --tamper-commitment     Mutate provider commitment");
                println!("  --expired               Set ticket expiry in the past");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    if run_variance_audit {
        run_variance_and_governor_audit(num, denom, face_value, audit_tickets).await;
        return;
    }

    // Standard single/batch mode
    run_single_or_bench_mode(
        num,
        denom,
        face_value,
        nonce,
        last_nonce,
        tamper_sig,
        malleable_s,
        tamper_nonce,
        tamper_commitment,
        expired,
        iterations,
    )
    .await;
}

/// Executes the full 10,000-ticket live cryptographic Binomial variance audit & Client Governor simulation.
async fn run_variance_and_governor_audit(num: u32, denom: u32, face_value: u128, total_tickets: usize) {
    let mut rng = rand::thread_rng();
    let client_signer = PrivateKeySigner::random();
    let client_addr = client_signer.address();
    let provider_addr = Address::from([0x11; 20]);
    let contract_addr = Address::from([0x22; 20]);
    let chain_id = 31337u64;

    let mut provider_seed: [u8; 32] = rng.gen();
    let mut verifier = TicketVerifier::new(provider_addr, contract_addr, chain_id, B256::from(provider_seed));
    let channel_id = keccak256([client_addr.as_slice(), provider_addr.as_slice()].concat());

    let p = num as f64 / denom as f64;
    let expected_wins = total_tickets as f64 * p;
    let theoretical_std_dev = (total_tickets as f64 * p * (1.0 - p)).sqrt();

    println!("===================================================================================");
    println!("        SPMP FAST GATEKEEPER — DYNAMIC VARIANCE & CLIENT GOVERNOR AUDIT            ");
    println!("===================================================================================");
    println!("Protocol Parameters:");
    println!("  • Sample Size:                 {} streamed tickets", total_tickets);
    println!("  • Win Probability (p):         {}/{} ({:.4}%)", num, denom, p * 100.0);
    println!("  • Expected Mean Wins (μ):       {:.1} wins", expected_wins);
    println!("  • Theoretical Std Dev (σ):     {:.2} wins", theoretical_std_dev);
    println!("  • 99.7% Normal Range (μ ± 3σ): [{:.0}, {:.0}] wins", (expected_wins - 3.0 * theoretical_std_dev).max(0.0), expected_wins + 3.0 * theoretical_std_dev);
    println!("  • Face Value per Win:          ${:.4} USDC", face_value as f64 / 1_000_000.0);
    println!("  • Expected Micro-Cost / Chunk: ${:.5} USDC", (face_value as f64 / 1_000_000.0) * p);
    println!("-----------------------------------------------------------------------------------");
    println!("Executing live cryptographic evaluation with atomic seed rotation...");

    let start_time = Instant::now();

    let mut total_wins = 0usize;
    let mut total_losses = 0usize;
    let mut current_dry_spell = 0usize;
    let mut max_dry_spell = 0usize;

    // Client Governor Tracking (Sliding Window of 50 tickets)
    // Tracks the win history across a 50-ticket window
    let mut sliding_window: VecDeque<bool> = VecDeque::with_capacity(50);
    let mut window_wins = 0usize;
    let mut governor_triggers = 0usize;
    let mut governor_triggered_sessions = 0usize;

    for nonce in 1..=total_tickets as u64 {
        let client_seed: [u8; 32] = rng.gen();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let ticket = Ticket {
            channelId: channel_id,
            provider: provider_addr,
            nonce,
            faceValue: face_value,
            winProbNumerator: num,
            winProbDenominator: denom,
            expiry: now + 86400,
            clientSeed: B256::from(client_seed),
            providerCommitment: verifier.provider_commitment,
        };

        let digest = ticket.eip712_signing_hash(&verifier.domain);
        let signature = client_signer.sign_hash(&digest).await.unwrap();

        let decision = verifier.evaluate_and_gate(&ticket, signature.as_bytes().as_ref(), client_addr, nonce - 1);

        let is_win = match decision {
            GatekeeperDecision::ClaimAndRotateWinning => {
                total_wins += 1;
                // Atomic seed rotation post-win per SPMP protocol specification
                provider_seed = rng.gen();
                verifier.rotate_seed(B256::from(provider_seed));
                true
            }
            GatekeeperDecision::ServeLosing => {
                total_losses += 1;
                false
            }
            GatekeeperDecision::Reject(err) => {
                panic!("FATAL: Unexpected verifier rejection at nonce {}: {:?}", nonce, err);
            }
        };

        // Track Dry Spell (Consecutive Losses)
        if is_win {
            current_dry_spell = 0;
        } else {
            current_dry_spell += 1;
            if current_dry_spell > max_dry_spell {
                max_dry_spell = current_dry_spell;
            }
        }

        // Sliding Window for Client Budget Governor (2 wins in <=50 tickets)
        if sliding_window.len() == 50 && sliding_window.pop_front().unwrap() {
            window_wins -= 1;
        }
        sliding_window.push_back(is_win);
        if is_win {
            window_wins += 1;
        }

        // Check if Governor condition met
        if window_wins >= 2 {
            governor_triggers += 1;
            // Simulated client terminates stream when budget threshold exceeded
            governor_triggered_sessions += 1;
            sliding_window.clear();
            window_wins = 0;
        }
    }

    let elapsed = start_time.elapsed();
    let empirical_p = total_wins as f64 / total_tickets as f64;
    let avg_latency_micros = elapsed.as_micros() as f64 / total_tickets as f64;

    // Theoretical probability of 1,000 consecutive losses at 1/50 odds:
    // P(0 wins in 1000) = (1 - p)^1000 = (0.98)^1000 ≈ 1.6829e-9 (1 in 594 million)
    let p_1000_dry_spell = (1.0 - p).powi(1000);
    // Expected maximum run of losses in N trials: E[L_N] ≈ ln(N * p) / -ln(1 - p)
    let expected_max_dry_spell = (total_tickets as f64 * p).ln() / -(1.0 - p).ln();

    println!("-----------------------------------------------------------------------------------");
    println!("Empirical Audit Results (Live Cryptographic Engine):");
    println!("  • Total Executions:            {} tickets", total_tickets);
    println!("  • Total Winning Tickets:       {} jackpot payouts", total_wins);
    println!("  • Total Losing Tickets:        {} compute chunks", total_losses);
    println!("  • Measured Win Rate:           {:.4}% (Target: {:.4}%)", empirical_p * 100.0, p * 100.0);
    println!("  • Variance Deviation:          {:.2}σ from mean ({:+.1} wins)", (total_wins as f64 - expected_wins) / theoretical_std_dev, total_wins as f64 - expected_wins);
    println!("  • Total Verification Latency:  {:?} (Avg: {:.2} µs / ticket)", elapsed, avg_latency_micros);
    println!("-----------------------------------------------------------------------------------");
    println!("Variance Boundary & Governor Analysis:");
    println!("  • Longest Recorded Dry Spell:  {} consecutive losing tickets", max_dry_spell);
    println!("  • Expected Max Dry Spell:      ~{:.0} consecutive losing tickets", expected_max_dry_spell);
    println!("  • P(1,000-Ticket Dry Spell):   {:.4e} (1 in ~{:.0} million trials)", p_1000_dry_spell, 1.0 / p_1000_dry_spell / 1_000_000.0);
    println!("  • Client Governor Tripped:     {} times (Stream Terminated: 2 wins in <=50 tickets)", governor_triggered_sessions);
    println!("  • Governor Trip Rate:          {:.2}% of 50-ticket epochs", (governor_triggers as f64 / (total_tickets as f64 / 50.0)) * 100.0);
    println!("===================================================================================");
}

#[allow(clippy::too_many_arguments)]
async fn run_single_or_bench_mode(
    num: u32,
    denom: u32,
    face_value: u128,
    mut nonce: u64,
    last_nonce: u64,
    tamper_sig: bool,
    malleable_s: bool,
    tamper_nonce: bool,
    tamper_commitment: bool,
    expired: bool,
    iterations: usize,
) {
    if tamper_nonce {
        nonce = last_nonce + 99;
    }

    let provider_seed = B256::from([0x42; 32]);
    let provider_addr = Address::from([0x11; 20]);
    let contract_addr = Address::from([0x22; 20]);
    let chain_id = 31337u64;

    let mut verifier = TicketVerifier::new(provider_addr, contract_addr, chain_id, provider_seed);
    let client_signer = PrivateKeySigner::random();
    let client_addr = client_signer.address();

    let channel_id = keccak256([client_addr.as_slice(), provider_addr.as_slice()].concat());
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expiry_ts = if expired { now - 3600 } else { now + 86400 };

    let commitment = if tamper_commitment {
        B256::from([0xDE; 32])
    } else {
        verifier.provider_commitment
    };

    let ticket = Ticket {
        channelId: channel_id,
        provider: provider_addr,
        nonce,
        faceValue: face_value,
        winProbNumerator: num,
        winProbDenominator: denom,
        expiry: expiry_ts,
        clientSeed: B256::from([0x99; 32]),
        providerCommitment: commitment,
    };

    let digest = ticket.eip712_signing_hash(&verifier.domain);
    let signature = client_signer.sign_hash(&digest).await.unwrap();
    let mut sig_bytes = signature.as_bytes().to_vec();

    if malleable_s {
        let r = signature.r();
        let s = signature.s();
        let high_s = SECP256K1_N - s;
        let v = signature.v();
        let flipped_v = if v.y_parity() { 27 } else { 28 };

        sig_bytes = [0u8; 65].to_vec();
        sig_bytes[0..32].copy_from_slice(&r.to_be_bytes::<32>());
        sig_bytes[32..64].copy_from_slice(&high_s.to_be_bytes::<32>());
        sig_bytes[64] = flipped_v;
    } else if tamper_sig {
        sig_bytes[10] ^= 0xFF;
    }

    println!("==========================================================================");
    println!("  SPMP Fast Gatekeeper (Developer 2) Hardened Cryptographic Sandbox       ");
    println!("==========================================================================");
    println!("Parameters:");
    println!("  • Win Odds:             {}/{} ({:.4}%)", num, denom, if denom == 0 { 0.0 } else { (num as f64 / denom as f64) * 100.0 });
    println!("  • Client Signer:        {:?}", client_addr);
    println!("  • Provider Address:     {:?}", provider_addr);
    println!("  • Nonce:                {} (Watermark: {})", nonce, last_nonce);
    println!("  • Expiry:               {} (Expired: {})", expiry_ts, expired);
    println!("  • Low-S Non-Malleable:  {}", !malleable_s);
    println!("  • Tamper Signature:     {}", tamper_sig);
    println!("  • Tamper Commitment:    {}", tamper_commitment);
    println!("  • Iterations:           {}", iterations);
    println!("--------------------------------------------------------------------------");

    for _ in 0..5 {
        let _ = verifier.verify_ticket(&ticket, &sig_bytes, client_addr, last_nonce);
    }

    let start = Instant::now();
    let mut last_decision = GatekeeperDecision::Reject(TicketVerdict::InvalidNonce);
    for _ in 0..iterations {
        last_decision = verifier.evaluate_and_gate(&ticket, &sig_bytes, client_addr, last_nonce);
    }
    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

    println!("Execution Outcome:");
    println!("  • Gatekeeper Decision:  {:?}", last_decision);
    println!("  • Seed Invalidated:     {}", verifier.seed_invalidated);
    println!("  • Total Elapsed Time:   {:?}", elapsed);
    println!("  • Avg Latency / Ticket: {:.2} µs ({:.4} ms)", avg_micros, avg_micros / 1000.0);
    println!("  • SLA Performance:      {}", if avg_micros <= 250.0 { "PASSED (<=0.25ms)" } else { "FAILED (>0.25ms)" });
    println!("==========================================================================");
}
