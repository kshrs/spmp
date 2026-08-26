use alloy_primitives::{keccak256, Address, B256};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use alloy_sol_types::SolStruct;
use provider_daemon::types::Ticket;
use provider_daemon::verifier::TicketVerifier;
use std::env;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    let mut num = 1u32;
    let mut denom = 1000u32;
    let mut face_value = 1_000_000u128;
    let mut nonce = 1u64;
    let mut last_nonce = 0u64;
    let mut tamper_sig = false;
    let mut tamper_nonce = false;
    let mut tamper_commitment = false;
    let mut expired = false;
    let mut iterations = 1usize;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--num" if i + 1 < args.len() => {
                num = args[i + 1].parse().unwrap_or(1);
                i += 1;
            }
            "--denom" if i + 1 < args.len() => {
                denom = args[i + 1].parse().unwrap_or(1000);
                i += 1;
            }
            "--face-value" if i + 1 < args.len() => {
                face_value = args[i + 1].parse().unwrap_or(1_000_000);
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
            "--tamper-nonce" => tamper_nonce = true,
            "--tamper-commitment" => tamper_commitment = true,
            "--expired" => expired = true,
            "--iterations" if i + 1 < args.len() => {
                iterations = args[i + 1].parse().unwrap_or(1);
                i += 1;
            }
            "--help" | "-h" => {
                println!("SPMP Fast Gatekeeper CLI Simulator");
                println!("Usage: cargo run --bin simulate -- [OPTIONS]");
                println!();
                println!("Options:");
                println!("  --num <u32>             Probability numerator (default: 1)");
                println!("  --denom <u32>           Probability denominator (default: 1000)");
                println!("  --face-value <u128>      Face value in micro-units (default: 1000000)");
                println!("  --nonce <u64>           Ticket sequence nonce (default: 1)");
                println!("  --last-nonce <u64>      Verifier session watermark (default: 0)");
                println!("  --tamper-sig            Inject corrupt signature bytes");
                println!("  --tamper-nonce          Mutate nonce out-of-order");
                println!("  --tamper-commitment     Mutate provider commitment");
                println!("  --expired               Set ticket expiry in the past");
                println!("  --iterations <usize>    Run benchmark loop for N trials (default: 1)");
                return;
            }
            _ => {}
        }
        i += 1;
    }

    if tamper_nonce {
        nonce = last_nonce + 99;
    }

    let provider_seed = B256::from([0x42; 32]);
    let provider_addr = Address::from([0x11; 20]);
    let contract_addr = Address::from([0x22; 20]);
    let chain_id = 31337u64;

    let verifier = TicketVerifier::new(provider_addr, contract_addr, chain_id, provider_seed);
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

    if tamper_sig {
        sig_bytes[10] ^= 0xFF; // Invalidate signature byte
    }

    println!("==========================================================================");
    println!("  SPMP Fast Gatekeeper (Developer 2) Cryptographic Verification Sandbox   ");
    println!("==========================================================================");
    println!("Parameters:");
    println!("  • Win Odds:             {}/{} ({:.4}%)", num, denom, (num as f64 / denom.max(1) as f64) * 100.0);
    println!("  • Client Signer:        {:?}", client_addr);
    println!("  • Provider Address:     {:?}", provider_addr);
    println!("  • Nonce:                {} (Watermark: {})", nonce, last_nonce);
    println!("  • Expiry:               {} (Expired: {})", expiry_ts, expired);
    println!("  • Tamper Signature:     {}", tamper_sig);
    println!("  • Tamper Commitment:    {}", tamper_commitment);
    println!("  • Iterations:           {}", iterations);
    println!("--------------------------------------------------------------------------");

    // Warm-up iteration to stabilize instruction cache
    for _ in 0..5 {
        let _ = verifier.verify_ticket(&ticket, &sig_bytes, client_addr, last_nonce);
    }

    // Timed benchmark loop
    let start = Instant::now();
    let mut last_verdict = provider_daemon::types::TicketVerdict::InvalidNonce;
    for _ in 0..iterations {
        last_verdict = verifier.verify_ticket(&ticket, &sig_bytes, client_addr, last_nonce);
    }
    let elapsed = start.elapsed();
    let avg_micros = elapsed.as_micros() as f64 / iterations as f64;

    println!("Execution Outcome:");
    println!("  • Ticket Verdict:       {:?}", last_verdict);
    println!("  • Total Elapsed Time:   {:?}", elapsed);
    println!("  • Avg Latency / Ticket: {:.2} µs ({:.4} ms)", avg_micros, avg_micros / 1000.0);
    println!("  • SLA Performance:      {}", if avg_micros < 500.0 { "PASSED (<0.5ms)" } else { "FAILED (>0.5ms)" });
    println!("==========================================================================");
}
