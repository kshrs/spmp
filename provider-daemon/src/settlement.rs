use crate::types::{ISPMPEscrow, Ticket};
use alloy_network::EthereumWallet;
use alloy_primitives::{Address, Bytes, B256};
use alloy_provider::ProviderBuilder;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Winning ticket task message sent across internal worker channels.
#[derive(Debug, Clone)]
pub struct ClaimTask {
    pub ticket: Ticket,
    pub signature: Vec<u8>,
    pub provider_seed: B256,
}

/// SettlementWorker manages the provider's on-chain wallet and submits
/// claimTicket transactions to the SPMPEscrow smart contract on Anvil or Sepolia.
pub struct SettlementWorker {
    contract_address: Address,
    wallet: EthereumWallet,
    provider_address: Address,
    rpc_url: String,
    task_rx: mpsc::Receiver<ClaimTask>,
}

impl SettlementWorker {
    /// Creates a new SettlementWorker instance with an on-chain signing wallet.
    pub fn new(
        rpc_url: &str,
        contract_address: Address,
        private_key_hex: &str,
        task_rx: mpsc::Receiver<ClaimTask>,
    ) -> Result<Self> {
        let clean_key = private_key_hex
            .strip_prefix("0x")
            .unwrap_or(private_key_hex);
        let signer: PrivateKeySigner = clean_key
            .parse()
            .context("Failed to parse provider private key for settlement")?;

        let provider_address = signer.address();
        let wallet = EthereumWallet::from(signer);

        Ok(Self {
            contract_address,
            wallet,
            provider_address,
            rpc_url: rpc_url.to_string(),
            task_rx,
        })
    }

    /// Returns the Ethereum address of the provider settlement wallet.
    pub fn provider_address(&self) -> Address {
        self.provider_address
    }

    /// Core background loop: listens for winning tickets on the queue,
    /// formats the on-chain call, and submits the claim transaction.
    pub async fn run(mut self) {
        info!(
            provider = ?self.provider_address,
            contract = ?self.contract_address,
            "SPMP Settlement Worker initialized and listening for winning tickets..."
        );

        // Build Alloy HTTP Provider connected to RPC (Anvil / Sepolia)
        let url: reqwest::Url = match self.rpc_url.parse() {
            Ok(u) => u,
            Err(e) => {
                error!(error = ?e, "Invalid RPC URL for settlement worker");
                return;
            }
        };

        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(self.wallet.clone())
            .on_http(url);

        let provider = Arc::new(provider);
        let contract = ISPMPEscrow::new(self.contract_address, provider.clone());

        // Process incoming winning tickets from the in-memory queue
        while let Some(task) = self.task_rx.recv().await {
            info!(
                nonce = task.ticket.nonce,
                channel = ?task.ticket.channelId,
                face_value = task.ticket.faceValue,
                "Submitting claimTicket transaction to EVM..."
            );

            let sig_bytes = Bytes::from(task.signature);

            let call_builder = contract.claimTicket(
                task.ticket.clone(),
                sig_bytes,
                task.provider_seed,
            );

            match call_builder.send().await {
                Ok(pending_tx) => {
                    info!(
                        pending_hash = ?pending_tx.tx_hash(),
                        "claimTicket broadcast successfully, awaiting confirmation..."
                    );

                    match pending_tx.watch().await {
                        Ok(tx_hash) => {
                            info!(
                                tx_hash = ?tx_hash,
                                nonce = task.ticket.nonce,
                                "Claim confirmed on-chain! Payout transferred."
                            );
                        }
                        Err(e) => {
                            error!(
                                error = ?e,
                                nonce = task.ticket.nonce,
                                "Failed waiting for claim receipt"
                            );
                        }
                    }
                }
                Err(e) => {
                    error!(
                        error = ?e,
                        nonce = task.ticket.nonce,
                        "Failed to submit claimTicket transaction"
                    );
                }
            }
        }

        warn!("Settlement worker channel closed. Exiting loop.");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const TEST_PROVIDER_KEY: &str =
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"; // Anvil Account #1
    const TEST_CONTRACT: Address = address!("5FbDB2315678afecb367f032d93F642f64180aa3");
    const TEST_RPC: &str = "http://127.0.0.1:8545";

    #[tokio::test]
    async fn test_settlement_worker_initialization() {
        let (_tx, rx) = mpsc::channel(10);
        let worker = SettlementWorker::new(TEST_RPC, TEST_CONTRACT, TEST_PROVIDER_KEY, rx)
            .expect("Failed to initialize SettlementWorker");

        assert_eq!(
            worker.provider_address(),
            address!("70997970C51812dc3A010C7d01b50e0d17dc79C8") // Anvil Account #1 Address
        );
    }
}
