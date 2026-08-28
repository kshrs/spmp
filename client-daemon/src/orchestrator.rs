// Developer 2 Module: Core Session Orchestrator
use alloy_primitives::B256;
use async_trait::async_trait;

#[async_trait]
pub trait TransportTrait: Send + Sync {
    fn get_provider_commitment(&self) -> B256;
    async fn send_ticket_and_prompt(
        &self,
        ticket: &crate::types::SignedTicket,
        prompt_chunk: &str,
    ) -> anyhow::Result<(String, bool)>;
}