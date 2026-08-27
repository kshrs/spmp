// Dev 3: Local Compute & LLM Stream Forwarder (Ollama / vLLM proxy)
use async_trait::async_trait;
use futures::{Stream, StreamExt};
use std::pin::Pin;

#[async_trait]
pub trait LLMBackend: Send + Sync {
    async fn generate_token_stream(
        &self,
        prompt: &str,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = String> + Send>>>;
}

pub struct OllamaClient {
    base_url: String, // e.g., "http://localhost:11434"
    model: String,    // e.g., "llama3"
    client: reqwest::Client,
}

impl OllamaClient {
    pub fn new(base_url: &str, model: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
            model: model.to_string(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl LLMBackend for OllamaClient {
    async fn generate_token_stream(
        &self,
        prompt: &str,
    ) -> anyhow::Result<Pin<Box<dyn Stream<Item = String> + Send>>> {
        let url = format!("{}/api/generate", self.base_url);
        
        // Format the payload for Ollama
        let payload = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": true
        });

        // Send request to local GPU / Ollama instance
        let response = self.client.post(&url).json(&payload).send().await?;

        // Map the incoming byte chunks into strings
        let stream = response.bytes_stream().map(|chunk| {
            match chunk {
                Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
                Err(_) => String::new(),
            }
        });

        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    struct MockBackend;

    #[async_trait]
    impl LLMBackend for MockBackend {
        async fn generate_token_stream(
            &self,
            _prompt: &str,
        ) -> anyhow::Result<Pin<Box<dyn Stream<Item = String> + Send>>> {
            // Simulates returning a token stream without needing an active GPU
            let s = stream::iter(vec!["Hello".to_string(), " world".to_string()]);
            Ok(Box::pin(s))
        }
    }

    #[tokio::test]
    async fn test_mock_backend_stream() {
        let backend = MockBackend;
        let mut stream = backend.generate_token_stream("test").await.unwrap();
        
        assert_eq!(stream.next().await, Some("Hello".to_string()));
        assert_eq!(stream.next().await, Some(" world".to_string()));
        assert_eq!(stream.next().await, None);
    }
}