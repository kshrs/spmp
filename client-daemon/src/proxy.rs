//! Developer 1: inbound OpenAI-compatible HTTP proxy.

use std::{convert::Infallible, sync::Arc};

use async_stream::stream;
use axum::{
    body::Body,
    extract::{Json, State},
    http::{header, HeaderValue, Response},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use serde::Deserialize;
use tokio::{net::TcpListener, sync::mpsc};

pub trait EngineTrait: Send + Sync {
    async fn stream_inference(
        &self,
        prompt: String,
        token_tx: mpsc::Sender<String>,
    ) -> anyhow::Result<()>;
}

pub struct ProxyServer<E: EngineTrait> {
    addr: String,
    engine: Arc<E>,
}

impl<E: EngineTrait + 'static> ProxyServer<E> {
    pub fn new(addr: &str, engine: E) -> Self {
        Self {
            addr: addr.into(),
            engine: Arc::new(engine),
        }
    }

    pub async fn start(self) -> anyhow::Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        axum::serve(listener, router(self.engine)).await?;
        Ok(())
    }
}

#[derive(Deserialize)]
struct ChatCompletionRequest {
    messages: Vec<ChatMessage>,
}

#[derive(Deserialize)]
struct ChatMessage {
    content: String,
}

fn router<E: EngineTrait + 'static>(engine: Arc<E>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/chat/completions", post(chat_completions::<E>))
        .with_state(engine)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

async fn chat_completions<E: EngineTrait + 'static>(
    State(engine): State<Arc<E>>,
    Json(request): Json<ChatCompletionRequest>,
) -> Response<Body> {
    let prompt = request
        .messages
        .into_iter()
        .map(|message| message.content)
        .collect::<Vec<_>>()
        .join("\n");
    let (token_tx, mut token_rx) = mpsc::channel(32);

    tokio::spawn(async move {
        if let Err(error) = engine.stream_inference(prompt, token_tx).await {
            tracing::warn!(%error, "inference stream failed");
        }
    });

    let body = Body::from_stream(stream! {
        while let Some(token) = token_rx.recv().await {
            let chunk = serde_json::json!({ "choices": [{ "delta": { "content": token } }] });
            yield Ok::<_, Infallible>(Bytes::from(format!("data: {chunk}\n\n")));
        }
        yield Ok(Bytes::from("data: [DONE]\n\n"));
    });

    Response::builder()
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/event-stream"),
        )
        .header(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"))
        .body(body)
        .expect("static SSE response headers are valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockEngine;

    impl EngineTrait for MockEngine {
        async fn stream_inference(
            &self,
            _prompt: String,
            token_tx: mpsc::Sender<String>,
        ) -> anyhow::Result<()> {
            token_tx.send("Hello".into()).await?;
            token_tx.send(" world!".into()).await?;
            Ok(())
        }
    }

    #[tokio::test]
    async fn streams_openai_sse_chunks_and_done_marker() {
        let response = chat_completions::<MockEngine>(
            State(Arc::new(MockEngine)),
            Json(ChatCompletionRequest {
                messages: vec![ChatMessage {
                    content: "Say hello".into(),
                }],
            }),
        )
        .await;
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();

        assert!(body.contains(r#"data: {"choices":[{"delta":{"content":"Hello"}}]}"#));
        assert!(body.contains(r#"data: {"choices":[{"delta":{"content":" world!"}}]}"#));
        assert!(body.ends_with("data: [DONE]\n\n"));
    }
}
