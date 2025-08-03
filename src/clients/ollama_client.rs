use async_trait::async_trait;
use reqwest::{Client, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{
    ai_provider::AiProvider,
    error::NotedError,
    file_utils::{FileData, FileType, ImageFormat},
};

// Request struct
#[derive(Serialize)]
struct OllamaRequest {
    model: String,
    prompt: String,
    images: Vec<String>,
    stream: bool,
}

// Response struct
#[derive(Deserialize, Debug)]
pub struct OllamaResponse {
    pub response: String,
    #[serde(default)]
    pub error: Option<String>,
}

// Client struct
pub struct OllamaClient {
    client: Client,
}

impl Default for OllamaClient {
    fn default() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl OllamaClient {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AiProvider for OllamaClient {
    fn get_default_prompt(&self) -> String {
        "The user has provided an image of handwritten notes. Your task is to accurately transcribe these notes into a well-structured Markdown file. Preserve the original hierarchy, including headings and lists. Use LaTeX for any mathematical equations that appear in the notes. The output should only be the markdown content.".to_string()
    }

    fn get_url(&self) -> String {
        // This will be overridden with the actual URL from config
        "http://localhost:11434/api/generate".to_string()
    }

    fn get_default_headers(&self) -> Vec<(String, String)> {
        vec![("content-type".to_string(), "application/json".to_string())]
    }

    fn can_handle_file(&self, file_data: &FileData) -> Result<(), NotedError> {
        const MAX_SIZE_MB: u64 = 100;
        const MAX_SIZE_BYTES: u64 = MAX_SIZE_MB * 1024 * 1024;

        if file_data.file_size > MAX_SIZE_BYTES {
            return Err(NotedError::FileSizeExceeded(
                file_data.file_size / (1024 * 1024),
                MAX_SIZE_MB,
            ));
        }

        match &file_data.file_type {
            FileType::Image(format) => match format {
                ImageFormat::Png | ImageFormat::Jpeg => Ok(()),
                ImageFormat::Gif | ImageFormat::WebP => {
                    Err(NotedError::UnsupportedFileTypeForProvider(
                        "Ollama".to_string(),
                        format!("{format:?} images"),
                    ))
                }
            },
            FileType::Document(_) => Err(NotedError::UnsupportedFileTypeForProvider(
                "Ollama".to_string(),
                "Document files".to_string(),
            )),
        }
    }

    fn build_request(
        &self,
        model_info: &str,
        _api_key: &str, // Ollama doesn't use API keys
        file_data: &FileData,
        prompt: String,
    ) -> Result<Request, NotedError> {
        // Extract URL and model from model_info which should be in format "url|model"
        let parts: Vec<&str> = model_info.split('|').collect();
        let (url, model) = if parts.len() == 2 {
            (format!("{}/api/generate", parts[0]), parts[1])
        } else {
            return Err(NotedError::ApiError(
                "Model info should be in format 'url|model'".to_string(),
            ));
        };

        let request_body = OllamaRequest {
            model: model.to_string(),
            prompt,
            images: vec![file_data.encoded_data.clone()],
            stream: false,
        };

        let mut request = self.client.post(&url);

        for (key, value) in self.get_default_headers() {
            request = request.header(key, value);
        }

        let request = request
            .json(&request_body)
            .build()
            .map_err(NotedError::NetworkError)?;

        Ok(request)
    }

    async fn handle_response(&self, response: Response) -> Result<String, NotedError> {
        let status = response.status();

        if status != StatusCode::OK {
            return Err(NotedError::ApiError(format!(
                "Received status code: {status}"
            )));
        }

        let response_body = response.text().await?;

        let ollama_response: OllamaResponse = serde_json::from_str(&response_body)
            .map_err(|e| NotedError::ResponseDecodeError(e.to_string()))?;

        if let Some(error) = ollama_response.error {
            return Err(NotedError::ApiError(error));
        }

        let cleaned_markdown = ollama_response
            .response
            .trim_start_matches("```markdown\n")
            .trim_end_matches("```");

        Ok(cleaned_markdown.to_string())
    }
}
