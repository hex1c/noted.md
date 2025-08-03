use crate::ai_provider::AiProvider;
use crate::error::NotedError;
use crate::file_utils::{DocumentFormat, FileData, FileType, ImageFormat};
use async_trait::async_trait;
use reqwest::{Client, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};

// Request structs

#[derive(Serialize)]
struct ClaudeRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<Message>,
}

#[derive(Serialize)]
struct Message {
    role: String,
    content: Vec<Content>,
}

#[derive(Serialize)]
struct Content {
    #[serde(rename = "type")]
    content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source: Option<Source>,
}

#[derive(Serialize)]
struct Source {
    #[serde(rename = "type")]
    source_type: String,
    media_type: String,
    data: String,
}

//  Response structs

#[derive(Deserialize, Debug)]
pub struct ClaudeResponse {
    pub content: Vec<ContentResponse>,
    #[serde(default)]
    pub error: Option<ClaudeError>,
}

#[derive(Deserialize, Debug)]
pub struct ClaudeError {
    pub message: String,
}

#[derive(Deserialize, Debug)]
pub struct ContentResponse {
    pub text: String,
}

// Client
pub struct ClaudeClient {
    client: Client,
}

impl Default for ClaudeClient {
    fn default() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl ClaudeClient {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AiProvider for ClaudeClient {
    fn get_default_prompt(&self) -> String {
        "Take the handwritten notes from this image and convert them into a clean, well-structured Markdown file. Pay attention to headings, lists, and any other formatting. Resemble the hierarchy. Use latex for mathematical equations. For latex use the $$ syntax instead of ```latex. Do not skip anything from the original text. The output should be suitable for use in Obsidian. Just give me the markdown, do not include other text in the response apart from the markdown file. No explanation on how the changes were made is needed".to_string()
    }

    fn get_url(&self) -> String {
        "https://api.anthropic.com/v1/messages".to_string()
    }

    fn get_default_headers(&self) -> Vec<(String, String)> {
        vec![
            ("anthropic-version".to_string(), "2023-06-01".to_string()),
            ("content-type".to_string(), "application/json".to_string()),
        ]
    }

    fn can_handle_file(&self, file_data: &FileData) -> Result<(), NotedError> {
        const MAX_SIZE_MB: u64 = 32;
        const MAX_SIZE_BYTES: u64 = MAX_SIZE_MB * 1024 * 1024;

        if file_data.file_size > MAX_SIZE_BYTES {
            return Err(NotedError::FileSizeExceeded(
                file_data.file_size / (1024 * 1024),
                MAX_SIZE_MB,
            ));
        }

        match &file_data.file_type {
            FileType::Image(format) => match format {
                ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif | ImageFormat::WebP => {
                    Ok(())
                }
            },
            FileType::Document(format) => match format {
                DocumentFormat::Pdf => Ok(()),
            },
        }
    }

    fn build_request(
        &self,
        model_info: &str,
        api_key: &str,
        file_data: &FileData,
        prompt: String,
    ) -> Result<Request, NotedError> {
        let file_type = match &file_data.file_type {
            FileType::Document(_) => "document".to_string(),
            FileType::Image(_) => "image".to_string(),
        };

        let request_body = ClaudeRequest {
            model: model_info.to_string(),
            max_tokens: 4096,
            messages: vec![Message {
                role: "user".to_string(),
                content: vec![
                    Content {
                        content_type: file_type,
                        text: None,
                        source: Some(Source {
                            source_type: "base64".to_string(),
                            media_type: file_data.mime_type.clone(),
                            data: file_data.encoded_data.clone(),
                        }),
                    },
                    Content {
                        content_type: "text".to_string(),
                        text: Some(prompt),
                        source: None,
                    },
                ],
            }],
        };

        let mut request = self.client.post(self.get_url());
        for (key, value) in self.get_default_headers() {
            request = request.header(key, value);
        }
        request
            .header("x-api-key", api_key)
            .json(&request_body)
            .build()
            .map_err(NotedError::NetworkError)
    }

    async fn handle_response(&self, response: Response) -> Result<String, NotedError> {
        let status = response.status();

        if status != StatusCode::OK {
            return match status {
                StatusCode::UNAUTHORIZED => Err(NotedError::InvalidApiKey),
                _ => Err(NotedError::ApiError(format!(
                    "Received status code: {status}"
                ))),
            };
        }

        let response_body = response.text().await?;

        let claude_response: ClaudeResponse = serde_json::from_str(&response_body)
            .map_err(|e| NotedError::ResponseDecodeError(e.to_string()))?;

        if let Some(error) = claude_response.error {
            return Err(NotedError::ApiError(error.message));
        }

        let markdown_text = claude_response
            .content
            .first()
            .map(|c| c.text.as_str())
            .unwrap_or("");

        let cleaned_markdown = markdown_text
            .trim_start_matches("```markdown\n")
            .trim_end_matches("```");

        Ok(cleaned_markdown.to_string())
    }
}
