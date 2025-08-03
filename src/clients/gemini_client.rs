use crate::ai_provider::AiProvider;
use crate::error::NotedError;
use crate::file_utils::{DocumentFormat, FileData, FileType, ImageFormat};
use async_trait::async_trait;
use reqwest::{Client, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};

// Request structs

#[derive(Serialize)]
struct GeminiRequest {
    contents: Vec<Content>,
}

#[derive(Serialize)]
struct Content {
    parts: Vec<Part>,
}

#[derive(Serialize)]
struct Part {
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    inline_data: Option<InlineData>,
}

#[derive(Serialize)]
struct InlineData {
    #[serde(rename = "mimeType")]
    mime_type: String,
    data: String,
}

//  Response structs

#[derive(Deserialize, Debug)]
pub struct GeminiResponse {
    pub candidates: Option<Vec<Candidate>>,
    #[serde(default)]
    pub error: Option<GeminiError>,
}

#[derive(Deserialize, Debug)]
pub struct GeminiError {
    pub message: String,
}

#[derive(Deserialize, Debug)]
pub struct Candidate {
    pub content: ContentResponse,
}

#[derive(Deserialize, Debug)]
pub struct ContentResponse {
    pub parts: Vec<PartResponse>,
}

#[derive(Deserialize, Debug)]
pub struct PartResponse {
    pub text: String,
}

// Client
pub struct GeminiClient {
    client: Client,
}

impl Default for GeminiClient {
    fn default() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl GeminiClient {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AiProvider for GeminiClient {
    fn get_default_prompt(&self) -> String {
        "Take the handwritten notes from this image and convert them into a clean, well-structured Markdown file. Pay attention to headings, lists, and any other formatting. Resemble the hierarchy. Use latex for mathematical equations. For latex use the $$ syntax instead of ```latex. Do not skip anything from the original text. The output should be suitable for use in Obsidian. Just give me the markdown, do not include other text in the response apart from the markdown file. No explanation on how the changes were made is needed".to_string()
    }

    fn get_url(&self) -> String {
        "https://generativelanguage.googleapis.com/v1beta/models/gemma-3-27b-it:generateContent"
            .to_string()
    }

    fn get_default_headers(&self) -> Vec<(String, String)> {
        vec![("content-type".to_string(), "application/json".to_string())]
    }

    fn can_handle_file(&self, file_data: &FileData) -> Result<(), NotedError> {
        const MAX_SIZE_MB: u64 = 20;
        const MAX_SIZE_BYTES: u64 = MAX_SIZE_MB * 1024 * 1024;

        if file_data.file_size > MAX_SIZE_BYTES {
            return Err(NotedError::FileSizeExceeded(
                file_data.file_size / (1024 * 1024),
                MAX_SIZE_MB,
            ));
        }

        match &file_data.file_type {
            FileType::Image(format) => match format {
                ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP => Ok(()),
                ImageFormat::Gif => Err(NotedError::UnsupportedFileTypeForProvider(
                    "Gemini".to_string(),
                    "GIF images".to_string(),
                )),
            },
            FileType::Document(format) => match format {
                DocumentFormat::Pdf => Ok(()),
            },
        }
    }

    fn build_request(
        &self,
        _model_info: &str, // Gemini uses fixed model in URL
        api_key: &str,
        file_data: &FileData,
        prompt: String,
    ) -> Result<Request, NotedError> {
        let url = format!("{}?key={}", self.get_url(), api_key);

        let request_body = GeminiRequest {
            contents: vec![Content {
                parts: vec![
                    Part {
                        text: Some(prompt),
                        inline_data: None,
                    },
                    Part {
                        text: None,
                        inline_data: Some(InlineData {
                            mime_type: file_data.mime_type.clone(),
                            data: file_data.encoded_data.clone(),
                        }),
                    },
                ],
            }],
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
            return match status {
                StatusCode::UNAUTHORIZED => Err(NotedError::InvalidApiKey),
                _ => Err(NotedError::ApiError(format!(
                    "Received status code: {status}"
                ))),
            };
        }

        let response_body = response.text().await?;

        let gemini_response: GeminiResponse = serde_json::from_str(&response_body)
            .map_err(|e| NotedError::ResponseDecodeError(e.to_string()))?;

        if let Some(error) = gemini_response.error {
            return Err(NotedError::ApiError(error.message));
        }

        let markdown_text = gemini_response
            .candidates
            .as_ref()
            .and_then(|candidates| candidates.first())
            .and_then(|candidate| candidate.content.parts.first())
            .map(|part| part.text.as_str())
            .unwrap_or("");

        let cleaned_markdown = markdown_text
            .trim_start_matches("```markdown\n")
            .trim_end_matches("```");

        Ok(cleaned_markdown.to_string())
    }
}
