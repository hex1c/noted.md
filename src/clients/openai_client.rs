use crate::{
    ai_provider::AiProvider,
    error::NotedError,
    file_utils::{FileData, FileType, ImageFormat},
};
use async_trait::async_trait;
use reqwest::{Client, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};

// Request structs

#[derive(Serialize)]
struct OpenAIRequest {
    model: String,
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
    image_url: Option<Image>,
}

#[derive(Serialize)]
struct Image {
    url: String,
}

// Response structs
#[derive(Deserialize, Debug)]
pub struct OpenAIResponse {
    pub choices: Vec<Choice>,

    #[serde(default)]
    pub error: Option<OpenAIError>,
}

#[derive(Deserialize, Debug)]
pub struct OpenAIError {
    pub message: String,
}

#[derive(Deserialize, Debug)]
pub struct Choice {
    pub message: ResponseMessage,
}

#[derive(Deserialize, Debug)]
pub struct ResponseMessage {
    pub content: String,
}

//Client
pub struct OpenAIClient {
    client: Client,
}

impl Default for OpenAIClient {
    fn default() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl OpenAIClient {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AiProvider for OpenAIClient {
    fn get_default_prompt(&self) -> String {
        "The user has provided an image of handwritten notes. Your task is to accurately transcribe these notes into a well-structured Markdown file. Preserve the original hierarchy, including headings and lists. Use LaTeX for any mathematical equations that appear in the notes. The output should only be the markdown content.".to_string()
    }

    fn get_url(&self) -> String {
        // This will be overridden with the actual URL from config
        "http://localhost:1234/v1/chat/completions".to_string()
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
                ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::Gif | ImageFormat::WebP => {
                    Ok(())
                }
            },
            FileType::Document(_) => Err(NotedError::UnsupportedFileTypeForProvider(
                "OpenAI".to_string(),
                "Document files".to_string(),
            )),
        }
    }

    fn build_request(
        &self,
        model_info: &str,
        api_key: &str,
        file_data: &FileData,
        prompt: String,
    ) -> Result<Request, NotedError> {
        // Extract URL from model_info which should be in format "url|model"
        let parts: Vec<&str> = model_info.split('|').collect();
        let (url, model) = if parts.len() == 2 {
            (format!("{}/v1/chat/completions", parts[0]), parts[1])
        } else {
            return Err(NotedError::ApiError(
                "Model info should be in format 'url|model'".to_string(),
            ));
        };

        let image_url = format!(
            "data:{};base64,{}",
            file_data.mime_type, file_data.encoded_data
        );

        let request_body = OpenAIRequest {
            model: model.to_string(),
            messages: vec![Message {
                role: "user".to_string(),
                content: vec![
                    Content {
                        content_type: "text".to_string(),
                        text: Some(prompt),
                        image_url: None,
                    },
                    Content {
                        content_type: "image_url".to_string(),
                        text: None,
                        image_url: Some(Image { url: image_url }),
                    },
                ],
            }],
        };

        let mut request_builder = self.client.post(&url);

        for (key, value) in self.get_default_headers() {
            request_builder = request_builder.header(key, value);
        }

        if !api_key.is_empty() {
            request_builder =
                request_builder.header("Authorization", format!("Bearer {api_key}"));
        }

        let request = request_builder
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

        let openai_response: OpenAIResponse = serde_json::from_str(&response_body)
            .map_err(|e| NotedError::ResponseDecodeError(e.to_string()))?;

        if let Some(error) = openai_response.error {
            return Err(NotedError::ApiError(error.message));
        }

        let markdown_text = openai_response
            .choices
            .first()
            .map(|c| c.message.content.as_str())
            .unwrap_or("");

        let cleaned_markdown = markdown_text
            .trim_start_matches("```markdown\n")
            .trim_end_matches("```");

        Ok(cleaned_markdown.to_string())
    }
}
