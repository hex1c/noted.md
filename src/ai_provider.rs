use crate::{error::NotedError, file_utils::FileData};
use async_trait::async_trait;
use reqwest::{Request, Response};

#[async_trait]
pub trait AiProvider {
    /// Get the default prompt for this provider
    fn get_default_prompt(&self) -> String;

    /// Get the API URL for this provider
    fn get_url(&self) -> String;

    /// Get default headers for this provider (API key is handled separately)
    fn get_default_headers(&self) -> Vec<(String, String)>;

    /// Check whether this provider can handle the given file
    fn can_handle_file(&self, file_data: &FileData) -> Result<(), NotedError>;

    /// Build a request to be called by a connection pooled client
    fn build_request(
        &self,
        model_info: &str,
        api_key: &str,
        file_data: &FileData,
        prompt: String,
    ) -> Result<Request, NotedError>;

    /// Handle response and return markdown to be saved to file
    async fn handle_response(&self, response: Response) -> Result<String, NotedError>;
}
