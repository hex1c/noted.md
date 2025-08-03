use async_trait::async_trait;
use crate::error::NotedError;
use serde::{Deserialize, Serialize};

pub mod file_storage;
pub mod notion_storage;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub original_path: String,
    pub file_name: String,
    pub title: String,
    pub output_path: Option<String>,
}

impl FileMetadata {
    pub fn new(original_path: String, output_path: Option<String>) -> Result<Self, NotedError> {
        let path = std::path::Path::new(&original_path);
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| NotedError::FileNameError(original_path.clone()))?
            .to_string();
        
        let title = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or(&file_name)
            .to_string();

        Ok(Self {
            original_path,
            file_name,
            title,
            output_path,
        })
    }
}

#[async_trait]
pub trait StorageProvider {
    async fn store(&self, content: &str, metadata: &FileMetadata) -> Result<String, NotedError>;
    fn provider_name(&self) -> &'static str;
    fn can_handle_content(&self, content: &str) -> Result<(), NotedError>;
}

pub fn create_storage_provider(
    storage_type: &str,
    config: &crate::config::Config,
    master_password: Option<&str>,
) -> Result<Box<dyn StorageProvider>, NotedError> {
    match storage_type {
        "file" => Ok(Box::new(file_storage::FileStorage::new())),
        "notion" => {
            if let Some(notion_config) = &config.notion {
                let api_key = if let Some(password) = master_password {
                    notion_config.api_key.decrypt(password)
                        .map_err(|e| NotedError::EncryptionError(e.to_string()))?
                } else {
                    return Err(NotedError::MasterPasswordRequired);
                };
                
                Ok(Box::new(notion_storage::NotionStorage::new(
                    api_key,
                    notion_config.database_id.clone(),
                    notion_config.title_property_name.clone(),
                    notion_config.properties.clone(),
                )))
            } else {
                Err(NotedError::ConfigurationError(
                    "Notion configuration not found".to_string(),
                ))
            }
        }
        _ => Err(NotedError::ConfigurationError(format!(
            "Unknown storage provider: {storage_type}"
        ))),
    }
}
