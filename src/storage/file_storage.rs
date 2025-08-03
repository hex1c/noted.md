use async_trait::async_trait;
use std::fs;
use std::path::Path;
use crate::error::NotedError;
use super::{FileMetadata, StorageProvider};

pub struct FileStorage {}

impl FileStorage {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl StorageProvider for FileStorage {
    async fn store(&self, content: &str, metadata: &FileMetadata) -> Result<String, NotedError> {
        let output_path = match &metadata.output_path {
            Some(dir) => {
                let dir_path = Path::new(dir);
                if !dir_path.exists() {
                    fs::create_dir_all(dir_path)?;
                }
                let final_path = dir_path.join(&metadata.file_name);
                final_path
                    .with_extension("md")
                    .to_string_lossy()
                    .into_owned()
            }
            None => {
                let path = Path::new(&metadata.original_path);
                path.with_extension("md").to_string_lossy().into_owned()
            }
        };

        fs::write(&output_path, content)?;
        Ok(output_path)
    }

    fn provider_name(&self) -> &'static str {
        "File System"
    }

    fn can_handle_content(&self, _content: &str) -> Result<(), NotedError> {
        // File storage can handle any content
        Ok(())
    }
}

impl Default for FileStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_storage_with_output_dir() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path().join("output");
        
        let metadata = FileMetadata {
            original_path: "/test/file.txt".to_string(),
            file_name: "file.txt".to_string(),
            title: "file".to_string(),
            output_path: Some(output_dir.to_string_lossy().to_string()),
        };

        let storage = FileStorage::new();
        let content = "# Test Content\n\nThis is a test.";
        
        let result = storage.store(content, &metadata).await;
        assert!(result.is_ok());
        
        let output_path = result.unwrap();
        assert!(output_path.ends_with("file.md"));
        assert!(Path::new(&output_path).exists());
        
        let saved_content = fs::read_to_string(&output_path).unwrap();
        assert_eq!(saved_content, content);
    }

    #[tokio::test]
    async fn test_file_storage_without_output_dir() {
        let temp_dir = TempDir::new().unwrap();
        let original_path = temp_dir.path().join("test.txt");
        
        let metadata = FileMetadata {
            original_path: original_path.to_string_lossy().to_string(),
            file_name: "test.txt".to_string(),
            title: "test".to_string(),
            output_path: None,
        };

        let storage = FileStorage::new();
        let content = "# Test Content\n\nThis is a test.";
        
        let result = storage.store(content, &metadata).await;
        assert!(result.is_ok());
        
        let output_path = result.unwrap();
        assert!(output_path.ends_with("test.md"));
        assert!(Path::new(&output_path).exists());
        
        let saved_content = fs::read_to_string(&output_path).unwrap();
        assert_eq!(saved_content, content);
    }

    #[test]
    fn test_provider_name() {
        let storage = FileStorage::new();
        assert_eq!(storage.provider_name(), "File System");
    }

    #[test]
    fn test_can_handle_content() {
        let storage = FileStorage::new();
        assert!(storage.can_handle_content("any content").is_ok());
    }

    #[tokio::test]
    async fn test_file_metadata_creation() {
        let metadata = FileMetadata::new(
            "/path/to/test.txt".to_string(),
            Some("/output".to_string()),
        ).unwrap();

        assert_eq!(metadata.original_path, "/path/to/test.txt");
        assert_eq!(metadata.file_name, "test.txt");
        assert_eq!(metadata.title, "test");
        assert_eq!(metadata.output_path, Some("/output".to_string()));
    }

    #[tokio::test]
    async fn test_file_metadata_without_output() {
        let metadata = FileMetadata::new(
            "/path/to/test.txt".to_string(),
            None,
        ).unwrap();

        assert_eq!(metadata.original_path, "/path/to/test.txt");
        assert_eq!(metadata.file_name, "test.txt");
        assert_eq!(metadata.title, "test");
        assert_eq!(metadata.output_path, None);
    }
}
