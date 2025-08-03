#[cfg(test)]
mod storage_integration_tests {
    use notedmd::storage::{FileMetadata, create_storage_provider};
    use notedmd::config::Config;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_file_storage_provider_creation() {
        let config = Config::default();
        let storage_provider = create_storage_provider("file", &config, None).unwrap();
        
        assert_eq!(storage_provider.provider_name(), "File System");
        assert!(storage_provider.can_handle_content("Test content").is_ok());
    }

    #[tokio::test]
    async fn test_file_storage_integration() {
        let temp_dir = TempDir::new().unwrap();
        let config = Config::default();
        let storage_provider = create_storage_provider("file", &config, None).unwrap();
        
        let metadata = FileMetadata::new(
            temp_dir.path().join("test.txt").to_string_lossy().to_string(),
            Some(temp_dir.path().to_string_lossy().to_string()),
        ).unwrap();

        let content = "# Test Content\n\nThis is a test markdown file.";
        
        let result = storage_provider.store(content, &metadata).await;
        assert!(result.is_ok());
        
        let output_path = result.unwrap();
        assert!(std::path::Path::new(&output_path).exists());
        
        let saved_content = std::fs::read_to_string(&output_path).unwrap();
        assert_eq!(saved_content, content);
    }

    #[tokio::test]
    async fn test_notion_storage_provider_creation_requires_config() {
        let config = Config::default(); // No notion config
        let result = create_storage_provider("notion", &config, None);
        
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("Notion configuration not found")),
            Ok(_) => panic!("Expected error but got success"),
        }
    }

    #[tokio::test]
    async fn test_unknown_storage_provider() {
        let config = Config::default();
        let result = create_storage_provider("unknown", &config, None);
        
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("Unknown storage provider")),
            Ok(_) => panic!("Expected error but got success"),
        }
    }
}
