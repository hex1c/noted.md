use notedmd::config::Config;
use notedmd::encryption::{EncryptionData, EncryptionError, MasterPassword};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_config_migration() {
    // Create a temporary directory for config files
    let temp_dir = tempdir().unwrap();
    let config_path = temp_dir.path().join("config.toml");

    // Create a config with plaintext API key
    let plaintext_config = r#"
        active_provider = "gemini"
        
        [gemini]
        api_key = "plain-api-key-12345"
    "#;

    // Write the plaintext config
    fs::write(&config_path, plaintext_config).unwrap();

    // Load this config
    let mut config: Config = toml::from_str(plaintext_config).unwrap();

    // Check if it needs migration
    assert!(config.needs_migration());

    // Set up master password
    let master_password = "test_master_password";

    // Migrate the config
    config.migrate(master_password).unwrap();

    // Verify that the gemini API key is now encrypted
    let gemini_config = config.gemini.as_ref().unwrap();
    assert!(gemini_config.api_key.is_encrypted_format());

    // Decrypt and verify the original data is preserved
    let decrypted = gemini_config.api_key.decrypt(master_password).unwrap();
    assert_eq!(decrypted, "plain-api-key-12345");

    // Serialize and deserialize the config
    let serialized = toml::to_string(&config).unwrap();
    let deserialized_config: Config = toml::from_str(&serialized).unwrap();

    // Verify the deserialized config still has encrypted data
    let deserialized_gemini = deserialized_config.gemini.as_ref().unwrap();
    assert!(deserialized_gemini.api_key.is_encrypted_format());

    // Check it no longer needs migration
    assert!(!deserialized_config.needs_migration());
}

#[test]
fn test_multiple_provider_migration() {
    // Create a config with multiple plaintext API keys
    let plaintext_config = r#"
        active_provider = "claude"
        
        [gemini]
        api_key = "gemini-key-12345"
        
        [claude]
        api_key = "claude-key-67890"
        model = "claude-3-opus"
        
        [notion]
        api_key = "notion-key-abcdef"
        database_id = "notion-db-123"
    "#;

    // Load this config
    let mut config: Config = toml::from_str(plaintext_config).unwrap();

    // Check if it needs migration
    assert!(config.needs_migration());

    // Set up master password
    let master_password = "master_password_456";

    // Migrate the config
    config.migrate(master_password).unwrap();

    // Verify that all API keys are now encrypted
    let gemini_config = config.gemini.as_ref().unwrap();
    assert!(gemini_config.api_key.is_encrypted_format());

    let claude_config = config.claude.as_ref().unwrap();
    assert!(claude_config.api_key.is_encrypted_format());

    let notion_config = config.notion.as_ref().unwrap();
    assert!(notion_config.api_key.is_encrypted_format());

    // Decrypt and verify all original data is preserved
    let gemini_decrypted = gemini_config.api_key.decrypt(master_password).unwrap();
    assert_eq!(gemini_decrypted, "gemini-key-12345");

    let claude_decrypted = claude_config.api_key.decrypt(master_password).unwrap();
    assert_eq!(claude_decrypted, "claude-key-67890");

    let notion_decrypted = notion_config.api_key.decrypt(master_password).unwrap();
    assert_eq!(notion_decrypted, "notion-key-abcdef");
}

#[test]
fn test_wrong_password_decrypt_fails() {
    // Create a config with an API key
    let master_password = "correct_password";

    // Create encrypted API key
    let api_key = EncryptionData::new("secret-api-key", master_password).unwrap();

    // Try to decrypt with wrong password
    let result = api_key.decrypt("wrong_password");
    assert!(result.is_err());

    // Make sure it's the right error type
    match result {
        Err(EncryptionError::InvalidMasterPassword) => {}
        _ => panic!("Expected InvalidMasterPassword error"),
    }
}

#[test]
fn test_master_password_file_permissions() {
    // Only run this test on Unix-like systems where file permissions are relevant
    {
        use std::os::unix::fs::PermissionsExt;

        // Create a temporary directory
        let temp_dir = tempdir().unwrap();
        let config_dir = temp_dir.path();

        // Create master password
        let master_password = MasterPassword::new(config_dir);
        master_password.setup("test_password").unwrap();

        // Check that the master.key file exists
        let key_file = config_dir.join("master.key");
        assert!(key_file.exists());

        // Check file permissions (should be readable and writable only by owner)
        let metadata = fs::metadata(&key_file).unwrap();
        let permissions = metadata.permissions();

        // The file should not be readable by others
        let mode = permissions.mode();
        let is_world_readable = mode & 0o004 != 0;
        assert!(
            !is_world_readable,
            "Master key file should not be world-readable"
        );
    }
}

#[test]
fn test_empty_api_key_handling() {
    // Create a config with both empty and non-empty API keys
    let config_str = r#"
        active_provider = "claude"
        
        [gemini]
        api_key = ""
        
        [claude]
        api_key = "claude-key-67890"
        model = "claude-3-opus"
        
        [notion]
        api_key = ""
        database_id = "notion-db-123"
        
        [openai]
        url = "http://localhost:1234"
        model = "llama3"
    "#;

    // Load this config
    let mut config: Config = toml::from_str(config_str).unwrap();

    // Check if it needs migration (should be true due to Claude key)
    assert!(config.needs_migration());

    // Set up master password
    let master_password = "test_password";

    // Migrate the config
    config.migrate(master_password).unwrap();

    // Verify that empty API keys remain empty
    let gemini_config = config.gemini.as_ref().unwrap();
    assert!(gemini_config.api_key.is_empty());

    // Verify that non-empty API keys are encrypted
    let claude_config = config.claude.as_ref().unwrap();
    assert!(claude_config.api_key.is_encrypted_format());

    // Decrypt and verify the original Claude data is preserved
    let claude_decrypted = claude_config.api_key.decrypt(master_password).unwrap();
    assert_eq!(claude_decrypted, "claude-key-67890");

    // Empty API keys should not cause problems when migrating
    let notion_config = config.notion.as_ref().unwrap();
    assert!(notion_config.api_key.is_empty());

    // OpenAI with no API key should remain that way
    let openai_config = config.openai.as_ref().unwrap();
    assert!(openai_config.api_key.is_none());
}
