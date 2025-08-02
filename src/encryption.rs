use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng},
};
use anyhow::Result;
use argon2::{
    Argon2,
    password_hash::{SaltString, rand_core::RngCore},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Failed to encrypt data: {0}")]
    EncryptionFailure(String),

    #[error("Failed to decrypt data: {0}")]
    DecryptionFailure(String),

    #[error("Invalid encryption format")]
    InvalidFormat,

    #[error("Master password required")]
    MasterPasswordRequired,

    #[error("Invalid master password")]
    InvalidMasterPassword,
}

/// Struct to securely store sensitive data
/// Uses the format "SALT:NONCE:CIPHER_TEXT" for storage
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionData(String);

impl EncryptionData {
    /// Check if the data is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Create new encrypted data from plaintext using master password
    pub fn new(plaintext: &str, master_password: &str) -> Result<Self, EncryptionError> {
        // Don't encrypt empty strings, just store them as-is
        if plaintext.is_empty() {
            return Ok(Self("".to_string()));
        }

        let salt = SaltString::generate(&mut OsRng);

        // Derive key from password using Argon2
        let mut key = [0u8; 32]; // AES-256 needs 32 bytes
        Argon2::default()
            .hash_password_into(
                master_password.as_bytes(),
                salt.as_str().as_bytes(),
                &mut key,
            )
            .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12]; // AES-GCM standard nonce size
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;

        // Format as "SALT:NONCE:CIPHER_TEXT"
        let encrypted = format!(
            "{}:{}:{}",
            salt.as_str(),
            STANDARD.encode(nonce),
            STANDARD.encode(&ciphertext)
        );

        // Zeroize the key for security
        let mut key_to_zeroize = key;
        key_to_zeroize.zeroize();

        Ok(Self(encrypted))
    }

    /// Decrypt the data using the master password
    pub fn decrypt(&self, master_password: &str) -> Result<String, EncryptionError> {
        // Split the stored format "SALT:NONCE:CIPHER_TEXT"
        let parts: Vec<&str> = self.0.split(':').collect();
        if parts.len() != 3 {
            return Err(EncryptionError::InvalidFormat);
        }

        let salt = parts[0];
        let nonce_base64 = parts[1];
        let ciphertext_base64 = parts[2];

        // Derive key from password and salt
        let mut key = [0u8; 32];
        Argon2::default()
            .hash_password_into(master_password.as_bytes(), salt.as_bytes(), &mut key)
            .map_err(|e| EncryptionError::DecryptionFailure(e.to_string()))?;

        // Decode the nonce and ciphertext
        let nonce_bytes = STANDARD
            .decode(nonce_base64)
            .map_err(|e| EncryptionError::DecryptionFailure(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        if nonce.len() != 12 {
            return Err(EncryptionError::DecryptionFailure(
                "Invalid nonce size".to_string(),
            ));
        }

        let ciphertext = STANDARD
            .decode(ciphertext_base64)
            .map_err(|e| EncryptionError::DecryptionFailure(e.to_string()))?;

        // Decrypt the data
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| EncryptionError::DecryptionFailure(e.to_string()))?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| EncryptionError::InvalidMasterPassword)?;

        let result = String::from_utf8(plaintext)
            .map_err(|e| EncryptionError::DecryptionFailure(e.to_string()))?;

        // Zeroize the key for security
        let mut key_to_zeroize = key;
        key_to_zeroize.zeroize();

        Ok(result)
    }

    /// Check if this is encrypted data (has the correct format)
    pub fn is_encrypted_format(&self) -> bool {
        let parts: Vec<&str> = self.0.split(':').collect();
        parts.len() == 3
    }

    /// Get the raw encrypted data string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EncryptionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ENCRYPTED]")
    }
}

impl fmt::Display for EncryptionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[ENCRYPTED]")
    }
}

impl FromStr for EncryptionData {
    type Err = EncryptionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))
    }
}

impl Default for EncryptionData {
    fn default() -> Self {
        Self("".to_string())
    }
}

/// Handle for secure master password operations
pub struct MasterPassword {
    hash_file: Option<std::path::PathBuf>,
}

impl MasterPassword {
    pub fn new(config_dir: &std::path::Path) -> Self {
        let hash_file = config_dir.join("master.key");
        Self {
            hash_file: Some(hash_file),
        }
    }

    /// Check if master password is set up
    pub fn is_setup(&self) -> bool {
        if let Some(path) = &self.hash_file {
            path.exists()
        } else {
            false
        }
    }

    /// Set up a new master password
    pub fn setup(&self, password: &str) -> Result<(), EncryptionError> {
        if let Some(path) = &self.hash_file {
            let salt = SaltString::generate(&mut OsRng);

            let mut key = [0u8; 32];
            Argon2::default()
                .hash_password_into(password.as_bytes(), salt.as_str().as_bytes(), &mut key)
                .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;

            // Store a verification hash that we can check against later
            let hash = format!("{}:{}", salt, STANDARD.encode(key));

            // Create directory if it doesn't exist
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;
            }

            // Write the hash to the file
            std::fs::write(path, hash)
                .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;

            // Set secure permissions on Unix systems
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(path)
                    .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?
                    .permissions();

                // Set to 600 (read/write for owner only)
                perms.set_mode(0o600);
                std::fs::set_permissions(path, perms)
                    .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;
            }

            let mut key_to_zeroize = key;
            key_to_zeroize.zeroize();

            Ok(())
        } else {
            Err(EncryptionError::EncryptionFailure(
                "No hash file path configured".to_string(),
            ))
        }
    }

    /// Verify the master password
    pub fn verify(&self, password: &str) -> Result<bool, EncryptionError> {
        if let Some(path) = &self.hash_file {
            if !path.exists() {
                return Err(EncryptionError::MasterPasswordRequired);
            }

            let hash = std::fs::read_to_string(path)
                .map_err(|e| EncryptionError::DecryptionFailure(e.to_string()))?;

            let parts: Vec<&str> = hash.split(':').collect();
            if parts.len() != 2 {
                return Err(EncryptionError::InvalidFormat);
            }

            let salt = parts[0];
            let stored_key_base64 = parts[1];
            let stored_key = STANDARD
                .decode(stored_key_base64)
                .map_err(|e| EncryptionError::DecryptionFailure(e.to_string()))?;

            // Derive key from the provided password
            let mut key = [0u8; 32];
            Argon2::default()
                .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key)
                .map_err(|e| EncryptionError::DecryptionFailure(e.to_string()))?;

            let result = key.as_slice() == stored_key.as_slice();

            let mut key_to_zeroize = key;
            key_to_zeroize.zeroize();

            Ok(result)
        } else {
            Err(EncryptionError::DecryptionFailure(
                "No hash file path configured".to_string(),
            ))
        }
    }

    /// Reset the master password
    pub fn reset(&self) -> Result<(), EncryptionError> {
        if let Some(path) = &self.hash_file {
            if path.exists() {
                std::fs::remove_file(path)
                    .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;
            }
            Ok(())
        } else {
            Err(EncryptionError::EncryptionFailure(
                "No hash file path configured".to_string(),
            ))
        }
    }
}

/// Securely prompt for master password
pub fn prompt_for_master_password(is_setup: bool) -> Result<String, EncryptionError> {
    use dialoguer::{Password, theme::ColorfulTheme};

    let prompt = if is_setup {
        "Set your master password for encrypting sensitive data"
    } else {
        "Enter your master password"
    };

    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt(prompt)
        .interact()
        .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;

    if is_setup {
        // Confirm password for setup
        let confirm = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Confirm master password")
            .interact()
            .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;

        if password != confirm {
            return Err(EncryptionError::EncryptionFailure(
                "Passwords do not match".to_string(),
            ));
        }
    }

    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_encryption_data_new_and_decrypt() {
        let plaintext = "supersecretapikey123";
        let master_password = "masterpassword123";

        // Encrypt the data
        let encrypted = EncryptionData::new(plaintext, master_password).unwrap();

        // Verify format (SALT:NONCE:CIPHER_TEXT)
        let parts: Vec<&str> = encrypted.as_str().split(':').collect();
        assert_eq!(parts.len(), 3);

        // Decrypt and verify
        let decrypted = encrypted.decrypt(master_password).unwrap();
        assert_eq!(decrypted, plaintext);

        // Verify incorrect password fails
        let result = encrypted.decrypt("wrongpassword");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            EncryptionError::InvalidMasterPassword
        ));
    }

    #[test]
    fn test_encryption_data_format_check() {
        // Valid format
        let data = EncryptionData("salt:nonce:ciphertext".to_string());
        assert!(data.is_encrypted_format());

        // Invalid format
        let data = EncryptionData("plaintext".to_string());
        assert!(!data.is_encrypted_format());

        // Empty data
        let data = EncryptionData("".to_string());
        assert!(!data.is_encrypted_format());
    }

    #[test]
    fn test_master_password_setup_and_verify() {
        // Create a temporary directory for tests that is automatically cleaned up
        let temp_dir = tempdir().unwrap();
        let config_dir = temp_dir.path();

        // Create MasterPassword instance
        let master_password = MasterPassword::new(config_dir);

        // Initially no master password should be set up
        assert!(!master_password.is_setup());

        // Set up a master password
        let password = "testpassword123";
        master_password.setup(password).unwrap();

        // Check that setup worked
        assert!(master_password.is_setup());

        // Verify correct password
        assert!(master_password.verify(password).unwrap());

        // Verify incorrect password
        assert!(!master_password.verify("wrongpassword").unwrap());

        // Reset the master password
        master_password.reset().unwrap();

        // Check that reset worked
        assert!(!master_password.is_setup());
    }

    #[test]
    fn test_end_to_end_encryption_workflow() {
        // Set up a temporary directory for tests
        let temp_dir = tempdir().unwrap();
        let config_dir = temp_dir.path();
        let master_password_str = "master_password_123";

        // Create MasterPassword instance
        let master_password = MasterPassword::new(config_dir);
        master_password.setup(master_password_str).unwrap();

        // Encrypt some sensitive data
        let api_key = "api_key_12345";
        let encrypted_api_key = EncryptionData::new(api_key, master_password_str).unwrap();

        // Save and load the encrypted data (simulating config storage)
        let config_file = config_dir.join("test_config.txt");
        fs::write(&config_file, encrypted_api_key.as_str()).unwrap();

        // Later, read it back
        let stored_encrypted_data = fs::read_to_string(&config_file).unwrap();
        let loaded_encrypted_key = EncryptionData(stored_encrypted_data);

        // Verify the master password and decrypt
        assert!(master_password.verify(master_password_str).unwrap());
        let decrypted_api_key = loaded_encrypted_key.decrypt(master_password_str).unwrap();

        // Verify the decryption worked
        assert_eq!(decrypted_api_key, api_key);
    }

    #[test]
    fn test_debug_and_display_traits() {
        let sensitive_data = EncryptionData::new("secret", "password").unwrap();

        // Debug should output [ENCRYPTED], not the actual data
        let debug_output = format!("{:?}", sensitive_data);
        assert_eq!(debug_output, "[ENCRYPTED]");

        // Display should output [ENCRYPTED], not the actual data
        let display_output = format!("{}", sensitive_data);
        assert_eq!(display_output, "[ENCRYPTED]");

        // Make sure the actual data is not in either output
        assert!(!debug_output.contains("secret"));
        assert!(!display_output.contains("secret"));
    }

    #[test]
    fn test_encryption_data_is_empty() {
        // Empty data
        let data = EncryptionData("".to_string());
        assert!(data.is_empty());

        // Non-empty data
        let data = EncryptionData("some content".to_string());
        assert!(!data.is_empty());

        // Encrypted data is not empty
        let plaintext = "secret";
        let master_password = "password";
        let encrypted = EncryptionData::new(plaintext, master_password).unwrap();
        assert!(!encrypted.is_empty());
    }
}
