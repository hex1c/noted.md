use crate::encryption::EncryptionData;
use crate::error::NotedError;
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Config {
    pub active_provider: Option<String>,
    pub gemini: Option<GeminiConfig>,
    pub ollama: Option<OllamaConfig>,
    pub claude: Option<ClaudeConfig>,
    pub openai: Option<OpenAIConfig>,
    pub notion: Option<NotionConfig>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct NotionConfig {
    pub api_key: EncryptionData,
    pub database_id: String,
    #[serde(default)]
    pub title_property_name: String,
    #[serde(default)]
    pub properties: Vec<NotionPropertyConfig>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct NotionPropertyConfig {
    pub name: String,
    pub property_type: String,
    pub default_value: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct ClaudeConfig {
    pub api_key: EncryptionData,
    pub model: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct GeminiConfig {
    pub api_key: EncryptionData,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct OllamaConfig {
    pub url: String,
    pub model: String,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct OpenAIConfig {
    pub url: String,
    pub model: String,
    pub api_key: Option<EncryptionData>,
}

pub fn get_config_path() -> Option<PathBuf> {
    ProjectDirs::from("com", "company", "notedmd").map(|dirs| {
        let config_dir = dirs.config_dir();
        if !config_dir.exists() {
            fs::create_dir_all(config_dir).ok();
        }
        config_dir.join("config.toml")
    })
}

pub fn get_config_dir() -> Option<PathBuf> {
    ProjectDirs::from("com", "company", "notedmd").map(|dirs| dirs.config_dir().to_path_buf())
}

impl Config {
    pub fn load() -> Result<Self, NotedError> {
        if let Some(config_path) = get_config_path() {
            if config_path.exists() {
                let content = fs::read_to_string(config_path)?;
                return Ok(toml::from_str(&content)?);
            }
        }
        Ok(Self::default())
    }

    pub fn save(&self) -> Result<(), NotedError> {
        if let Some(config_path) = get_config_path() {
            let toml_string = toml::to_string_pretty(self)?;
            fs::write(config_path, toml_string)?;
        }
        Ok(())
    }

    /// Check if the config contains any unencrypted API keys that need migration
    pub fn needs_migration(&self) -> bool {
        // Check each provider's API key to see if it needs migration
        // Only consider non-empty API keys that don't already have the encryption format
        if let Some(gemini) = &self.gemini {
            if !gemini.api_key.is_empty() && !gemini.api_key.is_encrypted_format() {
                return true;
            }
        }

        if let Some(claude) = &self.claude {
            if !claude.api_key.is_empty() && !claude.api_key.is_encrypted_format() {
                return true;
            }
        }

        if let Some(notion) = &self.notion {
            if !notion.api_key.is_empty() && !notion.api_key.is_encrypted_format() {
                return true;
            }
        }

        if let Some(openai) = &self.openai {
            if let Some(api_key) = &openai.api_key {
                if !api_key.is_empty() && !api_key.is_encrypted_format() {
                    return true;
                }
            }
        }

        false
    }

    /// Migrate plaintext API keys to encrypted format
    pub fn migrate(&mut self, master_password: &str) -> Result<(), NotedError> {
        use crate::encryption::EncryptionData;

        // Migrate Gemini API key
        if let Some(gemini) = &mut self.gemini {
            if !gemini.api_key.is_empty() && !gemini.api_key.is_encrypted_format() {
                gemini.api_key = EncryptionData::new(gemini.api_key.as_str(), master_password)
                    .map_err(|e| NotedError::EncryptionError(e.to_string()))?;
            }
        }

        // Migrate Claude API key
        if let Some(claude) = &mut self.claude {
            if !claude.api_key.is_empty() && !claude.api_key.is_encrypted_format() {
                claude.api_key = EncryptionData::new(claude.api_key.as_str(), master_password)
                    .map_err(|e| NotedError::EncryptionError(e.to_string()))?;
            }
        }

        // Migrate Notion API key
        if let Some(notion) = &mut self.notion {
            if !notion.api_key.is_empty() && !notion.api_key.is_encrypted_format() {
                notion.api_key = EncryptionData::new(notion.api_key.as_str(), master_password)
                    .map_err(|e| NotedError::EncryptionError(e.to_string()))?;
            }
        }

        // Migrate OpenAI API key if it exists
        if let Some(openai) = &mut self.openai {
            if let Some(api_key) = &openai.api_key {
                if !api_key.is_empty() && !api_key.is_encrypted_format() {
                    openai.api_key = Some(
                        EncryptionData::new(api_key.as_str(), master_password)
                            .map_err(|e| NotedError::EncryptionError(e.to_string()))?,
                    );
                }
            }
        }

        self.save()?;

        Ok(())
    }
}
