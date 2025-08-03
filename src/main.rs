mod ai_provider;
mod cli;
mod clients;
mod config;
mod encryption;
mod error;
mod file_utils;
mod notion;
mod ui;

use ai_provider::AiProvider;
use clap::Parser;
use cli::{Cli, Commands};
use colored::*;
use config::{ClaudeConfig, Config, GeminiConfig, OllamaConfig};
use dialoguer::Confirm;
use dialoguer::Input;
use dialoguer::MultiSelect;
use dialoguer::Select;
use dialoguer::{Password, theme::ColorfulTheme};
use encryption::{EncryptionData, MasterPassword, prompt_for_master_password};
use error::NotedError;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;

use crate::clients::claude_client::ClaudeClient;
use crate::clients::gemini_client::GeminiClient;
use crate::clients::notion_client::NotionClient;
use crate::clients::notion_client::PropertyType;
use crate::clients::ollama_client::OllamaClient;
use crate::clients::openai_client::OpenAIClient;
use crate::config::NotionConfig;
use crate::config::OpenAIConfig;
use std::path::Path;
use ui::{ascii_art, print_clean_config};

use crate::config::get_config_path;

async fn process_file_with_ai(
    file_path: &str,
    client: &dyn AiProvider,
    model_info: &str,
    api_key: &str,
    custom_prompt: Option<String>,
    progress_bar: &ProgressBar,
) -> Result<String, NotedError> {
    let path = Path::new(file_path);
    let file_name = match path.file_name() {
        Some(name) => name,
        None => {
            return Err(NotedError::FileNameError(file_path.to_string()));
        }
    };

    progress_bar.println(format!(
        "\n{}",
        format!("Processing file: {file_name:#?}").bold()
    ));

    let file_data = file_utils::process_file(file_path)?;
    progress_bar.println(format!(
        "{} {}",
        "✔".green(),
        "File read successfully.".green()
    ));

    // Check if the provider can handle this file type
    client.can_handle_file(&file_data)?;

    progress_bar.set_message(format!("{}", "Sending to your AI model...".yellow()));

    let prompt = custom_prompt.unwrap_or_else(|| client.get_default_prompt());

    // Build the request
    let request = client.build_request(model_info, api_key, &file_data, prompt)?;

    // Send the request using a connection pooled client
    let http_client = reqwest::Client::new();
    let response = http_client.execute(request).await?;

    // Handle the response
    let markdown = client.handle_response(response).await?;
    progress_bar.println(format!("{} {}", "✔".green(), "Received response.".green()));

    Ok(markdown)
}

async fn save_file_and_notion(
    file_path: &str,
    markdown: &str,
    output_dir: Option<&str>,
    progress_bar: &ProgressBar,
    notion_client: Option<&NotionClient>,
    notion_config: Option<&NotionConfig>,
) -> Result<(), NotedError> {
    let path = Path::new(file_path);
    let file_name = match path.file_name() {
        Some(name) => name,
        None => {
            return Err(NotedError::FileNameError(file_path.to_string()));
        }
    };

    let output_path = match output_dir {
        Some(dir) => {
            let dir_path = Path::new(dir);
            if !dir_path.exists() {
                std::fs::create_dir_all(dir_path)?;
            }
            let final_path = dir_path.join(file_name);
            final_path
                .with_extension("md")
                .to_string_lossy()
                .into_owned()
        }
        None => path.with_extension("md").to_string_lossy().into_owned(),
    };

    match std::fs::write(&output_path, markdown) {
        Ok(_) => {
            progress_bar.println(format!(
                "{} {}",
                "✔".green(),
                format!("Markdown saved to '{}'", output_path.cyan()).green()
            ));
            if let (Some(client), Some(config)) = (notion_client, notion_config) {
                match client
                    .create_notion_page(
                        file_name.to_string_lossy().into_owned().as_str(),
                        &config.title_property_name,
                        &config.properties,
                        markdown,
                    )
                    .await
                {
                    Ok(page) => {
                        progress_bar.println(format!(
                            "{} {}",
                            "✔".green(),
                            format!("Notion page created at '{}'", page.url.cyan()).green()
                        ));
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            };
            Ok(())
        }
        Err(e) => {
            progress_bar.println(format!(
                "{} {}",
                "✖".red(),
                format!("Failed to save file to '{}'. Error: {}", &output_path, e).red()
            ));
            Err(e.into())
        }
    }
}

/// Verify or set up the master password as needed
async fn ensure_master_password(
    require_master_password: bool,
) -> Result<Option<String>, NotedError> {
    if let Some(config_dir) = config::get_config_dir() {
        let master_password = MasterPassword::new(&config_dir);

        // Check if master password is already set up
        if master_password.is_setup() {
            // If master password is set, prompt for it and verify
            let password = prompt_for_master_password(false)
                .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

            if master_password
                .verify(&password)
                .map_err(|e| NotedError::EncryptionError(e.to_string()))?
            {
                return Ok(Some(password));
            } else {
                return Err(NotedError::InvalidMasterPassword);
            }
        } else if require_master_password {
            // If master password is required but not set, prompt to set it up
            println!("{}", "No master password set. You need to set up a master password to secure your configuration.".yellow());

            let password = prompt_for_master_password(true)
                .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

            master_password
                .setup(&password)
                .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

            println!("{}", "Master password set up successfully.".green());
            return Ok(Some(password));
        }
    }

    Ok(None)
}

/// Check if the configuration needs migration and warn the user
fn check_config_migration(config: &Config) -> Result<(), NotedError> {
    if config.needs_migration() {
        return Err(NotedError::MigrationRequired(
            "Configuration contains unencrypted API keys. Please run 'notedmd security --migrate' to encrypt them."
                .to_string()
        ));
    }
    Ok(())
}

async fn run() -> Result<(), NotedError> {
    let args = Cli::parse();
    let mut config = Config::load()?;

    match args.command {
        Commands::Security {
            change_master_password,
            reset,
            migrate,
        } => {
            if reset {
                println!("{}", "WARNING: This will reset your master password and all encrypted data will be lost.".red());
                if Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Are you sure you want to continue?")
                    .default(false)
                    .interact()?
                {
                    if let Some(config_dir) = config::get_config_dir() {
                        let master_password = MasterPassword::new(&config_dir);
                        master_password
                            .reset()
                            .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                        // Clear all encrypted fields
                        if let Some(gemini) = &mut config.gemini {
                            gemini.api_key = EncryptionData::default();
                        }

                        if let Some(claude) = &mut config.claude {
                            claude.api_key = EncryptionData::default();
                        }

                        if let Some(notion) = &mut config.notion {
                            notion.api_key = EncryptionData::default();
                        }

                        if let Some(openai) = &mut config.openai {
                            openai.api_key = None;
                        }

                        config.save()?;

                        println!(
                            "{}",
                            "Master password reset. All encrypted data has been cleared.".green()
                        );
                    }
                }
            } else if change_master_password {
                if let Some(config_dir) = config::get_config_dir() {
                    let master_password = MasterPassword::new(&config_dir);

                    if master_password.is_setup() {
                        // Verify current password first
                        let current_password = prompt_for_master_password(false)
                            .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                        if !master_password
                            .verify(&current_password)
                            .map_err(|e| NotedError::EncryptionError(e.to_string()))?
                        {
                            return Err(NotedError::InvalidMasterPassword);
                        }

                        // Get and decrypt all API keys
                        let mut api_keys = Vec::new();

                        if let Some(gemini) = &config.gemini {
                            if !gemini.api_key.is_empty() && gemini.api_key.is_encrypted_format() {
                                api_keys.push((
                                    "gemini",
                                    gemini
                                        .api_key
                                        .decrypt(&current_password)
                                        .map_err(|e| NotedError::EncryptionError(e.to_string()))?,
                                ));
                            }
                        }

                        if let Some(claude) = &config.claude {
                            if !claude.api_key.is_empty() && claude.api_key.is_encrypted_format() {
                                api_keys.push((
                                    "claude",
                                    claude
                                        .api_key
                                        .decrypt(&current_password)
                                        .map_err(|e| NotedError::EncryptionError(e.to_string()))?,
                                ));
                            }
                        }

                        if let Some(notion) = &config.notion {
                            if !notion.api_key.is_empty() && notion.api_key.is_encrypted_format() {
                                api_keys.push((
                                    "notion",
                                    notion
                                        .api_key
                                        .decrypt(&current_password)
                                        .map_err(|e| NotedError::EncryptionError(e.to_string()))?,
                                ));
                            }
                        }

                        if let Some(openai) = &config.openai {
                            if let Some(api_key) = &openai.api_key {
                                if !api_key.is_empty() && api_key.is_encrypted_format() {
                                    api_keys.push((
                                        "openai",
                                        api_key.decrypt(&current_password).map_err(|e| {
                                            NotedError::EncryptionError(e.to_string())
                                        })?,
                                    ));
                                }
                            }
                        }

                        // Set up new password
                        println!("{}", "Setting new master password".yellow());
                        let new_password = prompt_for_master_password(true)
                            .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                        master_password
                            .setup(&new_password)
                            .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                        // Re-encrypt all API keys with new password
                        for (provider, key) in api_keys {
                            match provider {
                                "gemini" => {
                                    if let Some(gemini) = &mut config.gemini {
                                        gemini.api_key = EncryptionData::new(&key, &new_password)
                                            .map_err(|e| {
                                            NotedError::EncryptionError(e.to_string())
                                        })?;
                                    }
                                }
                                "claude" => {
                                    if let Some(claude) = &mut config.claude {
                                        claude.api_key = EncryptionData::new(&key, &new_password)
                                            .map_err(|e| {
                                            NotedError::EncryptionError(e.to_string())
                                        })?;
                                    }
                                }
                                "notion" => {
                                    if let Some(notion) = &mut config.notion {
                                        notion.api_key = EncryptionData::new(&key, &new_password)
                                            .map_err(|e| {
                                            NotedError::EncryptionError(e.to_string())
                                        })?;
                                    }
                                }
                                "openai" => {
                                    if let Some(openai) = &mut config.openai {
                                        if openai.api_key.is_some() {
                                            openai.api_key = Some(
                                                EncryptionData::new(&key, &new_password).map_err(
                                                    |e| NotedError::EncryptionError(e.to_string()),
                                                )?,
                                            );
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }

                        config.save()?;
                        println!("{}", "Master password changed successfully.".green());
                    } else {
                        // No master password set yet, just set a new one
                        println!(
                            "{}",
                            "No master password set yet. Setting up new master password.".yellow()
                        );
                        let new_password = prompt_for_master_password(true)
                            .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                        master_password
                            .setup(&new_password)
                            .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                        println!("{}", "Master password set up successfully.".green());
                    }
                }
            } else if migrate {
                let mut config = Config::load()?;

                if !config.needs_migration() {
                    println!(
                        "{}",
                        "No migration needed. All API keys are already in encrypted format."
                            .green()
                    );
                    return Ok(());
                }

                // Set up master password if not already set
                let master_password = ensure_master_password(true)
                    .await?
                    .ok_or(NotedError::MasterPasswordRequired)?;

                println!(
                    "{}",
                    "Migrating configuration to encrypted format...".yellow()
                );
                config.migrate(&master_password)?;

                println!("{}", "Migration completed successfully.".green());
            } else {
                println!(
                    "Please specify a security command. Run with --help for more information."
                );
            }
        }
        Commands::Config {
            set_api_key,
            set_claude_api_key,
            set_provider,
            show_path,
            show,
            edit,
        } => {
            if show_path {
                if let Some(config_path) = config::get_config_path() {
                    if config_path.exists() {
                        println!("Config saved in {config_path:?}");
                    } else {
                        return Err(NotedError::ConfigNotFound);
                    }
                }
            }

            if show {
                if let Some(config_path) = config::get_config_path() {
                    if config_path.exists() {
                        let config = Config::load()?;
                        print_clean_config(config);
                    } else {
                        return Err(NotedError::ConfigNotFound);
                    }
                }
            }

            if let Some(ref key) = set_api_key {
                // For sensitive operations, require master password
                let master_password = ensure_master_password(true)
                    .await?
                    .ok_or(NotedError::MasterPasswordRequired)?;

                let mut config = Config::load()?;
                config.active_provider = Some("gemini".to_string());

                // Encrypt the API key
                let encrypted_key = EncryptionData::new(key, &master_password)
                    .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                config.gemini = Some(config::GeminiConfig {
                    api_key: encrypted_key,
                });

                config.save()?;
                println!("{}", "Config saved successfully.".green());
            }

            if let Some(ref key) = set_claude_api_key {
                // For sensitive operations, require master password
                let master_password = ensure_master_password(true)
                    .await?
                    .ok_or(NotedError::MasterPasswordRequired)?;

                let mut config = Config::load()?;
                config.active_provider = Some("claude".to_string());
                let model = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Claude model")
                    .default("claude-3-opus-20240229".to_string())
                    .interact_text()?;

                // Encrypt the API key
                let encrypted_key = EncryptionData::new(key, &master_password)
                    .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                config.claude = Some(config::ClaudeConfig {
                    api_key: encrypted_key,
                    model,
                });

                config.save()?;
                println!("{}", "Config saved successfully.".green());
            }

            if edit {
                ascii_art();
                println!(
                    "{}\n",
                    "Welcome to noted.md! Let's set up your AI provider.".bold()
                );

                // For sensitive operations, require master password
                let master_password = ensure_master_password(true)
                    .await?
                    .ok_or(NotedError::MasterPasswordRequired)?;

                let providers = vec![
                    "Gemini API (Cloud-based, requires API key)",
                    "Claude API (Cloud-based, requires API key)",
                    "Ollama (Local, requires Ollama to be set up)",
                    "OpenAI Compatible API (Cloud/Local, works with LM Studio)",
                ];
                let selected_provider = Select::with_theme(&ColorfulTheme::default())
                    .with_prompt("Choose your AI provider")
                    .items(&providers)
                    .default(0)
                    .interact()?;

                match selected_provider {
                    0 => {
                        let mut config = Config::load()?;
                        let api_key = Password::with_theme(&ColorfulTheme::default())
                            .with_prompt("Enter your Gemini API key: ")
                            .interact()?;

                        // Encrypt the API key
                        let encrypted_key = EncryptionData::new(&api_key, &master_password)
                            .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                        config.active_provider = Some("gemini".to_string());
                        config.gemini = Some(GeminiConfig {
                            api_key: encrypted_key,
                        });
                        config.save()?;
                        println!("{}", "Config saved successfully.".green());
                    }
                    1 => {
                        let mut config = Config::load()?;
                        let api_key = Password::with_theme(&ColorfulTheme::default())
                            .with_prompt("Enter your Claude API key: ")
                            .interact()?;

                        // Encrypt the API key
                        let encrypted_key = EncryptionData::new(&api_key, &master_password)
                            .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                        config.active_provider = Some("claude".to_string());
                        let anthropic_models = vec![
                            "    claude-opus-4-20250514",
                            "    claude-sonnet-4-20250514",
                            "    claude-3-7-sonnet-20250219",
                            "    claude-3-5-haiku-20241022",
                            "    claude-3-5-sonnet-20241022",
                            "    Other",
                        ];
                        let selected_model = Select::with_theme(&ColorfulTheme::default())
                            .with_prompt("Choose your Claude model:")
                            .items(&anthropic_models)
                            .default(0)
                            .interact()?;

                        let model = if selected_model == anthropic_models.len() - 1 {
                            Input::with_theme(&ColorfulTheme::default())
                                .with_prompt("Enter the custom model name:")
                                .interact_text()?
                        } else {
                            anthropic_models[selected_model].trim().to_string()
                        };

                        config.claude = Some(ClaudeConfig {
                            api_key: encrypted_key,
                            model,
                        });
                        config.save()?;
                        println!("{}", "Config saved successfully.".green());
                    }
                    2 => {
                        let url = Input::with_theme(&ColorfulTheme::default())
                            .with_prompt("Ollama server url")
                            .default("http://localhost:11434".to_string())
                            .interact_text()?;

                        let model = Input::with_theme(&ColorfulTheme::default())
                            .with_prompt("Ollama model")
                            .default("gemma3:27b".to_string())
                            .interact_text()?;

                        let mut config = Config::load()?;
                        config.active_provider = Some("ollama".to_string());
                        config.ollama = Some(OllamaConfig { url, model });
                        config.save()?;
                        println!("{}", "Config saved successfully.".green());
                    }
                    3 => {
                        let url = Input::with_theme(&ColorfulTheme::default())
                            .with_prompt("Server url")
                            .default("http://localhost:1234".to_string())
                            .interact_text()?;

                        let model = Input::with_theme(&ColorfulTheme::default())
                            .with_prompt("Model")
                            .default("gemma3:27b".to_string())
                            .interact_text()?;

                        let api_key_str = Password::with_theme(&ColorfulTheme::default())
                            .with_prompt("Enter your API key (Optional, press Enter if none): ")
                            .allow_empty_password(true)
                            .interact()?;

                        let api_key = if api_key_str.is_empty() {
                            None
                        } else {
                            // Encrypt the API key if provided
                            let encrypted_key = EncryptionData::new(&api_key_str, &master_password)
                                .map_err(|e| NotedError::EncryptionError(e.to_string()))?;
                            Some(encrypted_key)
                        };

                        let mut config = Config::load()?;
                        config.active_provider = Some("openai".to_string());
                        config.openai = Some(OpenAIConfig {
                            url,
                            model,
                            api_key,
                        });
                        config.save()?;
                        println!("{}", "Config saved successfully.".green());
                    }
                    _ => unreachable!(),
                }

                // notion
                let is_notion = Confirm::with_theme(&ColorfulTheme::default())
                    .with_prompt("Do you want to configure Notion to save your notes there?")
                    .interact()?;

                if is_notion {
                    let api_key_str = Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter your Notion API key: ")
                        .interact()?;

                    // Encrypt the API key
                    let api_key = EncryptionData::new(&api_key_str, &master_password)
                        .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                    let database_id = Password::with_theme(&ColorfulTheme::default())
                        .with_prompt("Enter your Notion Database ID: ")
                        .interact()?;

                    let spinner = ProgressBar::new_spinner();
                    spinner.set_style(
                        ProgressStyle::default_spinner()
                            .template("{spinner:.cyan} {msg}")
                            .unwrap(),
                    );
                    spinner.set_message("Fetching Notion database schema...");
                    spinner.enable_steady_tick(std::time::Duration::from_millis(100));

                    // Create a NotionClient with the API key (already decrypted from user input)
                    let client = NotionClient::new(api_key_str.clone(), database_id.clone());
                    let schema_result = client.get_database_schema().await;
                    spinner.finish_and_clear();
                    match schema_result {
                        Ok(schema) => {
                            let title_property_name = schema
                                .properties
                                .values()
                                .find(|prop| {
                                    matches!(prop.type_specific_config, PropertyType::Title(_))
                                })
                                .map(|prop| prop.name.clone())
                                .ok_or_else(|| {
                                    NotedError::ApiError(format!(
                                        "{}",
                                        "Database has no title property".red()
                                    ))
                                })?;

                            let properties: Vec<_> = schema
                                .properties
                                .into_iter()
                                .filter(|(_name, property)| {
                                    matches!(
                                        &property.type_specific_config,
                                        PropertyType::Select { .. }
                                            | PropertyType::MultiSelect { .. }
                                            | PropertyType::RichText(_)
                                            | PropertyType::Number(_)
                                            | PropertyType::Date(_)
                                            | PropertyType::Checkbox(_)
                                    )
                                })
                                .collect();

                            let mut default_properties = Vec::new();
                            if properties.is_empty() {
                                println!(
                                    "{}",
                                    "No user configurable properties found in this database."
                                        .yellow()
                                );
                            } else {
                                println!("Enter the default values for the following properties: ");
                            }
                            for (name, property) in &properties {
                                match &property.type_specific_config {
                                    PropertyType::MultiSelect { multi_select } => {
                                        let options: Vec<_> = multi_select
                                            .options
                                            .iter()
                                            .map(|option| option.name.clone())
                                            .collect();

                                        let selections =
                                            MultiSelect::with_theme(&ColorfulTheme::default())
                                                .with_prompt(format!(
                                                    "Select default options for '{name}' (press Space to select and Enter to confirm)"
                                                ))
                                                .items(&options)
                                                .interact()?;
                                        let selected_names: Vec<String> = selections
                                            .iter()
                                            .map(|&i| options[i].clone())
                                            .collect();
                                        let prop_config = config::NotionPropertyConfig {
                                            name: name.clone(),
                                            property_type: "multi_select".to_string(),
                                            default_value: serde_json::json!(selected_names),
                                        };
                                        default_properties.push(prop_config);
                                    }
                                    PropertyType::Select { select } => {
                                        let options: Vec<_> = select
                                            .options
                                            .iter()
                                            .map(|option| option.name.clone())
                                            .collect();
                                        let selection = Select::with_theme(&ColorfulTheme::default())
                                                .with_prompt(format!("Select default option for '{name}' (Select and Enter to confirm)"))
                                                .items(&options)
                                                .interact()?;
                                        let selected_name = options[selection].clone();
                                        let prop_config = config::NotionPropertyConfig {
                                            name: name.clone(),
                                            property_type: "select".to_string(),
                                            default_value: serde_json::json!(selected_name),
                                        };
                                        default_properties.push(prop_config);
                                    }
                                    PropertyType::RichText(_) => {
                                        let default_value: String =
                                            Input::with_theme(&ColorfulTheme::default())
                                                .with_prompt(format!("Default text for '{name}'"))
                                                .interact_text()?;
                                        let prop_config = config::NotionPropertyConfig {
                                            name: name.clone(),
                                            property_type: "rich_text".to_string(),
                                            default_value: serde_json::json!(default_value),
                                        };
                                        default_properties.push(prop_config);
                                    }
                                    PropertyType::Checkbox(_) => {
                                        let checked =
                                            Confirm::with_theme(&ColorfulTheme::default())
                                                .with_prompt(format!(
                                                    "Should '{name}' be checked by default?"
                                                ))
                                                .interact()?;
                                        let prop_config = config::NotionPropertyConfig {
                                            name: name.clone(),
                                            property_type: "checkbox".to_string(),
                                            default_value: serde_json::json!(checked),
                                        };
                                        default_properties.push(prop_config);
                                    }

                                    PropertyType::Date(_) => {
                                        let default_value: String =
                                            Input::with_theme(&ColorfulTheme::default())
                                                .with_prompt(format!(
                                                    "Default date for '{name}' (YYYY-MM-DD)"
                                                ))
                                                .interact_text()?;
                                        let prop_config = config::NotionPropertyConfig {
                                            name: name.clone(),
                                            property_type: "date".to_string(),
                                            default_value: serde_json::json!(default_value),
                                        };
                                        default_properties.push(prop_config);
                                    }

                                    PropertyType::Number(_) => {
                                        let default_value: f64 =
                                            Input::with_theme(&ColorfulTheme::default())
                                                .with_prompt(format!("Default number for '{name}'"))
                                                .interact()?;
                                        let prop_config = config::NotionPropertyConfig {
                                            name: name.clone(),
                                            property_type: "number".to_string(),
                                            default_value: serde_json::json!(default_value),
                                        };

                                        default_properties.push(prop_config);
                                    }
                                    _ => {
                                        println!(
                                            "{} Property '{}' is not supported for default configuration.",
                                            "✖".red(),
                                            name
                                        );
                                    }
                                }
                            }

                            let mut config = Config::load()?;
                            config.notion = Some(NotionConfig {
                                api_key,
                                database_id,
                                title_property_name,
                                properties: default_properties,
                            });
                            config.save()?;
                        }
                        Err(e) => eprintln!("{e}"),
                    }
                }
                println!(
                    "{}",
                    "You can now run 'notedmd convert <file>' to convert your files.".cyan()
                );
            }

            if let Some(ref new_provider) = set_provider {
                if let Some(config_path) = get_config_path() {
                    if !config_path.exists() {
                        return Err(NotedError::ConfigNotFound);
                    }

                    let mut config = Config::load()?;
                    let new_provider_str = new_provider.as_str();
                    let is_configured = match new_provider_str {
                        "gemini" => config.gemini.is_some(),
                        "claude" => config.claude.is_some(),
                        "ollama" => config.ollama.is_some(),
                        "openai" => config.openai.is_some(),
                        _ => {
                            eprintln!(
                                "Invalid provider '{new_provider}'. Please choose from 'gemini', 'claude', or 'ollama'."
                            );
                            return Ok(());
                        }
                    };

                    if is_configured {
                        config.active_provider = Some(new_provider_str.to_string());
                        config.save()?;
                        println!("Active provider set to '{}'.", new_provider_str.cyan());
                    } else {
                        eprintln!(
                            "{} is not configured. Please run 'notedmd config --edit' to set it up.",
                            new_provider_str.yellow()
                        );
                    }
                }
            }

            if !edit
                && !show
                && !show_path
                && set_api_key.is_none()
                && set_claude_api_key.is_none()
                && set_provider.is_none()
            {
                if let Some(config_path) = get_config_path() {
                    if config_path.exists() {
                        let config = Config::load()?;
                        print_clean_config(config);
                    } else {
                        return Err(NotedError::ConfigNotFound);
                    }
                }
            }
        }
        Commands::Convert {
            path,
            output,
            api_key,
            prompt,
            notion,
        } => {
            let config = Config::load()?;

            // Check if configuration needs migration
            check_config_migration(&config)?;

            // For operations that need access to sensitive data, require master password
            let master_password = ensure_master_password(true)
                .await?
                .ok_or(NotedError::MasterPasswordRequired)?;

            let (client, model_info, api_key): (Box<dyn AiProvider>, String, String) =
                match config.active_provider.as_deref() {
                    Some("gemini") => {
                        let final_api_key = if let Some(key) = api_key {
                            key
                        } else if let Some(gemini_config) = &config.gemini {
                            // Decrypt the API key
                            gemini_config
                                .api_key
                                .decrypt(&master_password)
                                .map_err(|e| NotedError::EncryptionError(e.to_string()))?
                        } else {
                            return Err(NotedError::GeminiNotConfigured);
                        };
                        (
                            Box::new(GeminiClient::new()),
                            "gemma-3-27b-it".to_string(),
                            final_api_key,
                        )
                    }
                    Some("ollama") => {
                        let url = if let Some(ollama_config) = &config.ollama {
                            ollama_config.url.clone()
                        } else {
                            return Err(NotedError::OllamaNotConfigured);
                        };
                        let model = if let Some(ollama_config) = &config.ollama {
                            ollama_config.model.clone()
                        } else {
                            return Err(NotedError::OllamaNotConfigured);
                        };
                        let model_info = format!("{url}|{model}");
                        (Box::new(OllamaClient::new()), model_info, String::new())
                    }
                    Some("claude") => {
                        let final_api_key = if let Some(key) = api_key {
                            key
                        } else if let Some(claude_config) = &config.claude {
                            // Decrypt the API key
                            claude_config
                                .api_key
                                .decrypt(&master_password)
                                .map_err(|e| NotedError::EncryptionError(e.to_string()))?
                        } else {
                            return Err(NotedError::ClaudeNotConfigured);
                        };

                        let model = if let Some(claude_config) = &config.claude {
                            claude_config.model.clone()
                        } else {
                            return Err(NotedError::ClaudeNotConfigured);
                        };

                        (Box::new(ClaudeClient::new()), model, final_api_key)
                    }
                    Some("openai") => {
                        let url = if let Some(openai_config) = &config.openai {
                            openai_config.url.clone()
                        } else {
                            return Err(NotedError::OpenAINotConfigured);
                        };
                        let model = if let Some(openai_config) = &config.openai {
                            openai_config.model.clone()
                        } else {
                            return Err(NotedError::OpenAINotConfigured);
                        };
                        let final_api_key = if let Some(openai_config) = &config.openai {
                            if let Some(encrypted_key) = &openai_config.api_key {
                                // Decrypt the API key if present
                                encrypted_key
                                    .decrypt(&master_password)
                                    .map_err(|e| NotedError::EncryptionError(e.to_string()))?
                            } else {
                                String::new()
                            }
                        } else {
                            return Err(NotedError::OpenAINotConfigured);
                        };
                        let model_info = format!("{url}|{model}");
                        (Box::new(OpenAIClient::new()), model_info, final_api_key)
                    }
                    _ => return Err(NotedError::NoActiveProvider),
                };

            let input_path = Path::new(&path);
            if !input_path.exists() {
                return Err(NotedError::IoError(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Input path not found: {path}"),
                )));
            }
            let (notion_client, notion_config) = if notion {
                if let Some(config) = &config.notion {
                    // Decrypt the Notion API key
                    let decrypted_api_key = config
                        .api_key
                        .decrypt(&master_password)
                        .map_err(|e| NotedError::EncryptionError(e.to_string()))?;

                    let client = NotionClient::new(decrypted_api_key, config.database_id.clone());
                    (Some(client), Some(config))
                } else {
                    return Err(NotedError::NotionNotConfigured);
                }
            } else {
                (None, None)
            };

            if input_path.is_dir() {
                let files_to_convert: Vec<_> = std::fs::read_dir(input_path)?
                    .filter_map(Result::ok)
                    .filter_map(|entry| {
                        let path = entry.path();
                        if path.is_file() {
                            if let Some(path_str) = path.to_str() {
                                if file_utils::get_file_mime_type(path_str).is_ok() {
                                    return Some(path);
                                }
                            }
                        }
                        None
                    })
                    .collect();

                if files_to_convert.is_empty() {
                    println!("No supported files found in the directory.");
                    return Ok(());
                }

                let progress_bar = ProgressBar::new(files_to_convert.len() as u64);
                progress_bar.set_style(
                    ProgressStyle::default_bar()
                        .template("{bar:40.cyan/blue} {pos}/{len} {msg}")
                        .unwrap(),
                );
                progress_bar.set_message("Processing files...");

                for file_path_buf in files_to_convert {
                    if let Some(file_path_str) = file_path_buf.to_str() {
                        match process_file_with_ai(
                            file_path_str,
                            client.as_ref(),
                            &model_info,
                            &api_key,
                            prompt.clone(),
                            &progress_bar,
                        )
                        .await
                        {
                            Ok(markdown) => {
                                if let Err(e) = save_file_and_notion(
                                    file_path_str,
                                    &markdown,
                                    output.as_deref(),
                                    &progress_bar,
                                    notion_client.as_ref(),
                                    notion_config,
                                )
                                .await
                                {
                                    progress_bar.println(format!("{}", e.to_string().red()));
                                }
                            }
                            Err(e) => {
                                progress_bar.println(format!("{}", e.to_string().red()));
                            }
                        }
                    }
                    progress_bar.inc(1);
                }

                progress_bar
                    .finish_with_message(format!("{}", "Completed processing all files".green()));
            } else {
                let path_str = input_path.to_str().ok_or_else(|| {
                    NotedError::FileNameError(input_path.to_string_lossy().to_string())
                })?;
                file_utils::get_file_mime_type(path_str)?;
                let progress_bar = ProgressBar::new(1);
                progress_bar.set_style(
                    ProgressStyle::default_bar()
                        .template("{bar:40.cyan/blue} {pos}/{len} {msg}")
                        .unwrap(),
                );
                progress_bar.set_message("Processing file...");
                match process_file_with_ai(
                    path_str,
                    client.as_ref(),
                    &model_info,
                    &api_key,
                    prompt,
                    &progress_bar,
                )
                .await
                {
                    Ok(markdown) => {
                        if let Err(e) = save_file_and_notion(
                            path_str,
                            &markdown,
                            output.as_deref(),
                            &progress_bar,
                            notion_client.as_ref(),
                            notion_config,
                        )
                        .await
                        {
                            progress_bar.println(format!("{}", e.to_string().red()));
                        }
                    }
                    Err(e) => {
                        progress_bar.println(format!("{}", e.to_string().red()));
                    }
                }
                progress_bar.inc(1);
                progress_bar
                    .finish_with_message(format!("{}", "Completed processing file".green()));
            }
        }
    }
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{} {}", "✖".red(), e.to_string().red());
        std::process::exit(1);
    }
}
