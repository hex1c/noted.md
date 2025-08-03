use crate::error::NotedError;
use base64::{Engine, engine::general_purpose};
use std::{fs, path::Path};

#[derive(Debug, Clone, PartialEq)]
pub enum FileType {
    Image(ImageFormat),
    Document(DocumentFormat),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ImageFormat {
    Png,
    Jpeg,
    Gif,
    WebP,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DocumentFormat {
    Pdf,
}

pub struct FileData {
    pub encoded_data: String,
    pub mime_type: String,
    pub file_type: FileType,
    pub file_size: u64,
}

pub fn process_file(file_path: &str) -> Result<FileData, NotedError> {
    let data = fs::read(file_path)?;
    let file_size = data.len() as u64;
    let encoded_data: String = general_purpose::STANDARD.encode(&data);
    let (mime_type, file_type) = get_file_type_info(file_path)?;

    Ok(FileData {
        encoded_data,
        mime_type,
        file_type,
        file_size,
    })
}

pub fn get_file_mime_type(file_path: &str) -> Result<String, NotedError> {
    let (mime_type, _) = get_file_type_info(file_path)?;
    Ok(mime_type)
}

pub fn get_file_type_info(file_path: &str) -> Result<(String, FileType), NotedError> {
    let file_extension = Path::new(file_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase());

    match file_extension.as_deref() {
        Some("png") => Ok(("image/png".to_string(), FileType::Image(ImageFormat::Png))),
        Some("jpg") | Some("jpeg") => {
            Ok(("image/jpeg".to_string(), FileType::Image(ImageFormat::Jpeg)))
        }
        Some("gif") => Ok(("image/gif".to_string(), FileType::Image(ImageFormat::Gif))),
        Some("webp") => Ok(("image/webp".to_string(), FileType::Image(ImageFormat::WebP))),
        Some("pdf") => Ok((
            "application/pdf".to_string(),
            FileType::Document(DocumentFormat::Pdf),
        )),
        Some(ext) => Err(NotedError::UnsupportedFileType(ext.to_string())),
        None => Err(NotedError::UnsupportedFileType("No extension".to_string())),
    }
}
