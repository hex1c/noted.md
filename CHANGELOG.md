# Changelog

## [0.2.3]

### Added
- Added `--show`, `--edit`, and `--set-provider` subcommands to the `config` command for better configuration management.

### Changed
- Updated the Claude model selection from a text input to a selection menu to improve user experience and prevent typos.

### Fixed
- Resolved an issue where API errors in successful (`200 OK`) responses were ignored, preventing silent failures.
- Corrected a bug where configuring the Ollama provider would erase all other existing provider settings.

## [0.2.2]

### Added
- Added Claude support.

### Changed
- Refactored the project to move the individual client files to a client subfolder.

## [0.2.1]

### Fixed
- Fixed a bug where `active_provider` was not being set when using `--set-api-key` option.

## [0.2.0]

### Added
  - Added Ollama support
  - Added a `prompt` option to the `convert` command to override the default prompt.

## [0.1.1]

### Added
  - Ollama provider support in onboarding (configuration only)
  - Provider abstraction for AI client support
  - Unified configuration via `notedmd config` command

  ### Changed
  - Improved provider selection and configuration flow in onboarding process

## [0.1.0]

### Added
- Initial release of `notedmd`.
- `convert` command to process single files or directories of images and PDFs.
- `config` command to manage the Gemini API key.
- Interactive prompt to enter API key if not configured.
- Progress bar for batch processing.

### Fixed
- Progress bar rendering correctly during batch processing without being disrupted by log messages.
- Removed redundant ASCII art display on every command run.
