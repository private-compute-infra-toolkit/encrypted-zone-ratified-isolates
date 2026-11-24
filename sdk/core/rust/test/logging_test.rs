// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::{format_log_line, resolve_isolate_name, sanitize_isolate_name, setup_logging};

const DEFAULT_ISOLATE_NAME: &str = "ratified_isolate_default";
const MANIFEST_ISOLATE_NAME: &str = "manifest_configured_isolate";

/// Verifies that `resolve_isolate_name` prefers a non-empty `EZ_ISOLATE_NAME` override over the default name.
#[test]
fn test_resolve_isolate_name_prefers_env_override() {
    // Resolve the isolate name when `EZ_ISOLATE_NAME` is present and non-empty.
    let resolved = resolve_isolate_name(Some(MANIFEST_ISOLATE_NAME), DEFAULT_ISOLATE_NAME);

    // Confirm that the manifest environment override takes precedence over the binary default.
    assert_eq!(resolved, MANIFEST_ISOLATE_NAME);
}

/// Verifies that `resolve_isolate_name` falls back to the default isolate name when `EZ_ISOLATE_NAME` is unset or empty.
#[test]
fn test_resolve_isolate_name_falls_back_when_unset_or_empty() {
    // Resolve the isolate name when the environment variable is unset.
    let resolved_when_unset = resolve_isolate_name(None, DEFAULT_ISOLATE_NAME);
    assert_eq!(resolved_when_unset, DEFAULT_ISOLATE_NAME);

    // Resolve the isolate name when the environment variable is empty.
    let resolved_when_empty = resolve_isolate_name(Some(""), DEFAULT_ISOLATE_NAME);
    assert_eq!(resolved_when_empty, DEFAULT_ISOLATE_NAME);

    // Resolve the isolate name when the environment variable contains only control characters.
    let resolved_when_control_only = resolve_isolate_name(Some("\r\n\t"), DEFAULT_ISOLATE_NAME);
    assert_eq!(resolved_when_control_only, DEFAULT_ISOLATE_NAME);

    // Resolve the isolate name when the fallback default itself contains control characters.
    let resolved_sanitized_default = resolve_isolate_name(None, "ratified_isolate\r\n_default");
    assert_eq!(resolved_sanitized_default, DEFAULT_ISOLATE_NAME);
}

/// Verifies that `sanitize_isolate_name` strips embedded newline and control characters to prevent log injection.
#[test]
fn test_sanitize_isolate_name_strips_control_characters() {
    const RAW_ISOLATE_NAME: &str = "crypto\n_oracle\r\t\x07";
    const EXPECTED_SANITIZED_NAME: &str = "crypto_oracle";

    // Sanitize an isolate name containing embedded control characters.
    let sanitized = sanitize_isolate_name(RAW_ISOLATE_NAME);

    // Confirm all control characters are removed while preserving valid identifier characters.
    assert_eq!(sanitized, EXPECTED_SANITIZED_NAME);
}

/// Verifies that `format_log_line` renders the timestamp, level, `[isolate_name]` tag, source location, and message.
#[test]
fn test_format_log_line_includes_isolate_name_and_source_location() {
    const TIMESTAMP: &str = "2026-11-11T19:00:00.123456Z";
    const MODULE_PATH: &str = "approver::server";
    const FILE_PATH: &str = "approver/src/server.rs";
    const LINE_NUMBER: u32 = 42;
    const EXPECTED_LINE: &[u8] =
        b"2026-11-11T19:00:00.123456Z INFO [manifest_configured_isolate] approver::server::approver/src/server.rs:42 - server ready\n";

    // Format a log record with full module, file, and line metadata directly into a byte buffer.
    let record = log::Record::builder()
        .args(format_args!("server ready"))
        .level(log::Level::Info)
        .module_path_static(Some(MODULE_PATH))
        .file_static(Some(FILE_PATH))
        .line(Some(LINE_NUMBER))
        .build();
    let mut buf = Vec::new();
    let result = format_log_line(&mut buf, TIMESTAMP, MANIFEST_ISOLATE_NAME, &record);

    // Confirm the write succeeded and the formatted line matches the standardized EZ isolate log format.
    assert!(result.is_ok());
    assert_eq!(buf, EXPECTED_LINE);
}

/// Verifies that `format_log_line` handles missing optional record metadata without panicking.
#[test]
fn test_format_log_line_handles_missing_location_metadata() {
    const TIMESTAMP: &str = "2026-11-11T19:00:00.000000Z";
    const EXPECTED_LINE: &[u8] =
        b"2026-11-11T19:00:00.000000Z WARN [ratified_isolate_default] :::0 - fallback location\n";

    // Format a log record when module_path, file, and line are all `None`.
    let record = log::Record::builder()
        .args(format_args!("fallback location"))
        .level(log::Level::Warn)
        .build();
    let mut buf = Vec::new();
    let result = format_log_line(&mut buf, TIMESTAMP, DEFAULT_ISOLATE_NAME, &record);

    // Confirm the write succeeded and default empty strings and line 0 are used cleanly.
    assert!(result.is_ok());
    assert_eq!(buf, EXPECTED_LINE);
}

/// Verifies that `setup_logging` disables logging when `enable_logging` is `false`, initializes
/// the global logger at `Info` level when `enable_logging` is `true`, and is idempotent.
#[test]
fn test_setup_logging_is_idempotent() {
    // Confirm that calling `setup_logging` with `enable_logging = false` disables logging.
    setup_logging(DEFAULT_ISOLATE_NAME, false);
    assert_eq!(log::max_level(), log::LevelFilter::Off);
    assert!(!log::log_enabled!(log::Level::Info));

    // Initialize the global logger twice with `enable_logging = true` to confirm `try_init`
    // does not panic on repeated calls.
    setup_logging(DEFAULT_ISOLATE_NAME, true);
    setup_logging(MANIFEST_ISOLATE_NAME, true);

    // Confirm that `setup_logging` installed an active global logger with `Info` level enabled.
    assert_ne!(log::max_level(), log::LevelFilter::Off);
    assert!(log::log_enabled!(log::Level::Info));
    log::info!("setup_logging smoke test message");

    // Confirm that calling `setup_logging` with `enable_logging = false` turns logging off.
    setup_logging(DEFAULT_ISOLATE_NAME, false);
    assert_eq!(log::max_level(), log::LevelFilter::Off);
    assert!(!log::log_enabled!(log::Level::Info));
}
