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

/// Environment variable injected by the Enforcer containing the manifest isolate name.
const ISOLATE_NAME_ENV_VAR: &str = "EZ_ISOLATE_NAME";

/// Strips ASCII and Unicode control characters from an isolate name before log formatting.
fn sanitize_isolate_name(name: &str) -> String {
    name.chars().filter(|c| !c.is_control()).collect()
}

/// Resolves the effective isolate name from an optional `EZ_ISOLATE_NAME` value and a fallback.
fn resolve_isolate_name(env_isolate_name: Option<&str>, default_isolate_name: &str) -> String {
    if let Some(raw_env_name) = env_isolate_name {
        let sanitized_env_name = sanitize_isolate_name(raw_env_name);
        if !sanitized_env_name.is_empty() {
            return sanitized_env_name;
        }
    }
    sanitize_isolate_name(default_isolate_name)
}

/// Writes a single log record line with microsecond timestamp, level, `[isolate_name]`, and
/// source location directly to `writer`.
fn format_log_line(
    writer: &mut impl std::io::Write,
    timestamp: impl std::fmt::Display,
    isolate_name: &str,
    record: &log::Record<'_>,
) -> std::io::Result<()> {
    writeln!(
        writer,
        "{timestamp} {} [{isolate_name}] {}::{}:{} - {}",
        record.level(),
        record.module_path().unwrap_or(""),
        record.file().unwrap_or(""),
        record.line().unwrap_or(0),
        record.args(),
    )
}

/// Initializes console logging with an `[<isolate_name>]` prefix (`EZ_ISOLATE_NAME` if set
/// and non-empty after stripping control characters, otherwise `default_isolate_name`) when
/// `enable_logging` is `true`, or disables logging when `enable_logging` is `false`.
pub fn setup_logging(default_isolate_name: &str, enable_logging: bool) {
    if !enable_logging {
        log::set_max_level(log::LevelFilter::Off);
        return;
    }
    let env_isolate_name = std::env::var(ISOLATE_NAME_ENV_VAR).ok();
    let isolate_name = resolve_isolate_name(env_isolate_name.as_deref(), default_isolate_name);
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(move |buf, record| {
            format_log_line(buf, buf.timestamp_micros(), &isolate_name, record)
        })
        .try_init();
}

#[cfg(test)]
#[path = "../test/logging_test.rs"]
mod logging_test;
