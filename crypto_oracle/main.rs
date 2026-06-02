// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use clap::Parser;
use crypto_oracle::CryptoOracle;
use crypto_oracle_sdk::{
    create_isolate_server_with_resp_scope, DataScopeType, OracleApiIsolateRpcService,
};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// OTel traces endpoint
    #[arg(long)]
    otel_traces_endpoint: Option<String>,
    /// OTel traces sample ratio
    #[arg(
        long,
        default_value_t = 1.0 / ((1_u32 << 17) as f64),
        help = "Sampler probability for traces."
    )]
    traces_sample_ratio: f64,

    /// OTel metrics endpoint
    #[arg(long, default_value = "unix:///enforcer-isolate-shared/otlp-metrics.sock")]
    otel_metrics_endpoint: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initializes the logger. It will check the `RUST_LOG` environment
    // variable first. If it's missing, it defaults to the "info" level.
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    let args = Args::parse();

    let _otel_traces = crypto_oracle_sdk::traces::setup_traces(
        "crypto_oracle",
        &args.otel_traces_endpoint,
        args.traces_sample_ratio,
    )
    .await?;

    crypto_oracle_sdk::telemetry::metrics::setup_metrics(
        "crypto_oracle",
        Some(args.otel_metrics_endpoint),
    )
    .await;

    log::info!("Starting Crypto Oracle Ratified Isolate");
    let oracle = Arc::new(CryptoOracle::new());

    log::info!("Starting Crypto Oracle Ratified Isolate Server");
    // TODO: Per-request scope once supported
    let server = create_isolate_server_with_resp_scope! {
        OracleApiIsolateRpcService => oracle => DataScopeType::Public,
    };

    server.start(None).await;

    log::info!("Crypto Oracle Ratified Isolate server shut down gracefully");

    Ok(())
}
