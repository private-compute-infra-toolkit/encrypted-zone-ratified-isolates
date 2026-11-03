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
use tls_session_manager::{
    ez_invoker::BridgeEzInvoker, InvokeConfig, TlsSessionManager, TsmConfig,
};
use tls_session_manager_sdk::{
    create_isolate_server_with_resp_scope_and_client, DataScopeType, IsolateEzBridgeSdkClient,
    TlsSessionManagerServiceIsolateRpcService,
};

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short = 'd', long, help = "The name of the destination server's service domain")]
    destination_operator_domain: String,
    #[arg(short = 's', long, help = "The grpc service name of the destination server")]
    destination_service_name: String,
    #[arg(short = 'm', long, help = "The grpc service method called on the destination server")]
    destination_method_name: String,
    // TODO(b/509939896): Remove this once the manifest no longer tries to pass this flag.
    #[arg(
        long,
        default_value = "",
        help = "Unused. Previously passed into the session to produce the session token."
    )]
    binding_token_info: String,
    #[arg(long, help = "Optional path to the server certificate PEM file")]
    server_cert_path: Option<String>,
    #[arg(long, help = "Optional path to the server private key PEM file")]
    server_key_path: Option<String>,
    #[arg(long, help = "If true, fetch the frontend TLS certificate from SetupService (AVS)")]
    enable_avs: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initializes the logger. It will check the `RUST_LOG` environment
    // variable first. If it's missing, it defaults to the "info" level.
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));
    let args = Args::parse();

    let server_target = InvokeConfig {
        domain_name: args.destination_operator_domain,
        service_name: args.destination_service_name,
        method_name: args.destination_method_name,
    };

    let bridge_client = Arc::new(IsolateEzBridgeSdkClient::new().await?);
    let ez_invoker = Arc::new(BridgeEzInvoker::new(bridge_client.clone(), server_target.clone()));

    let tsm_config = if args.enable_avs {
        TsmConfig { server_target, enable_avs: true, server_cert_pem: None, server_key_pem: None }
    } else {
        let server_cert_pem =
            args.server_cert_path.as_ref().map(std::fs::read_to_string).transpose()?;
        let server_key_pem =
            args.server_key_path.as_ref().map(std::fs::read_to_string).transpose()?;
        TsmConfig { server_target, enable_avs: false, server_cert_pem, server_key_pem }
    };

    log::info!("Starting TSM Isolate server...");

    let tsm_logic = Arc::new(TlsSessionManager::new(ez_invoker.clone(), tsm_config));

    let server = create_isolate_server_with_resp_scope_and_client! {
        // TODO(b/484030934): Update to specify supported methods once per-method
        // scope is supported in the SDK
        // Public scope since responds on Public API
        TlsSessionManagerServiceIsolateRpcService => tsm_logic => DataScopeType::Public
    };

    if args.enable_avs {
        log::info!("Triggering async frontend certificate fetch from SetupService (AVS)...");
        tsm_logic.start_async_certificate_fetch();
    }

    server.start(None).await;

    log::info!("Server shut down gracefully.");
    Ok(())
}
