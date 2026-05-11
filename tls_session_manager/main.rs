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
use tls_session_manager::{InvokeConfig, TlsSessionManager, TsmConfig};
use tls_session_manager_sdk::{
    create_isolate_server_with_client, TlsSessionManagerServiceIsolateRpcService,
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
    #[arg(
        long,
        help = "Binding token info string passed into the session to produce the session token."
    )]
    binding_token_info: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Args::parse();
    let tsm_config = TsmConfig {
        server_target: InvokeConfig {
            domain_name: args.destination_operator_domain,
            service_name: args.destination_service_name,
            method_name: args.destination_method_name,
        },
        binding_token_info: args.binding_token_info,
    };

    // Makes it respect RUST_LOG=info and similar
    env_logger::init();

    log::info!("Starting TSM Isolate server...");

    let tsm_logic = Arc::new(TlsSessionManager::new(tsm_config));

    let server = create_isolate_server_with_client! {
        TlsSessionManagerServiceIsolateRpcService => tsm_logic
    };

    server.start(None).await;

    log::info!("Server shut down gracefully.");
    Ok(())
}
