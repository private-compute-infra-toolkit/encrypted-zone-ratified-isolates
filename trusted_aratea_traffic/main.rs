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

use clap::Parser;
use ez_isolate_bridge_sdk::PrivateInferenceServiceIsolateRpcService;
use ez_isolate_bridge_sdk::{create_isolate_server_with_resp_scope_and_client, DataScopeType};
use std::sync::Arc;
use trusted_aratea_traffic_lib::trusted_aratea_traffic::TrustedArateaTrafficImpl;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Domain to forward requests to
    #[arg(long, help = "Domain to forward requests to")]
    forward_operator_domain: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args = Args::parse();

    let logic = Arc::new(TrustedArateaTrafficImpl::new(args.forward_operator_domain));

    // Every response from this Isolate will be tagged with the Public data scope.
    let server = create_isolate_server_with_resp_scope_and_client! {
        PrivateInferenceServiceIsolateRpcService => logic => DataScopeType::Public
    };

    log::info!("Starting TrustedArateaTraffic Isolate server");
    server.start(None).await;
    log::info!("TrustedArateaTraffic Isolate server shut down");
    Ok(())
}
