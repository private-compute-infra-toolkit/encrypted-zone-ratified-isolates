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

use crypto_oracle::CryptoOracle;
use crypto_oracle_sdk::{
    create_isolate_server_with_resp_scope, DataScopeType, OracleApiIsolateRpcService,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

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
