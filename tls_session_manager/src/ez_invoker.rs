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
use tokio::sync::mpsc::{channel, Receiver};
use tokio_retry::strategy::{jitter, ExponentialBackoff};
use tokio_retry::RetryIf;
use tokio_stream::{wrappers::ReceiverStream, StreamExt};
use tonic::{Request, Status};

use setup_isolate_proto::setup_isolate::v1::{
    FetchFrontendTlsCertificateRequest, FetchFrontendTlsCertificateResponse,
};
use setup_isolate_sdk::SetupServiceIsolateStub;
use tls_session_manager_sdk::{DataScopeType, IsolateEzBridgeSdkClient, RpcHandler};
const RETRY_MAX_DELAY_MILLIS: u64 = 60000;
const CHANNEL_SIZE: usize = 256;
const RETRY_COUNT: usize = 10;
const RETRY_BASE_DELAY_MILLIS: u64 = 1000;
const RETRY_SCALING: u64 = 2;

const TRUSTED_DOMAIN_NAME: &str = "EZ_Trusted";

/// A consistent retry strategy across methods. Exponential backoff, with jitter for randomness.
fn get_retry_strategy() -> impl Iterator<Item = std::time::Duration> {
    ExponentialBackoff::from_millis(RETRY_BASE_DELAY_MILLIS)
        .factor(RETRY_SCALING)
        .max_delay(std::time::Duration::from_millis(RETRY_MAX_DELAY_MILLIS))
        .map(jitter)
        .take(RETRY_COUNT)
}

/// Trait for being able to send out calls needed for TSM
/// Wrapper around SDK calls, to support mocking out
#[tonic::async_trait]
pub trait EzInvoker: std::fmt::Debug + Send + Sync {
    /// Start a streaming session with the server using raw bytes.
    /// Forwards `ForwardedControlPlaneMetadata` from `request.extensions()` to the backend stream.
    async fn stream_server(
        &self,
        request: Request<Receiver<Vec<u8>>>,
    ) -> Result<Receiver<Result<Vec<u8>, Status>>, Status>;

    /// Fetch the signed frontend TLS certificate from SetupService
    async fn fetch_frontend_certificate(
        &self,
        request: FetchFrontendTlsCertificateRequest,
    ) -> Result<FetchFrontendTlsCertificateResponse, Status>;

    /// Notify the SDK that there is a new isolate state
    async fn new_isolate_state(
        &self,
        state: enforcer_proto::enforcer::v1::IsolateState,
    ) -> Result<(), Status>;
}

/// Invoker that calls the SDK bridge
#[derive(Debug)]
pub struct BridgeEzInvoker {
    bridge_client: Arc<IsolateEzBridgeSdkClient>,
    server_target: crate::InvokeConfig,
}

impl BridgeEzInvoker {
    pub fn new(
        bridge_client: Arc<IsolateEzBridgeSdkClient>,
        server_target: crate::InvokeConfig,
    ) -> Self {
        Self { bridge_client, server_target }
    }
}

#[tonic::async_trait]
impl EzInvoker for BridgeEzInvoker {
    async fn stream_server(
        &self,
        request: Request<Receiver<Vec<u8>>>,
    ) -> Result<Receiver<Result<Vec<u8>, Status>>, Status> {
        let rpc_handler = RpcHandler::new(
            self.bridge_client.clone(),
            self.server_target.domain_name.clone(),
            self.server_target.service_name.clone(),
            DataScopeType::UserPrivate,
        );
        let request_stream = request.map(ReceiverStream::new);
        let mut response_stream = rpc_handler
            .stream_isolate_rpc_call_vec(&self.server_target.method_name, request_stream)
            .await?
            .into_inner();

        // Convert response stream to receiver
        let (response_tx, response_rx) = channel::<Result<Vec<u8>, Status>>(CHANNEL_SIZE);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    response = response_stream.next() => {
                        let Some(response) = response else { break; };
                        let response = match response {
                            Ok(response) => response,
                            Err(status) => {
                                log::error!("Error from gRPC stream: {status:?}");
                                // Strip the error message to prevent leaking internal isolate details
                                let stripped_status =
                                    tonic::Status::new(status.code(), /*message=*/ "");
                                if let Err(e) = response_tx.send(Err(stripped_status)).await {
                                    log::error!("Failed to send invoke EZ error response: {e:?}");
                                }
                                return;
                            }
                        };
                        if let Err(e) = response_tx.send(Ok(response)).await {
                            log::error!("Failed to send invoke EZ response: {e:?}");
                            return;
                        }
                    }
                    _ = response_tx.closed() => {
                        // Response channel dropped (e.g. TSM hung up).
                        // Break to gracefully tear down the backend stream.
                        return;
                    }
                }
            }
        });

        Ok(response_rx)
    }

    async fn fetch_frontend_certificate(
        &self,
        request: FetchFrontendTlsCertificateRequest,
    ) -> Result<FetchFrontendTlsCertificateResponse, Status> {
        let stub = SetupServiceIsolateStub::new_with_scope(
            TRUSTED_DOMAIN_NAME.to_string(),
            DataScopeType::Public,
            self.bridge_client.clone(),
        );

        let retry_strategy = get_retry_strategy();
        let should_retry = |e: &Status| {
            !matches!(e.code(), tonic::Code::InvalidArgument | tonic::Code::Unauthenticated)
        };
        RetryIf::start(
            retry_strategy,
            || async { stub.fetch_frontend_tls_certificate(Request::new(request.clone())).await },
            should_retry,
        )
        .await
        .map(|x| x.into_inner())
    }

    async fn new_isolate_state(
        &self,
        state: enforcer_proto::enforcer::v1::IsolateState,
    ) -> Result<(), Status> {
        self.bridge_client.new_isolate_state(state).await
    }
}
