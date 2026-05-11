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

//! TLS session management between a client and a server.
//!
//! This module provides the initial structure and boilerplate required for the TLS Session Manager
//! ratified isolate. It implements the necessary traits and configuration but currently serves as a
//! stub that returns `Unimplemented` for actual session management logic.

use tonic::{Request, Response, Status};

use tls_session_manager_sdk::{
    with_sdk_client, GrpcResponseStream, IsolateEzBridgeSdkClient, StartTlsSessionRequestStream,
    TlsSessionManagerService,
};

use tls_session_manager_proto::tls_session_manager::v1::StartTlsSessionResponse;

/// Metadata of the destination target of an invoke request, based on ControlPlaneMetaData
#[derive(Debug, Default, Clone)]
pub struct InvokeConfig {
    pub domain_name: String,
    pub service_name: String,
    pub method_name: String,
}

#[derive(Debug, Default, Clone)]
pub struct TsmConfig {
    pub server_target: InvokeConfig,
    pub binding_token_info: String,
}

#[with_sdk_client]
#[derive(Debug, Default)]
pub struct TlsSessionManager {
    #[allow(dead_code)]
    server_target: InvokeConfig,
    #[allow(dead_code)]
    binding_token_info: String,
}

/// Standard StartTlsSession RPC - stub for now
#[tonic::async_trait]
impl TlsSessionManagerService for TlsSessionManager {
    type StartTlsSessionStream =
        std::pin::Pin<Box<dyn GrpcResponseStream<StartTlsSessionResponse>>>;

    async fn start_tls_session<T: StartTlsSessionRequestStream>(
        &self,
        _request: Request<T>,
    ) -> Result<Response<Self::StartTlsSessionStream>, Status> {
        Err(Status::unimplemented("StartTlsSession is not yet implemented"))
    }
}

// For testing purposes and legacy compatibility, we also implement the Tonic-generated trait.
#[tonic::async_trait]
impl tls_session_manager_proto::tls_session_manager::v1::tls_session_manager_service_server::TlsSessionManagerService for TlsSessionManager {
    type StartTlsSessionStream = tokio_stream::wrappers::ReceiverStream<Result<StartTlsSessionResponse, Status>>;

    async fn start_tls_session(
        &self,
        _request: tonic::Request<tonic::Streaming<tls_session_manager_proto::tls_session_manager::v1::StartTlsSessionRequest>>,
    ) -> Result<Response<Self::StartTlsSessionStream>, Status> {
        Err(Status::unimplemented("StartTlsSession is not yet implemented"))
    }
}

impl TlsSessionManager {
    pub fn new(tsm_config: TsmConfig) -> Self {
        Self {
            server_target: tsm_config.server_target,
            binding_token_info: tsm_config.binding_token_info,
            ..Default::default()
        }
    }
}
