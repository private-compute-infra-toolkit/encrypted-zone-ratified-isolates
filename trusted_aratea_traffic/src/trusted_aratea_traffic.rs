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

use anyhow::Result;
use enforcer_proto::data_scope_proto::enforcer::v1::DataScopeType;
use ez_isolate_bridge_sdk::{
    with_sdk_client, IsolateEzBridgeSdkClient, PrivateInferenceService,
    PrivateInferenceServiceIsolateStub,
};
use private_inference_service_proto::private_inference_service::{
    GenerateContentRequest, GenerateContentResponse,
};
use std::sync::OnceLock;
use tonic::{Request, Response, Status};

/// Implementation of the `PrivateInferenceService` gRPC service.
///
/// This struct forwards incoming `GenerateContentRequest`s to a specified
/// operator domain with the downgraded data scope.
#[with_sdk_client]
#[derive(Clone)]
pub struct TrustedArateaTrafficImpl {
    forward_operator_domain: String,
    stub: OnceLock<PrivateInferenceServiceIsolateStub>,
}

impl TrustedArateaTrafficImpl {
    /// Creates a new `TrustedArateaTrafficImpl` instance.
    ///
    /// # Arguments
    /// * `forward_operator_domain` - The domain to which incoming content generation requests should be forwarded.
    pub fn new(forward_operator_domain: String) -> Self {
        Self { forward_operator_domain, client: Default::default(), stub: OnceLock::new() }
    }
}

#[tonic::async_trait]
impl PrivateInferenceService for TrustedArateaTrafficImpl {
    async fn generate_content(
        &self,
        request: Request<GenerateContentRequest>,
    ) -> Result<Response<GenerateContentResponse>, Status> {
        log::info!("Received GenerateContent request");

        let stub = self.stub.get_or_init(|| {
            PrivateInferenceServiceIsolateStub::new_with_scope(
                self.forward_operator_domain.clone(),
                DataScopeType::UserPrivate,
                self.get_client(),
            )
        });

        // TODO: Only forward Smart Trust features.
        log::info!("Forwarding GenerateContent to: {}", self.forward_operator_domain);

        let forward_response = stub
            .generate_content(Request::new(request.into_inner()))
            .await
            .map_err(|e| Status::internal(format!("Failed to forward request: {}", e)))?;

        let response = Response::new(forward_response.into_inner());

        log::info!("Received response from: {}", self.forward_operator_domain);
        Ok(response)
    }
}
