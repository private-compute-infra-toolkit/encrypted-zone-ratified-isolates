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

use crate::isolate_ez_bridge_client::IsolateEzBridgeSdkClient;
use crate::shm_slab_pool::EzShmSlabPool;
use crate::{GrpcClientRequestStream, PinBoxGrpcResponseStream};
use enforcer_proto::data_scope_proto::enforcer::v1::DataScopeType;
use enforcer_proto::enforcer::v1::{
    ControlPlaneMetadata, EzPayloadIsolateScope, InvokeEzRequest, InvokeEzResponse,
    IsolateDataScope,
};
use payload_proto::enforcer::v1::{
    ez_hybrid_payload::DeliveryMethod, EzHybridPayload, EzPayloadData, ShmSlotData,
};
use prost::Message;
use std::sync::Arc;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

/// Handles RPC calls to the isolate by wrapping the `IsolateEzBridgeSdkClient`.
///
/// This struct is responsible for marshaling requests and responses between the client application
/// and the Encrypted Zone (EZ) isolate. It handles the details of creating `InvokeEzRequest` messages,
/// managing IPC message IDs, and decoding `InvokeEzResponse` messages.
#[derive(Debug, Clone)]
pub struct RpcHandler {
    client: Arc<IsolateEzBridgeSdkClient>,
    operator_domain: String,
    service_name: String,
    request_scope: DataScopeType,
    shm_pool: Option<EzShmSlabPool>,
}

impl RpcHandler {
    /// Creates a new `RpcHandler`.
    ///
    /// # Arguments
    ///
    /// * `client` - The shared `IsolateEzBridgeSdkClient` used to communicate with the bridge.
    /// * `operator_domain` - The domain of the service running in the isolate.
    /// * `service_name` - The name of the service running in the isolate.
    /// * `request_scope` - The data scope to use for requests.
    pub fn new(
        client: Arc<IsolateEzBridgeSdkClient>,
        operator_domain: String,
        service_name: String,
        request_scope: DataScopeType,
    ) -> Self {
        let shm_pool = EzShmSlabPool::new()
            .inspect_err(|e| {
                log::error!(
                    "Failed to create shared memory pool; will fallback to default IPC: {:?}",
                    e
                )
            })
            .ok();
        Self { client, operator_domain, service_name, request_scope, shm_pool }
    }

    async fn create_invoke_ez_request(
        &self,
        ipc_message_id: u64,
        method_name: String,
        request_bytes: Vec<u8>,
    ) -> InvokeEzRequest {
        let mut delivery_method = None;
        if let Some(shm_pool) = &self.shm_pool {
            if request_bytes.len() > shm_pool.shm_payload_threshold {
                if let Ok(out_slots) = shm_pool.write_to_enforcer(&request_bytes).await {
                    delivery_method =
                        Some(DeliveryMethod::ShmData(ShmSlotData { slots: out_slots }));
                }
            }
        };
        if delivery_method.is_none() {
            delivery_method =
                Some(DeliveryMethod::InlineData(EzPayloadData { datagrams: vec![request_bytes] }));
        };
        let metadata_headers = crate::telemetry::traces::get_trace_context();
        InvokeEzRequest {
            control_plane_metadata: Some(ControlPlaneMetadata {
                ipc_message_id,
                requester_is_local: true,
                destination_operator_domain: self.operator_domain.clone(),
                destination_service_name: self.service_name.clone(),
                destination_method_name: method_name,
                metadata_headers,
                ..Default::default()
            }),
            isolate_request_iscope: Some(EzPayloadIsolateScope {
                datagram_iscopes: vec![IsolateDataScope {
                    scope_type: self.request_scope as i32,
                    ..Default::default()
                }],
            }),
            isolate_request_payload: Some(EzHybridPayload { delivery_method }),
        }
    }
}

impl RpcHandler {
    /// Performs a unary RPC call to the isolate.
    ///
    /// This method encodes the request message, creates an `InvokeEzRequest`, sends it to the isolate
    /// via the bridge client, and decodes the response.
    ///
    /// # Arguments
    ///
    /// * `method_name` - The name of the RPC method to invoke.
    /// * `request` - The request message.
    ///
    /// # Generic Parameters
    ///
    /// * `T` - The type of the request message (must implement `prost::Message`).
    /// * `U` - The type of the response message (must implement `prost::Message` + `Default`).
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the decoded response message or a `tonic::Status` error.
    pub async fn isolate_rpc_call<T: Message, U: Message + Default>(
        &self,
        method_name: &str,
        request: T,
    ) -> Result<U, Status> {
        let request_bytes = request.encode_to_vec();
        let response = self.isolate_rpc_call_helper(method_name, request_bytes).await?;
        decode_invoke_ez_response(self.shm_pool.as_ref(), &response)
    }

    /// Performs a unary RPC call to the isolate, using Vec<u8>.
    ///
    /// This method creates an `InvokeEzRequest`, sends it to the isolate
    /// via the bridge client, and decodes the response.
    /// This allows for raw vector payloads to be sent without encoding/decoding
    ///
    /// # Arguments
    ///
    /// * `method_name` - The name of the RPC method to invoke.
    /// * `request` - The request message as a vector payload.
    ///
    /// Returns a `Result` containing the vector response message or a `tonic::Status` error.
    pub async fn isolate_rpc_call_vec(
        &self,
        method_name: &str,
        request: Vec<u8>,
    ) -> Result<Vec<u8>, Status> {
        let response = self.isolate_rpc_call_helper(method_name, request).await?;
        extract_invoke_ez_response(self.shm_pool.as_ref(), &response)
    }

    /// Helper to avoid cloning / ownership differences between vec / non-vec
    async fn isolate_rpc_call_helper(
        &self,
        method_name: &str,
        request_bytes: Vec<u8>,
    ) -> Result<InvokeEzResponse, Status> {
        let ipc_message_id = rand::random::<u64>();

        let request = self
            .create_invoke_ez_request(ipc_message_id, method_name.to_string(), request_bytes)
            .await;

        let response = self.client.invoke_ez(request).await?;

        if response.control_plane_metadata.as_ref().map_or(0, |m| m.ipc_message_id)
            != ipc_message_id
        {
            log::error!(
                "Error: Mismatched IPC message id. Expected {}, got {:?}",
                ipc_message_id,
                response.control_plane_metadata.as_ref().map(|m| m.ipc_message_id)
            );
            return Err(Status::internal("Mismatched IPC message id"));
        }

        Ok(response)
    }

    /// Performs a streaming RPC call to the isolate.
    ///
    /// This method simplifies the process of creating a bidirectional streaming RPC. It maps the
    /// input stream of requests to `InvokeEzRequest` messages and maps the output stream of
    /// `InvokeEzResponse` messages back to the expected response type.
    ///
    /// # Arguments
    ///
    /// * `method_name` - The name of the RPC method to invoke.
    /// * `request_stream` - The stream of request messages.
    ///
    /// # Generic Parameters
    ///
    /// * `T` - The type of the request message (must implement `prost::Message`).
    /// * `U` - The type of the response message (must implement `prost::Message` + `Default`).
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the response stream or a `tonic::Status` error.
    pub async fn stream_isolate_rpc_call<T: Message, U: Message + Default>(
        &self,
        method_name: &str,
        request_stream: Request<impl GrpcClientRequestStream<T>>,
    ) -> Result<Response<PinBoxGrpcResponseStream<U>>, Status> {
        let request_stream_vec = request_stream.map(|stream| stream.map(|req| req.encode_to_vec()));

        let response_stream_vec =
            self.stream_isolate_rpc_call_vec(method_name, request_stream_vec).await?;

        let mapped_response_stream = response_stream_vec.into_inner().map(move |res| {
            let bytes = res?;
            U::decode(bytes.as_slice()).map_err(|e| {
                log::error!("Failed to decode response: {:?}", e);
                Status::internal(e.to_string())
            })
        });

        Ok(Response::new(Box::pin(mapped_response_stream)))
    }

    /// Performs a streaming RPC call to the isolate, using raw `Vec<u8>` payloads.
    ///
    /// This method maps an input stream of raw request bytes to `InvokeEzRequest` messages,
    /// and maps the output stream of `InvokeEzResponse` messages back to raw response bytes.
    pub async fn stream_isolate_rpc_call_vec(
        &self,
        method_name: &str,
        request_stream: Request<impl futures::Stream<Item = Vec<u8>> + Send + Unpin + 'static>,
    ) -> Result<
        Response<
            std::pin::Pin<
                Box<dyn futures::Stream<Item = Result<Vec<u8>, Status>> + Send + 'static>,
            >,
        >,
        Status,
    > {
        let this = self.clone();
        let method_name = method_name.to_string();
        let ipc_message_id = rand::random::<u64>();

        let invoke_ez_stream = request_stream.into_inner().then(move |request_bytes| {
            let this = this.clone();
            let method_name = method_name.clone();
            async move {
                this.create_invoke_ez_request(ipc_message_id, method_name, request_bytes).await
            }
        });

        let response_stream = self.client.stream_invoke_ez(invoke_ez_stream).await?;
        let shm_pool = self.shm_pool.clone();
        let mapped_response_stream = response_stream.map(move |res| {
            let response = res?;
            extract_invoke_ez_response(shm_pool.as_ref(), &response)
        });

        Ok(Response::new(Box::pin(mapped_response_stream)))
    }
}

fn extract_invoke_ez_response(
    shm_pool: Option<&EzShmSlabPool>,
    response: &InvokeEzResponse,
) -> Result<Vec<u8>, Status> {
    let payload = response
        .ez_response_payload
        .as_ref()
        .ok_or_else(|| Status::invalid_argument("Missing ez_response_payload"))?;

    match payload.delivery_method.as_ref() {
        Some(DeliveryMethod::InlineData(data)) => data
            .datagrams
            .first()
            .cloned()
            .ok_or_else(|| Status::invalid_argument("Missing inline datagram bytes")),
        Some(DeliveryMethod::ShmData(shm_data)) => {
            if let Some(shm_pool) = shm_pool {
                shm_pool.read_from_enforcer(&shm_data.slots).map_err(|err| {
                    Status::internal(format!("Failed to read from shared memory: {:?}", err))
                })
            } else {
                Err(Status::internal("Received ShmData but EzShmSlabPool is not initialized"))
            }
        }
        _ => Err(Status::invalid_argument("Missing delivery method in response")),
    }
}

fn decode_invoke_ez_response<U: Message + Default>(
    shm_pool: Option<&EzShmSlabPool>,
    response: &InvokeEzResponse,
) -> Result<U, Status> {
    let response_bytes = extract_invoke_ez_response(shm_pool, response)?;
    U::decode(response_bytes.as_slice()).map_err(|e| {
        log::error!("Failed to decode response: {:?}", e);
        Status::internal(e.to_string())
    })
}
