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
//

use derivative::Derivative;
use enforcer_proto::data_scope_proto::enforcer::v1::DataScopeType;
use enforcer_proto::enforcer::v1::ez_isolate_bridge_client::EzIsolateBridgeClient;
use enforcer_proto::enforcer::v1::ez_isolate_bridge_server::EzIsolateBridge;
use enforcer_proto::enforcer::v1::isolate_ez_bridge_server::IsolateEzBridge;
use enforcer_proto::enforcer::v1::{
    ControlPlaneMetadata, CreateFileshareRequest, CreateFileshareResponse, CreateMemshareRequest,
    CreateMemshareResponse, InvokeEzRequest, InvokeEzResponse, InvokeIsolateRequest,
    InvokeIsolateResponse, NotifyIsolateStateRequest, NotifyIsolateStateResponse,
    PollIsolateStateRequest, PollIsolateStateResponse, PublishEventForRequest,
    PublishEventForResponse, StreamSubscribeToRequest, StreamSubscribeToResponse,
};
use futures::StreamExt;
use hyper_util::rt::TokioIo;
use payload_proto::enforcer::v1::{
    ez_hybrid_payload::DeliveryMethod, EzHybridPayload, EzPayloadData, ShmSlotReference,
};
use rust_core::shm_slab_pool::{ShmSlabPool, ShmSlabPoolOptions};
use rust_core::{
    EzShmSlabPool, GrpcResponseStream, IsolateRpcService, PeekableInvokeIsolateRequestStream,
    PinBoxInvokeIsolateResponseStream,
};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{IntoStreamingRequest, Request, Response, Status, Streaming};
use tower::service_fn;

#[derive(Debug, Derivative)]
#[derivative(Default)]
pub struct MockEzIsolateBridge {
    #[derivative(Default(value = "AtomicUsize::new(0)"))]
    call_count: AtomicUsize,
}

impl MockEzIsolateBridge {
    pub fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }
}

#[tonic::async_trait]
impl EzIsolateBridge for MockEzIsolateBridge {
    async fn invoke_isolate(
        &self,
        _request: Request<InvokeIsolateRequest>,
    ) -> Result<Response<InvokeIsolateResponse>, Status> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(InvokeIsolateResponse::default()))
    }

    type StreamInvokeIsolateStream = PinBoxInvokeIsolateResponseStream;
    async fn stream_invoke_isolate(
        &self,
        _request: Request<tonic::Streaming<InvokeIsolateRequest>>,
    ) -> Result<Response<Self::StreamInvokeIsolateStream>, Status> {
        Err(Status::unimplemented("no streaming"))
    }

    async fn update_isolate_state(
        &self,
        _request: Request<enforcer_proto::enforcer::v1::UpdateIsolateStateRequest>,
    ) -> Result<Response<enforcer_proto::enforcer::v1::UpdateIsolateStateResponse>, Status> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(Response::new(enforcer_proto::enforcer::v1::UpdateIsolateStateResponse {
            current_state: enforcer_proto::enforcer::v1::IsolateState::Ready as i32,
        }))
    }
}

#[derive(Debug)]
pub struct TestEzIsolateBridgeClient {
    client: EzIsolateBridgeClient<Channel>,
}

impl TestEzIsolateBridgeClient {
    /// Establishes the connection to the gRPC server over a Unix Domain Socket.
    pub async fn new(server_uds_path: &str) -> Result<Self, anyhow::Error> {
        let uds_uri = format!("http://localhost/{}", server_uds_path);

        let endpoint = Endpoint::from_shared(uds_uri)
            .map_err(|e| anyhow::anyhow!("Invalid UDS URI: {}", e))?;

        // TODO: Add retries if this tests starts to flake
        let channel = endpoint.connect_with_connector_lazy(service_fn(|uri: Uri| async move {
            let path = uri.path();
            let stream = UnixStream::connect(path).await?;
            Ok::<_, std::io::Error>(TokioIo::new(stream))
        }));

        Ok(Self { client: EzIsolateBridgeClient::new(channel) })
    }

    pub async fn invoke_isolate(
        &self,
        request: InvokeIsolateRequest,
    ) -> Result<InvokeIsolateResponse, Status> {
        let mut client = self.client.clone();
        let response = client.invoke_isolate(request).await?.into_inner();
        Ok(response)
    }

    pub async fn stream_invoke_isolate(
        &self,
        request: impl IntoStreamingRequest<Message = InvokeIsolateRequest>,
    ) -> Result<Streaming<InvokeIsolateResponse>, Status> {
        let mut client = self.client.clone();
        let response = client.stream_invoke_isolate(request).await?.into_inner();
        Ok(response)
    }

    pub async fn update_isolate_state(
        &self,
        request: enforcer_proto::enforcer::v1::UpdateIsolateStateRequest,
    ) -> Result<enforcer_proto::enforcer::v1::UpdateIsolateStateResponse, Status> {
        let mut client = self.client.clone();
        let response = client.update_isolate_state(request).await?.into_inner();
        Ok(response)
    }
}

#[derive(Debug, Derivative)]
#[derivative(Default)]
pub struct MockIsolateRpcService {
    #[derivative(Default(value = "Arc::new(AtomicUsize::new(0))"))]
    unary_call_count: Arc<AtomicUsize>,
    #[derivative(Default(value = "Arc::new(AtomicUsize::new(0))"))]
    stream_call_count: Arc<AtomicUsize>,
    #[derivative(Default(value = "Arc::new(AtomicUsize::new(0))"))]
    stream_message_count: Arc<AtomicUsize>,
}

impl MockIsolateRpcService {
    pub fn unary_call_count(&self) -> usize {
        self.unary_call_count.load(Ordering::SeqCst)
    }

    pub fn stream_call_count(&self) -> usize {
        self.stream_call_count.load(Ordering::SeqCst)
    }

    pub fn stream_message_count(&self) -> usize {
        self.stream_message_count.load(Ordering::SeqCst)
    }
}

#[tonic::async_trait]
impl IsolateRpcService for MockIsolateRpcService {
    async fn unary_rpc_handler(
        &self,
        method_name: &str,
        request_bytes: &[u8],
        shm_pool: Option<&EzShmSlabPool>,
    ) -> Result<InvokeIsolateResponse, Status> {
        if method_name != "mock_method" {
            return Err(Status::invalid_argument("Invalid method name"));
        }
        self.unary_call_count.fetch_add(1, Ordering::SeqCst);
        let resp = rust_core::payload_bytes_to_invoke_isolate_response(
            request_bytes.to_vec(),
            DataScopeType::Unspecified,
            shm_pool,
        )
        .await;
        Ok(resp)
    }

    async fn streaming_rpc_handler(
        &self,
        method_name: &str,
        request: Request<PeekableInvokeIsolateRequestStream>,
        shm_pool: Option<EzShmSlabPool>,
    ) -> Result<Response<PinBoxInvokeIsolateResponseStream>, Status> {
        if method_name != "mock_method" {
            return Err(Status::invalid_argument("Invalid method name"));
        }
        self.stream_call_count.fetch_add(1, Ordering::SeqCst);

        let stream_message_count = self.stream_message_count.clone();
        let shm_pool_clone = shm_pool.clone();
        let output_stream = request.into_inner().then(move |req| {
            let stream_message_count = stream_message_count.clone();
            let shm_pool = shm_pool_clone.clone();
            async move {
                stream_message_count.fetch_add(1, Ordering::SeqCst);
                let req = req?;

                use payload_proto::enforcer::v1::ez_hybrid_payload::DeliveryMethod;
                let request_bytes = match req.isolate_input.and_then(|i| i.delivery_method) {
                    Some(DeliveryMethod::InlineData(data)) => data.datagrams.into_iter().next(),
                    Some(DeliveryMethod::ShmData(shm_data)) => {
                        if let Some(shm_pool) = &shm_pool {
                            shm_pool.read_from_enforcer(&shm_data.slots).ok()
                        } else {
                            None
                        }
                    }
                    None => None,
                };
                let request_bytes = request_bytes.unwrap_or_default();

                let resp = rust_core::payload_bytes_to_invoke_isolate_response(
                    request_bytes,
                    DataScopeType::Unspecified,
                    shm_pool.as_ref(),
                )
                .await;
                Ok(resp)
            }
        });

        Ok(Response::new(Box::pin(output_stream)))
    }

    fn service_name(&self) -> &str {
        "mock_service"
    }
}

#[derive(Debug)]
pub struct ErrorIsolateRpcService;

#[tonic::async_trait]
impl IsolateRpcService for ErrorIsolateRpcService {
    async fn unary_rpc_handler(
        &self,
        _method_name: &str,
        _request_bytes: &[u8],
        _shm_pool: Option<&EzShmSlabPool>,
    ) -> Result<InvokeIsolateResponse, Status> {
        Err(Status::unimplemented("Internal error"))
    }

    async fn streaming_rpc_handler(
        &self,
        _method_name: &str,
        _request: Request<PeekableInvokeIsolateRequestStream>,
        _shm_pool: Option<EzShmSlabPool>,
    ) -> Result<Response<PinBoxInvokeIsolateResponseStream>, Status> {
        Err(Status::unimplemented("Internal error"))
    }

    fn service_name(&self) -> &str {
        "error_service"
    }
}

#[derive(Debug, Derivative, Clone)]
#[derivative(Default)]
pub struct MockIsolateEzBridgeServer {
    #[derivative(Default(value = "Arc::new(AtomicUsize::new(0))"))]
    unary_call_count: Arc<AtomicUsize>,
    #[derivative(Default(value = "Arc::new(AtomicUsize::new(0))"))]
    stream_call_count: Arc<AtomicUsize>,
    #[derivative(Default(value = "Arc::new(AtomicUsize::new(0))"))]
    stream_message_count: Arc<AtomicUsize>,
    #[derivative(Default(value = "Arc::new(Mutex::new(None))"))]
    last_known_state: Arc<Mutex<Option<i32>>>,
    #[derivative(Default(value = "Arc::new(Mutex::new(None))"))]
    last_received_request: Arc<Mutex<Option<InvokeEzRequest>>>,
    #[derivative(Default(value = "Arc::new(Mutex::new(false))"))]
    force_shm_response: Arc<Mutex<bool>>,
}

impl MockIsolateEzBridgeServer {
    pub fn unary_call_count(&self) -> usize {
        self.unary_call_count.load(Ordering::SeqCst)
    }

    pub fn stream_call_count(&self) -> usize {
        self.stream_call_count.load(Ordering::SeqCst)
    }

    pub fn stream_message_count(&self) -> usize {
        self.stream_message_count.load(Ordering::SeqCst)
    }

    pub async fn last_known_state(&self) -> Option<i32> {
        *self.last_known_state.lock().await
    }

    pub async fn last_received_request(&self) -> Option<InvokeEzRequest> {
        self.last_received_request.lock().await.clone()
    }

    pub async fn set_force_shm_response(&self, force: bool) {
        *self.force_shm_response.lock().await = force;
    }
}

#[tonic::async_trait]
impl IsolateEzBridge for MockIsolateEzBridgeServer {
    async fn invoke_ez(
        &self,
        request: Request<InvokeEzRequest>,
    ) -> Result<Response<InvokeEzResponse>, Status> {
        let req = request.into_inner();
        *self.last_received_request.lock().await = Some(req.clone());
        self.unary_call_count.fetch_add(1, Ordering::SeqCst);

        let force_shm = *self.force_shm_response.lock().await;
        let resp = validate_and_process_invoke_ez(req, "mock_", force_shm).await?;
        Ok(Response::new(resp))
    }

    type StreamInvokeEzStream = Pin<Box<dyn GrpcResponseStream<InvokeEzResponse>>>;
    async fn stream_invoke_ez(
        &self,
        request: Request<Streaming<InvokeEzRequest>>,
    ) -> Result<Response<Self::StreamInvokeEzStream>, Status> {
        self.stream_call_count.fetch_add(1, Ordering::SeqCst);
        let stream_message_count = self.stream_message_count.clone();
        let force_shm_response = self.force_shm_response.clone();

        let output_stream = request.into_inner().then(move |req| {
            let stream_message_count = stream_message_count.clone();
            let force_shm_response = force_shm_response.clone();
            async move {
                stream_message_count.fetch_add(1, Ordering::SeqCst);
                let Ok(req) = req else {
                    return Err(Status::invalid_argument("Request should be Ok"));
                };

                let force_shm = *force_shm_response.lock().await;
                validate_and_process_invoke_ez(req, "stream_mock_", force_shm).await
            }
        });

        Ok(Response::new(Box::pin(output_stream)))
    }

    type CreateMemshareStream = Pin<Box<dyn GrpcResponseStream<CreateMemshareResponse>>>;
    async fn create_memshare(
        &self,
        _request: Request<Streaming<CreateMemshareRequest>>,
    ) -> Result<Response<Self::CreateMemshareStream>, Status> {
        Err(Status::unimplemented("unimplemented"))
    }

    type NotifyIsolateStateStream = Pin<Box<dyn GrpcResponseStream<NotifyIsolateStateResponse>>>;
    async fn notify_isolate_state(
        &self,
        request: Request<Streaming<NotifyIsolateStateRequest>>,
    ) -> Result<Response<Self::NotifyIsolateStateStream>, Status> {
        let last_known_state = self.last_known_state.clone();
        let output_stream = request.into_inner().then(move |req| {
            let last_known_state = last_known_state.clone();
            async move {
                let req = req.expect("Request should be Ok");
                let mut state = last_known_state.lock().await;
                *state = Some(req.new_isolate_state);
                Ok(NotifyIsolateStateResponse::default())
            }
        });
        Ok(Response::new(Box::pin(output_stream)))
    }

    async fn poll_isolate_state(
        &self,
        _request: Request<PollIsolateStateRequest>,
    ) -> Result<Response<PollIsolateStateResponse>, Status> {
        let state = self.last_known_state.lock().await;

        Ok(Response::new(PollIsolateStateResponse { isolate_state: state.unwrap_or(0) }))
    }

    async fn create_fileshare(
        &self,
        _request: Request<CreateFileshareRequest>,
    ) -> Result<Response<CreateFileshareResponse>, Status> {
        Err(Status::unimplemented("unimplemented"))
    }

    async fn publish_event_for(
        &self,
        _request: Request<PublishEventForRequest>,
    ) -> Result<Response<PublishEventForResponse>, Status> {
        Err(Status::unimplemented("unimplemented"))
    }

    type StreamSubscribeToStream = ReceiverStream<Result<StreamSubscribeToResponse, Status>>;
    async fn stream_subscribe_to(
        &self,
        _request: Request<StreamSubscribeToRequest>,
    ) -> Result<Response<Self::StreamSubscribeToStream>, Status> {
        Err(Status::unimplemented("unimplemented"))
    }
}

async fn validate_and_process_invoke_ez(
    req: InvokeEzRequest,
    prefix: &str,
    force_shm: bool,
) -> Result<InvokeEzResponse, Status> {
    let Some(control_plane_metadata) = req.control_plane_metadata else {
        return Err(Status::invalid_argument("Control plane metadata is required"));
    };

    if !control_plane_metadata.requester_is_local {
        return Err(Status::invalid_argument("Requester is not local"));
    }
    if let Some(payload_scope) = req.isolate_request_iscope {
        if payload_scope.datagram_iscopes.len() != 1 {
            return Err(Status::invalid_argument("Datagram scopes are required"));
        }
        let datagram_scope = &payload_scope.datagram_iscopes[0];
        if datagram_scope.scope_type != DataScopeType::UserPrivate as i32 {
            return Err(Status::invalid_argument("Datagram id is required"));
        }
    } else {
        return Err(Status::invalid_argument("Payload scope is required"));
    }
    let request_bytes = match req.isolate_request_payload.clone().and_then(|p| p.delivery_method) {
        Some(DeliveryMethod::InlineData(data)) => {
            data.datagrams.into_iter().next().unwrap_or_default()
        }
        Some(DeliveryMethod::ShmData(shm_data)) => match MockEzShmSlabPool::new() {
            Ok(mock_pool) => match mock_pool.read_request(&shm_data.slots) {
                Ok(payload_bytes) => payload_bytes,
                Err(err) => {
                    return Err(Status::internal(format!(
                        "Failed to read from isolate shared memory pool: {:?}",
                        err
                    )));
                }
            },
            Err(err) => {
                return Err(Status::internal(format!(
                    "Failed to initialize MockEzShmSlabPool: {:?}",
                    err
                )));
            }
        },
        None => Vec::new(),
    };

    let ez_response_payload = if force_shm {
        match MockEzShmSlabPool::new() {
            Ok(mock_pool) => match mock_pool.write_response(&request_bytes).await {
                Ok(slots) => Some(EzHybridPayload {
                    delivery_method: Some(DeliveryMethod::ShmData(
                        payload_proto::enforcer::v1::ShmSlotData { slots },
                    )),
                }),
                Err(err) => {
                    return Err(Status::internal(format!(
                        "Mock server failed to write response to shared memory: {:?}",
                        err
                    )));
                }
            },
            Err(err) => {
                return Err(Status::internal(format!(
                    "Mock server failed to initialize MockEzShmSlabPool: {:?}",
                    err
                )));
            }
        }
    } else {
        Some(EzHybridPayload {
            delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                datagrams: vec![request_bytes],
            })),
        })
    };

    Ok(InvokeEzResponse {
        control_plane_metadata: Some(ControlPlaneMetadata {
            ipc_message_id: control_plane_metadata.ipc_message_id,
            destination_ez_instance_id: format!("{}instance_id", prefix),
            destination_service_name: format!("{}service_name", prefix),
            destination_method_name: format!("{}method_name", prefix),
            destination_operator_domain: format!("{}operator_domain", prefix),
            responder_is_local: true,
            ..Default::default()
        }),
        ez_response_payload,
        ..Default::default()
    })
}

/// Wrapper facilitating shared memory slab communication on the mock/server/enforcer side.
#[derive(Clone, Debug)]
pub struct MockEzShmSlabPool {
    enforcer_writes_pool: Arc<ShmSlabPool>, // write to
    isolate_writes_pool: Arc<ShmSlabPool>,  // read from
}

impl MockEzShmSlabPool {
    /// Creates and initializes the mock shared memory slab pools using
    /// configuration specified in environment variables:
    /// - `EZ_SHM_NUM_SLOTS`: Total block slots.
    /// - `EZ_SHM_SLOT_SIZE`: Slot block size in bytes.
    /// - `EZ_SHM_ENFORCER_WRITES_PATH`: Filesystem path to enforcer writes pool.
    /// - `EZ_SHM_ISOLATE_WRITES_PATH`: Filesystem path to isolate writes pool.
    pub fn new() -> anyhow::Result<Self> {
        let num_slots = std::env::var("EZ_SHM_NUM_SLOTS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1024);

        let slot_size = std::env::var("EZ_SHM_SLOT_SIZE")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5 * 1024 * 1024);

        let enforcer_shm_path = std::env::var("EZ_SHM_ENFORCER_WRITES_PATH")
            .unwrap_or_else(|_| "/enforcer-isolate-shared/enforcer-writes".to_string());

        let isolate_shm_path = std::env::var("EZ_SHM_ISOLATE_WRITES_PATH")
            .unwrap_or_else(|_| "/enforcer-isolate-shared/isolate-writes".to_string());

        let enforcer_writes_pool = Arc::new(ShmSlabPool::new(ShmSlabPoolOptions {
            file_name: enforcer_shm_path,
            number_of_slots: num_slots,
            slot_size,
            writer: true,  // Mock writes to enforcer-writes
            create: false, // Backing files created by TestShmSlabPools
        })?);

        let isolate_writes_pool = Arc::new(ShmSlabPool::new(ShmSlabPoolOptions {
            file_name: isolate_shm_path,
            number_of_slots: num_slots,
            slot_size,
            writer: false, // Mock only reads from isolate-writes
            create: false, // Backing files created by TestShmSlabPools
        })?);

        Ok(Self { enforcer_writes_pool, isolate_writes_pool })
    }

    /// Reads incoming request payload from isolate-writes pool.
    pub fn read_request(&self, slot_references: &[ShmSlotReference]) -> anyhow::Result<Vec<u8>> {
        self.isolate_writes_pool.read_from_pool(slot_references).map_err(Into::into)
    }

    /// Writes outgoing response payload to enforcer-writes pool.
    pub async fn write_response(&self, payload: &[u8]) -> anyhow::Result<Vec<ShmSlotReference>> {
        self.enforcer_writes_pool.write_to_pool(payload).await.map_err(Into::into)
    }
}

/// Helper structure to construct and manage shared memory slab pools for tests.
///
/// Under RAII, environment variables set by the constructor are automatically
/// cleaned up when the `TestShmSlabPools` goes out of scope, preventing environment
/// leakage between test cases.
#[derive(Debug)]
pub struct TestShmSlabPools {
    pub enforcer_pool: Arc<ShmSlabPool>,
    pub isolate_pool: Arc<ShmSlabPool>,
}

impl TestShmSlabPools {
    /// Creates back-to-back shared memory slab pools under `dir`, initializes the backing files,
    /// and configures corresponding `EZ_SHM_*` environment variables.
    pub fn new(dir: &std::path::Path, number_of_slots: u64, slot_size: u64) -> Self {
        let enforcer_path = dir.join("enforcer_writes").to_string_lossy().to_string();
        let isolate_path = dir.join("isolate_writes").to_string_lossy().to_string();

        let enforcer_pool = Arc::new(
            ShmSlabPool::new(ShmSlabPoolOptions {
                file_name: enforcer_path.clone(),
                number_of_slots,
                slot_size,
                writer: true,
                create: true,
            })
            .expect("Failed to initialize enforcer_writes backing pool for test"),
        );

        let isolate_pool = Arc::new(
            ShmSlabPool::new(ShmSlabPoolOptions {
                file_name: isolate_path.clone(),
                number_of_slots,
                slot_size,
                writer: true,
                create: true,
            })
            .expect("Failed to initialize isolate_writes backing pool for test"),
        );

        std::env::set_var("EZ_SHM_NUM_SLOTS", number_of_slots.to_string());
        std::env::set_var("EZ_SHM_SLOT_SIZE", slot_size.to_string());
        std::env::set_var("EZ_SHM_ENFORCER_WRITES_PATH", &enforcer_path);
        std::env::set_var("EZ_SHM_ISOLATE_WRITES_PATH", &isolate_path);

        Self { enforcer_pool, isolate_pool }
    }
}

impl Drop for TestShmSlabPools {
    fn drop(&mut self) {
        std::env::remove_var("EZ_SHM_NUM_SLOTS");
        std::env::remove_var("EZ_SHM_SLOT_SIZE");
        std::env::remove_var("EZ_SHM_ENFORCER_WRITES_PATH");
        std::env::remove_var("EZ_SHM_ISOLATE_WRITES_PATH");
        std::env::remove_var("EZ_SHM_PAYLOAD_THRESHOLD");
        std::env::remove_var("EZ_SHM_THRESHOLD");
    }
}
