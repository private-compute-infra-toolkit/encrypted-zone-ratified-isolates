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
use enforcer_proto::enforcer::v1::ez_isolate_bridge_client::EzIsolateBridgeClient;
use enforcer_proto::enforcer::v1::isolate_ez_bridge_server::{
    IsolateEzBridge, IsolateEzBridgeServer,
};
use enforcer_proto::enforcer::v1::{
    ControlPlaneMetadata, CreateFileshareRequest, CreateFileshareResponse, CreateMemshareRequest,
    CreateMemshareResponse, InvokeEzRequest, InvokeEzResponse, InvokeIsolateRequest, IsolateState,
    NotifyIsolateStateRequest, NotifyIsolateStateResponse, PollIsolateStateRequest,
    PollIsolateStateResponse, PublishEventForRequest, PublishEventForResponse,
    StreamSubscribeToRequest, StreamSubscribeToResponse,
};
use hyper_util::rt::TokioIo;
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use once_cell::sync::Lazy;
use payload_proto::enforcer::v1::{
    EzHybridPayload, EzPayloadData, ez_hybrid_payload::DeliveryMethod,
};
use prost::Message;
use setup_isolate_proto::setup_isolate::v1::{
    FetchFrontendTlsCertificateRequest, FetchFrontendTlsCertificateResponse,
    FetchTlsCertificateRequest, FetchTlsCertificateResponse, GetTlsCsrRequest,
};
use std::env;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Sender, channel};
use tokio::time::{Duration, sleep};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Endpoint, Server, Uri};
use tonic::{Request, Response, Status, Streaming};
use tower::service_fn;
static SERVER_UDS_PATH: Lazy<String> =
    Lazy::new(|| env::var("SERVER_UDS_PATH").expect("Required env var"));
static READY_FIFO_PATH: Lazy<String> =
    Lazy::new(|| env::var("READY_FIFO_PATH").expect("Required env var"));
static CLIENT_UDS_PATH: Lazy<String> =
    Lazy::new(|| env::var("CLIENT_UDS_PATH").expect("Required env var"));

const CHANNEL_SIZE: usize = 256;
async fn test_unimplemented_method<T: Message>(method_name: &str, request_msg: T) {
    let harness = TestHarness::start()
        .await
        .expect("Test harness should start");
    // 1. Verify Isolate State is marked READY
    let final_state = *harness.service.latest_state.lock().await;
    assert_eq!(final_state, Some(IsolateState::Ready));
    // 2. Set up client-side communication channel over RpcDispatcher's EzIsolateBridge protocol
    let (request_tx, request_rx) = channel::<InvokeIsolateRequest>(128);
    let mut client = harness.client.clone();
    let response = client
        .stream_invoke_isolate(ReceiverStream::new(request_rx))
        .await
        .unwrap();
    let mut stream = response.into_inner();
    // 3. Construct request
    let request_bytes = request_msg.encode_to_vec();
    let invoke_request = InvokeIsolateRequest {
        control_plane_metadata: Some(ControlPlaneMetadata {
            ipc_message_id: rand::random(),
            destination_operator_domain: "ServerDomain".to_string(),
            destination_service_name: "SetupService".to_string(),
            destination_method_name: method_name.to_string(),
            ..Default::default()
        }),
        isolate_input: Some(EzHybridPayload {
            delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                datagrams: vec![request_bytes],
            })),
        }),
        ..Default::default()
    };
    // 4. Send request
    request_tx.send(invoke_request).await.unwrap();
    // 5. Receive and verify response
    let res = stream
        .next()
        .await
        .expect("Stream closed before receiving response!");
    assert_eq!(res.unwrap_err().code(), tonic::Code::Unimplemented);
    harness.stop().await.expect("Harness should stop");
}
#[tokio::test]
async fn test_get_tls_csr() {
    test_unimplemented_method("GetTlsCsr", GetTlsCsrRequest::default()).await;
}
#[tokio::test]
async fn test_fetch_mtls_certificate_success() {
    let harness = TestHarness::start().await.expect("Harness should start");
    let mut client = harness.client.clone();
    let request_msg = FetchTlsCertificateRequest {
        signed_certificate_signing_request: vec![10, 20, 30],
    };
    let invoke_request = InvokeIsolateRequest {
        control_plane_metadata: Some(ControlPlaneMetadata {
            ipc_message_id: rand::random(),
            destination_operator_domain: "ServerDomain".to_string(),
            destination_service_name: "SetupService".to_string(),
            destination_method_name: "FetchMtlsCertificate".to_string(),
            ..Default::default()
        }),
        isolate_input: Some(EzHybridPayload {
            delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                datagrams: vec![request_msg.encode_to_vec()],
            })),
        }),
        ..Default::default()
    };
    let invoke_resp = client
        .invoke_isolate(invoke_request)
        .await
        .unwrap()
        .into_inner();
    let payload = invoke_resp.isolate_output.unwrap();
    let mut response_bytes = match payload.delivery_method {
        Some(DeliveryMethod::InlineData(data)) => data.datagrams,
        _ => panic!("Expected InlineData"),
    };
    let response_msg =
        FetchTlsCertificateResponse::decode(response_bytes.pop().unwrap().as_slice()).unwrap();
    assert_eq!(response_msg.certificate_chain, vec![vec![1, 2, 3, 4]]);
    assert_eq!(response_msg.trust_anchors, vec![vec![5, 6, 7, 8]]);
    harness.stop().await.expect("Harness should stop");
}
#[tokio::test]
async fn test_fetch_frontend_tls_certificate_success() {
    let harness = TestHarness::start().await.expect("Harness should start");
    let mut client = harness.client.clone();
    let request_msg = FetchFrontendTlsCertificateRequest {
        signed_certificate_signing_request: vec![1, 2, 3],
    };
    let invoke_request = InvokeIsolateRequest {
        control_plane_metadata: Some(ControlPlaneMetadata {
            ipc_message_id: rand::random(),
            destination_operator_domain: "ServerDomain".to_string(),
            destination_service_name: "SetupService".to_string(),
            destination_method_name: "FetchFrontendTlsCertificate".to_string(),
            ..Default::default()
        }),
        isolate_input: Some(EzHybridPayload {
            delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                datagrams: vec![request_msg.encode_to_vec()],
            })),
        }),
        ..Default::default()
    };
    let invoke_resp = client
        .invoke_isolate(invoke_request)
        .await
        .unwrap()
        .into_inner();
    let payload = invoke_resp.isolate_output.unwrap();
    let mut response_bytes = match payload.delivery_method {
        Some(DeliveryMethod::InlineData(data)) => data.datagrams,
        _ => panic!("Expected InlineData"),
    };
    let response_msg =
        FetchFrontendTlsCertificateResponse::decode(response_bytes.pop().unwrap().as_slice())
            .unwrap();
    assert_eq!(response_msg.certificate_chain, vec![vec![1, 2, 3, 4]]);
    assert_eq!(response_msg.trust_anchors, vec![vec![5, 6, 7, 8]]);
    harness.stop().await.expect("Harness should stop");
}
#[derive(Debug, Default, Clone)]
struct MockIsolateEzBridge {
    latest_state: Arc<Mutex<Option<IsolateState>>>,
}
#[tonic::async_trait]
impl IsolateEzBridge for MockIsolateEzBridge {
    type StreamInvokeEzStream = ReceiverStream<Result<InvokeEzResponse, Status>>;
    async fn stream_invoke_ez(
        &self,
        _request: Request<Streaming<InvokeEzRequest>>,
    ) -> Result<Response<Self::StreamInvokeEzStream>, Status> {
        Err(Status::internal(
            "mocked internal error for stream_invoke_ez",
        ))
    }
    async fn invoke_ez(
        &self,
        request: Request<InvokeEzRequest>,
    ) -> Result<Response<InvokeEzResponse>, Status> {
        let req = request.into_inner();
        let metadata = req.control_plane_metadata.expect("Metadata required");
        if metadata.destination_operator_domain == "thick/avs-proxy" {
            let payload = req.isolate_request_payload.expect("Payload required");
            let request_bytes = match payload.delivery_method {
                Some(
                    payload_proto::enforcer::v1::ez_hybrid_payload::DeliveryMethod::InlineData(
                        mut data,
                    ),
                ) => data.datagrams.pop().expect("Datagram required"),
                _ => return Err(Status::internal("Invalid delivery method")),
            };
            let get_cert_req = ez_mtls_proto::enforcer::v1::GetCertificateRequest::decode(
                request_bytes.as_slice(),
            )
            .map_err(|e| {
                Status::invalid_argument(format!("Failed to decode GetCertificateRequest: {}", e))
            })?;
            if get_cert_req.policy_hint
                == ez_mtls_proto::enforcer::v1::PolicyHint::BackendMtlsCert as i32
                || get_cert_req.policy_hint
                    == ez_mtls_proto::enforcer::v1::PolicyHint::FrontendTlsCert as i32
            {
                assert_eq!(get_cert_req.operator_role, "test_operator");
            } else {
                panic!("Invalid policy hint");
            }
            let fake_cert_response = ez_mtls_proto::enforcer::v1::GetCertificateResponse {
                certs: vec![vec![1, 2, 3, 4], vec![5, 6, 7, 8]],
            };
            let mut response_bytes = Vec::new();
            fake_cert_response
                .encode(&mut response_bytes)
                .map_err(|e| {
                    Status::internal(format!("Failed to encode GetCertificateResponse: {}", e))
                })?;
            Ok(Response::new(InvokeEzResponse {
                control_plane_metadata: Some(ControlPlaneMetadata {
                    ipc_message_id: metadata.ipc_message_id,
                    ..Default::default()
                }),
                ez_response_payload: Some(EzHybridPayload {
                    delivery_method: Some(
                        payload_proto::enforcer::v1::ez_hybrid_payload::DeliveryMethod::InlineData(
                            payload_proto::enforcer::v1::EzPayloadData {
                                datagrams: vec![response_bytes],
                            },
                        ),
                    ),
                }),
                ..Default::default()
            }))
        } else {
            Err(Status::unimplemented(format!(
                "Method {} not implemented in Mock Enforcer",
                metadata.destination_method_name
            )))
        }
    }
    type CreateMemshareStream = ReceiverStream<Result<CreateMemshareResponse, Status>>;
    async fn create_memshare(
        &self,
        _request: Request<Streaming<CreateMemshareRequest>>,
    ) -> Result<Response<Self::CreateMemshareStream>, Status> {
        Err(Status::internal(
            "mocked internal error for create_memshare",
        ))
    }
    type NotifyIsolateStateStream = ReceiverStream<Result<NotifyIsolateStateResponse, Status>>;
    async fn notify_isolate_state(
        &self,
        request: Request<Streaming<NotifyIsolateStateRequest>>,
    ) -> Result<Response<Self::NotifyIsolateStateStream>, Status> {
        let mut stream = request.into_inner();
        let (tx, rx) = channel(CHANNEL_SIZE);
        let latest_state = self.latest_state.clone();
        tokio::spawn(async move {
            while let Some(msg) = stream.next().await {
                if let Ok(req) = msg {
                    let state = IsolateState::try_from(req.new_isolate_state)
                        .unwrap_or(IsolateState::Unspecified);
                    *latest_state.lock().await = Some(state);
                    let _ = tx.send(Ok(NotifyIsolateStateResponse::default())).await;
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
    async fn poll_isolate_state(
        &self,
        _request: Request<PollIsolateStateRequest>,
    ) -> Result<Response<PollIsolateStateResponse>, Status> {
        Err(Status::internal(
            "mocked internal error for poll_isolate_state",
        ))
    }
    async fn create_fileshare(
        &self,
        _request: Request<CreateFileshareRequest>,
    ) -> Result<Response<CreateFileshareResponse>, Status> {
        Err(Status::internal(
            "mocked internal error for create_fileshare",
        ))
    }
    async fn publish_event_for(
        &self,
        _request: Request<PublishEventForRequest>,
    ) -> Result<Response<PublishEventForResponse>, Status> {
        Err(Status::internal(
            "mocked internal error for publish_event_for",
        ))
    }
    type StreamSubscribeToStream = ReceiverStream<Result<StreamSubscribeToResponse, Status>>;
    async fn stream_subscribe_to(
        &self,
        _request: Request<StreamSubscribeToRequest>,
    ) -> Result<Response<Self::StreamSubscribeToStream>, Status> {
        Err(Status::internal(
            "mocked internal error for stream_subscribe_to",
        ))
    }
}
#[derive(Debug)]
struct TestHarness {
    client: EzIsolateBridgeClient<tonic::transport::Channel>,
    service: MockIsolateEzBridge,
    server_handle: Option<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>>,
    fake_server_shutdown_tx: Sender<()>,
    process: Option<Child>,
}
impl TestHarness {
    async fn start() -> anyhow::Result<Self> {
        // Ensure parent directory for UDS and FIFO exists.
        let server_uds_path = Path::new(SERVER_UDS_PATH.as_str());
        if let Some(parent) = server_uds_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                anyhow::anyhow!("Failed to create parent dir {}: {}", parent.display(), e)
            })?;
        }
        // Clean up any old socket/FIFO files that might exist.
        for path in [
            SERVER_UDS_PATH.as_str(),
            CLIENT_UDS_PATH.as_str(),
            READY_FIFO_PATH.as_str(),
        ] {
            if Path::new(path).exists() {
                tokio::fs::remove_file(path)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to remove file {}: {}", path, e))?;
            }
        }
        // Create the ready signal FIFO path
        mkfifo(READY_FIFO_PATH.as_str(), Mode::S_IRWXU)
            .map_err(|e| anyhow::anyhow!("Failed to create FIFO path {}", e))?;
        let uds = UnixListener::bind(CLIENT_UDS_PATH.as_str())
            .expect("Should be able to bind to client UDS path");
        let uds_stream = UnixListenerStream::new(uds);
        // This sets up and runs the fake enforcer gRPC server that the IsolateRpcServer will connect to.
        let isolate_ez_service = MockIsolateEzBridge::default();
        let (fake_server_shutdown_tx, mut fake_server_shutdown_rx) = channel(1);
        let service_clone = isolate_ez_service.clone();
        let server_handle = tokio::spawn(async move {
            Server::builder()
                .add_service(IsolateEzBridgeServer::new(service_clone))
                .serve_with_incoming_shutdown(uds_stream, async move {
                    fake_server_shutdown_rx.recv().await;
                })
                .await
        });
        // Spawn the setup_isolate binary
        use runfiles::Runfiles;
        let r =
            Runfiles::create().map_err(|e| anyhow::anyhow!("Failed to create runfiles: {}", e))?;
        let binary_path = r
            .rlocation("_main/setup_isolate")
            .ok_or_else(|| anyhow::anyhow!("Could not find setup_isolate in runfiles"))?;
        let mut command = Command::new(binary_path);
        command.kill_on_drop(true);
        command
            .env("SERVER_UDS_PATH", SERVER_UDS_PATH.as_str())
            .env("CLIENT_UDS_PATH", CLIENT_UDS_PATH.as_str())
            .env("READY_FIFO_PATH", READY_FIFO_PATH.as_str())
            .env("EZ_OPERATOR_ROLE", "test_operator")
            .arg("--otel-metrics-endpoint")
            .arg("disabled")
            .arg("--otel-traces-endpoint")
            .arg("disabled")
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit());
        let child = command
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn setup_isolate: {}", e))?;
        // Signal ready by opening the FIFO for writing.
        // This blocks until the server also opens it for reading.
        let _ = tokio::fs::OpenOptions::new()
            .write(true)
            .open(READY_FIFO_PATH.as_str())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to open ready FIFO: {}", e))?;
        // Initialize the client with a Retry Loop guaranteeing that the server IPC listener is online
        let uds_uri = format!("http://localhost/{}", SERVER_UDS_PATH.as_str());
        let endpoint = Endpoint::from_shared(uds_uri)
            .map_err(|e| anyhow::anyhow!("Invalid UDS URI: {}", e))?;
        let mut channel = None;
        for _ in 0..20 {
            if let Ok(c) = endpoint
                .connect_with_connector(service_fn(|uri: Uri| async move {
                    let path = uri.path();
                    let stream = tokio::net::UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }))
                .await
            {
                channel = Some(c);
                break;
            }
            sleep(Duration::from_millis(100)).await;
        }
        let channel = channel
            .ok_or_else(|| anyhow::anyhow!("Failed to connect to UDS server after retries"))?;
        let client = EzIsolateBridgeClient::new(channel);
        Ok(Self {
            client,
            service: isolate_ez_service,
            server_handle: Some(server_handle),
            fake_server_shutdown_tx,
            process: Some(child),
        })
    }
    async fn stop(mut self) -> anyhow::Result<()> {
        if let Some(mut child) = self.process.take() {
            child
                .kill()
                .await
                .map_err(|e| anyhow::anyhow!("Failed to kill setup_isolate: {}", e))?;
        }
        // Stop the fake enforcer server.
        self.fake_server_shutdown_tx.send(()).await?;
        if let Some(handle) = self.server_handle.take() {
            handle
                .await
                .map_err(|e| anyhow::anyhow!("Fake enforcer server task panicked: {}", e))?
                .map_err(|e| anyhow::anyhow!("Fake enforcer server failed: {}", e))?;
        }
        Ok(())
    }
}
impl Drop for TestHarness {
    fn drop(&mut self) {
        for path in [
            SERVER_UDS_PATH.as_str(),
            CLIENT_UDS_PATH.as_str(),
            READY_FIFO_PATH.as_str(),
        ] {
            let path = Path::new(path);
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
        }
        if let Some(parent) = Path::new(SERVER_UDS_PATH.as_str()).parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}
