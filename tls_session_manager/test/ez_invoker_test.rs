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

use enforcer_proto::data_scope_proto::enforcer::v1::DataScopeType;
use enforcer_proto::enforcer::v1::isolate_ez_bridge_server::{
    IsolateEzBridge, IsolateEzBridgeServer,
};
use enforcer_proto::enforcer::v1::{
    ControlPlaneMetadata, CreateFileshareRequest, CreateFileshareResponse, CreateMemshareRequest,
    CreateMemshareResponse, InvokeEzRequest, InvokeEzResponse, NotifyIsolateStateRequest,
    NotifyIsolateStateResponse, PollIsolateStateRequest, PollIsolateStateResponse,
    PublishEventForRequest, PublishEventForResponse, StreamSubscribeToRequest,
    StreamSubscribeToResponse,
};
use payload_proto::enforcer::v1::{
    ez_hybrid_payload::DeliveryMethod, EzHybridPayload, EzPayloadData,
};
use prost::Message;
use setup_isolate_proto::setup_isolate::v1::{
    FetchFrontendTlsCertificateRequest, FetchFrontendTlsCertificateResponse,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tempfile::TempDir;
use tls_session_manager::ez_invoker::{BridgeEzInvoker, EzInvoker};
use tls_session_manager::InvokeConfig;
use tls_session_manager_sdk::IsolateEzBridgeSdkClient;
use tokio::net::UnixListener;
use tokio::sync::{oneshot, Mutex};
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

const SIMULATED_FAILURES: usize = 2;
const CONCURRENT_CALLS: usize = 4;
// With base_delay = 1s and scaling = 2, 2 jittered retries are strictly bounded
// above by 2s + 4s = 6s; if base and scaling are swapped, retry 2 hits the 60s
// cap (~31s expected per call).
const TWO_RETRY_TIMEOUT: Duration = Duration::from_secs(8);

// IsolateEzBridgeSdkClient caches CLIENT_UDS_PATH in a process-wide Lazy on first call,
// so all sequential tests in this binary reuse a single TempDir path.
static TEST_UDS_DIR: OnceLock<TempDir> = OnceLock::new();

#[tokio::test]
async fn test_fetch_frontend_certificate_sends_public_scope_and_setup_service_metadata() {
    let harness = TestHarness::start().await.expect("Failed to start TestHarness");
    let invoker = new_invoker(&harness);

    let csr = b"valid-csr".to_vec();
    let resp = invoker
        .fetch_frontend_certificate(FetchFrontendTlsCertificateRequest {
            signed_certificate_signing_request: csr.clone(),
        })
        .await
        .expect("fetch_frontend_certificate should succeed");
    assert_eq!(resp.certificate_chain, vec![[b"cert-for-".as_slice(), csr.as_slice()].concat()]);
    assert_eq!(resp.trust_anchors, vec![b"test-trust-anchor".to_vec()]);
    assert_eq!(harness.mock_server.call_count(), 1);

    let captured = harness.mock_server.captured_requests().await;
    assert_eq!(captured.len(), 1);
    let iscope = captured[0].isolate_request_iscope.as_ref().expect("Expected request iscope");
    assert_eq!(iscope.datagram_iscopes.len(), 1);
    assert_eq!(iscope.datagram_iscopes[0].scope_type, DataScopeType::Public as i32);
    let metadata =
        captured[0].control_plane_metadata.as_ref().expect("Expected control plane metadata");
    assert_eq!(metadata.destination_operator_domain, "EZ_Trusted");
    assert_eq!(metadata.destination_service_name, "SetupService");
    assert_eq!(metadata.destination_method_name, "FetchFrontendTlsCertificate");

    harness.stop().await;
}

#[tokio::test]
async fn test_fetch_frontend_certificate_fails_fast_on_non_retryable_status() {
    let harness = TestHarness::start().await.expect("Failed to start TestHarness");
    let invoker = new_invoker(&harness);

    for non_retryable in
        [Status::invalid_argument("invalid CSR"), Status::unauthenticated("unauthenticated caller")]
    {
        let expected_code = non_retryable.code();
        let bad_csr = b"bad-csr".to_vec();
        // Plan 2 failures to prove no retry is attempted.
        harness
            .mock_server
            .reset_csr_failures(
                std::iter::once((bad_csr.clone(), SIMULATED_FAILURES)).collect(),
                non_retryable,
            )
            .await;
        let err = tokio::time::timeout(
            Duration::from_secs(1),
            invoker.fetch_frontend_certificate(FetchFrontendTlsCertificateRequest {
                signed_certificate_signing_request: bad_csr,
            }),
        )
        .await
        .expect("Non-retryable status timed out")
        .expect_err("Non-retryable status should fail immediately");
        assert_eq!(err.code(), expected_code);
        assert_eq!(harness.mock_server.call_count(), 1);
    }

    harness.stop().await;
}

#[tokio::test]
async fn test_fetch_frontend_certificate_retries_on_unavailable() {
    let harness = TestHarness::start().await.expect("Failed to start TestHarness");
    let invoker = new_invoker(&harness);

    let csrs: [Vec<u8>; CONCURRENT_CALLS] =
        std::array::from_fn(|i| format!("retry-csr-{i}").into_bytes());
    harness
        .mock_server
        .reset_csr_failures(
            csrs.iter().cloned().map(|csr| (csr, SIMULATED_FAILURES)).collect(),
            Status::unavailable("SetupService temporarily unavailable"),
        )
        .await;

    let [c0, c1, c2, c3] = &csrs;
    let (r0, r1, r2, r3) = tokio::time::timeout(TWO_RETRY_TIMEOUT, async {
        tokio::join!(
            invoker.fetch_frontend_certificate(FetchFrontendTlsCertificateRequest {
                signed_certificate_signing_request: c0.clone(),
            }),
            invoker.fetch_frontend_certificate(FetchFrontendTlsCertificateRequest {
                signed_certificate_signing_request: c1.clone(),
            }),
            invoker.fetch_frontend_certificate(FetchFrontendTlsCertificateRequest {
                signed_certificate_signing_request: c2.clone(),
            }),
            invoker.fetch_frontend_certificate(FetchFrontendTlsCertificateRequest {
                signed_certificate_signing_request: c3.clone(),
            }),
        )
    })
    .await
    .expect(
        "2 exponential backoff retries timed out (ExponentialBackoff base/factor may be swapped)",
    );

    for (csr, res) in csrs.iter().zip([r0, r1, r2, r3]) {
        let resp = res.expect("Transient UNAVAILABLE errors should retry and succeed");
        assert_eq!(
            resp.certificate_chain,
            vec![[b"cert-for-".as_slice(), csr.as_slice()].concat()]
        );
        assert_eq!(resp.trust_anchors, vec![b"test-trust-anchor".to_vec()]);
    }
    assert_eq!(harness.mock_server.call_count(), CONCURRENT_CALLS * (SIMULATED_FAILURES + 1));

    harness.stop().await;
}

fn new_invoker(harness: &TestHarness) -> BridgeEzInvoker {
    BridgeEzInvoker::new(
        harness.bridge_client.clone(),
        InvokeConfig {
            domain_name: "BackendDomain".to_string(),
            service_name: "BackendService".to_string(),
            method_name: "BackendMethod".to_string(),
        },
    )
}

struct FailurePlan {
    counts: HashMap<Vec<u8>, usize>,
    status: Status,
}

#[derive(Clone)]
struct MockBridgeServer {
    call_count: Arc<AtomicUsize>,
    failures_by_csr: Arc<Mutex<FailurePlan>>,
    captured_requests: Arc<Mutex<Vec<InvokeEzRequest>>>,
}

impl MockBridgeServer {
    fn new() -> Self {
        Self {
            call_count: Arc::new(AtomicUsize::new(0)),
            failures_by_csr: Arc::new(Mutex::new(FailurePlan {
                counts: HashMap::new(),
                status: Status::ok(""),
            })),
            captured_requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    async fn reset_csr_failures(&self, counts: HashMap<Vec<u8>, usize>, status: Status) {
        self.call_count.store(0, Ordering::SeqCst);
        self.captured_requests.lock().await.clear();
        *self.failures_by_csr.lock().await = FailurePlan { counts, status };
    }

    fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    async fn captured_requests(&self) -> Vec<InvokeEzRequest> {
        self.captured_requests.lock().await.clone()
    }
}

#[tonic::async_trait]
impl IsolateEzBridge for MockBridgeServer {
    async fn invoke_ez(
        &self,
        request: Request<InvokeEzRequest>,
    ) -> Result<Response<InvokeEzResponse>, Status> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        let req = request.into_inner();
        self.captured_requests.lock().await.push(req.clone());

        let datagram = req
            .isolate_request_payload
            .as_ref()
            .and_then(|p| p.delivery_method.as_ref())
            .and_then(|d| match d {
                DeliveryMethod::InlineData(data) => data.datagrams.first().cloned(),
                _ => None,
            })
            .ok_or_else(|| Status::invalid_argument("Expected InlineData request payload"))?;
        let cert_req = FetchFrontendTlsCertificateRequest::decode(datagram.as_slice())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let csr = cert_req.signed_certificate_signing_request;

        {
            let mut failures = self.failures_by_csr.lock().await;
            let err_status = failures.status.clone();
            if let Some(remaining) = failures.counts.get_mut(&csr).filter(|r| **r > 0) {
                *remaining -= 1;
                return Err(err_status);
            }
        }

        let ipc_message_id =
            req.control_plane_metadata.as_ref().map(|m| m.ipc_message_id).unwrap_or(0);
        let resp_proto = FetchFrontendTlsCertificateResponse {
            certificate_chain: vec![[b"cert-for-".as_slice(), csr.as_slice()].concat()],
            trust_anchors: vec![b"test-trust-anchor".to_vec()],
        };

        Ok(Response::new(InvokeEzResponse {
            control_plane_metadata: Some(ControlPlaneMetadata {
                ipc_message_id,
                responder_is_local: true,
                ..Default::default()
            }),
            ez_response_payload: Some(EzHybridPayload {
                delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                    datagrams: vec![resp_proto.encode_to_vec()],
                })),
            }),
            ..Default::default()
        }))
    }

    type StreamInvokeEzStream = ReceiverStream<Result<InvokeEzResponse, Status>>;
    async fn stream_invoke_ez(
        &self,
        _request: Request<Streaming<InvokeEzRequest>>,
    ) -> Result<Response<Self::StreamInvokeEzStream>, Status> {
        Err(Status::unimplemented("unimplemented"))
    }

    type CreateMemshareStream = ReceiverStream<Result<CreateMemshareResponse, Status>>;
    async fn create_memshare(
        &self,
        _request: Request<Streaming<CreateMemshareRequest>>,
    ) -> Result<Response<Self::CreateMemshareStream>, Status> {
        Err(Status::unimplemented("unimplemented"))
    }

    type NotifyIsolateStateStream = ReceiverStream<Result<NotifyIsolateStateResponse, Status>>;
    async fn notify_isolate_state(
        &self,
        _request: Request<Streaming<NotifyIsolateStateRequest>>,
    ) -> Result<Response<Self::NotifyIsolateStateStream>, Status> {
        Err(Status::unimplemented("unimplemented"))
    }

    async fn poll_isolate_state(
        &self,
        _request: Request<PollIsolateStateRequest>,
    ) -> Result<Response<PollIsolateStateResponse>, Status> {
        Err(Status::unimplemented("unimplemented"))
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

struct TestHarness {
    bridge_client: Arc<IsolateEzBridgeSdkClient>,
    mock_server: MockBridgeServer,
    shutdown_tx: oneshot::Sender<()>,
    server_handle: tokio::task::JoinHandle<()>,
    socket_path: PathBuf,
}

impl TestHarness {
    async fn start() -> anyhow::Result<Self> {
        let socket_path = match TEST_UDS_DIR.get() {
            Some(dir) => dir.path().join("test_client.uds"),
            None => {
                let dir = tempfile::tempdir()?;
                let path = dir.path().join("test_client.uds");
                let path_str = path.to_string_lossy().into_owned();
                // SAFETY: Tests run single-threaded (--test-threads=1) before IsolateEzBridgeSdkClient::new().
                unsafe {
                    std::env::set_var("CLIENT_UDS_PATH", &path_str);
                }
                let _ = TEST_UDS_DIR.set(dir);
                path
            }
        };
        if socket_path.exists() {
            std::fs::remove_file(&socket_path)?;
        }

        let uds = UnixListener::bind(&socket_path)?;
        let uds_stream = UnixListenerStream::new(uds);
        let mock_server = MockBridgeServer::new();
        let server_clone = mock_server.clone();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let server_handle = tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(IsolateEzBridgeServer::new(server_clone))
                .serve_with_incoming_shutdown(uds_stream, async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        let bridge_client =
            Arc::new(IsolateEzBridgeSdkClient::new().await.map_err(|e| anyhow::anyhow!("{e}"))?);
        Ok(Self { bridge_client, mock_server, shutdown_tx, server_handle, socket_path })
    }

    async fn stop(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.server_handle.await;
        let _ = std::fs::remove_file(&self.socket_path);
    }
}
