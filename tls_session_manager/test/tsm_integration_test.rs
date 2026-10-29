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
    ez_hybrid_payload::DeliveryMethod, EzHybridPayload, EzPayloadData,
};
use prost::Message;
use rcgen::CertificateParams;
use rustls_pki_types::CertificateSigningRequestDer;
use setup_isolate_proto::setup_isolate::v1::{
    FetchTlsCertificateRequest, FetchTlsCertificateResponse,
};
use std::env;
use std::error::Error;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use tls_session_manager_proto::tls_session_manager::v1::{
    StartTlsSessionRequest, StartTlsSessionResponse,
};
use tokio::net::UnixListener;
use tokio::process::{Child, Command};
use tokio::sync::mpsc::{channel, Sender};
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::StreamExt;
use tonic::transport::{Endpoint, Server, Uri};
use tonic::{Request, Response, Status, Streaming};
use tower::service_fn;

static SERVER_UDS_PATH: Lazy<String> =
    Lazy::new(|| env::var("SERVER_UDS_PATH").expect("Required env var"));
static READY_FIFO_PATH: Lazy<String> =
    Lazy::new(|| env::var("READY_FIFO_PATH").expect("Required env var"));
static CLIENT_UDS_PATH: Lazy<String> =
    Lazy::new(|| env::var("CLIENT_UDS_PATH").expect("Required env var"));

static FAKE_AVS: Lazy<(rcgen::Certificate, rcgen::KeyPair)> = Lazy::new(|| {
    let ca_pem_path = find_test_file("test_ca.pem");
    let ca_key_path = find_test_file("test_ca.key");
    let ca_pem = std::fs::read_to_string(ca_pem_path).unwrap();
    let ca_key = std::fs::read_to_string(ca_key_path).unwrap();

    let ca_key_pair = rcgen::KeyPair::from_pem(&ca_key).unwrap();
    let ca_params = rcgen::CertificateParams::from_ca_cert_pem(&ca_pem).unwrap();
    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
    (ca_cert, ca_key_pair)
});

const CHANNEL_SIZE: usize = 256;

/// Integration test to verify that the compiled TLS Session Manager Isolate binary can be
/// successfully spawned, parse command-line flags, resolve certificate files from runfiles,
/// complete the startup readiness handshake via FIFO, and execute an end-to-end TLS handshake
/// and decrypted data exchange using the low-level gRPC-over-UDS SDK IPC mechanisms.
///
/// Unlike library unit tests, this verifies the binary entry point (`main.rs`), flag parsing
/// correctness, configuration file loading, and correctness of SDK macro-based IPC server setup.
async fn run_handshake_test(enable_avs: bool) {
    let harness = TestHarness::start(enable_avs).await.expect("Test harness should start");

    // 1. Verify Isolate State is marked READY
    // (polling with timeout to avoid race conditions, for at most 5 seconds)
    let mut final_state = None;
    for _ in 0..100 {
        final_state = *harness.service.latest_state.lock().await;
        if final_state == Some(IsolateState::Ready) {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(final_state, Some(IsolateState::Ready));

    // 2. Create client-side unattested context with the pre-shared test CA
    let ca_pem_path = find_test_file("test_ca.pem");
    let ca_der = oak_session_tls::utils::load_cert_der(std::io::BufReader::new(
        std::fs::File::open(ca_pem_path).expect("failed to open test_ca.pem"),
    ));

    let client_config = oak_session_tls::ClientContextConfig {
        tls_identity_provider: None,
        server_trust_anchor_provider: Some(
            oak_session_tls::utils::create_static_trust_anchor_provider(ca_der),
        ),
        custom_cert_verifier: None,
        expected_server_name: None,
    };
    let client_context = oak_session_tls::OakSessionTlsClientContext::create(client_config)
        .expect("failed to create client context");

    // 3. Set up client-side communication channel over RpcDispatcher's EzIsolateBridge protocol
    let (request_tx, request_rx) = channel::<InvokeIsolateRequest>(128);
    let mut client = harness.client.clone();
    let response = client.stream_invoke_isolate(ReceiverStream::new(request_rx)).await.unwrap();
    let response_stream = std::sync::Arc::new(tokio::sync::Mutex::new(response.into_inner()));

    // 4. Define callbacks to drive client handshake
    let request_tx_clone = request_tx.clone();
    let sender = move |frame: Vec<u8>| {
        let request_tx = request_tx_clone.clone();
        async move {
            let request_msg = StartTlsSessionRequest { frame };
            let request_bytes = request_msg.encode_to_vec();

            let invoke_request = InvokeIsolateRequest {
                control_plane_metadata: Some(ControlPlaneMetadata {
                    ipc_message_id: rand::random(),
                    destination_operator_domain: "ServerDomain".to_string(),
                    destination_service_name: "TlsSessionManagerService".to_string(),
                    destination_method_name: "StartTlsSession".to_string(),
                    ..Default::default()
                }),
                isolate_input: Some(EzHybridPayload {
                    delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                        datagrams: vec![request_bytes],
                    })),
                }),
                ..Default::default()
            };

            request_tx.send(invoke_request).await.map_err(|e| std::io::Error::other(e.to_string()))
        }
    };

    let response_stream_clone = response_stream.clone();
    let receiver = move || {
        let response_stream = response_stream_clone.clone();
        async move {
            let mut stream = response_stream.lock().await;
            match stream.next().await {
                Some(Ok(response)) => {
                    let payload_bytes =
                        match response.isolate_output.and_then(|o| o.delivery_method) {
                            Some(DeliveryMethod::InlineData(data)) => {
                                data.datagrams.into_iter().next().unwrap_or_default()
                            }
                            _ => Vec::new(),
                        };
                    let response_msg = StartTlsSessionResponse::decode(payload_bytes.as_slice())
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    Ok(Some(response_msg.frame))
                }
                Some(Err(e)) => Err(std::io::Error::other(e.to_string())),
                None => Ok(None),
            }
        }
    };

    // 5. Drive the client-side handshake
    let (mut client_session, _initial_data) = client_context
        .new_initialized_session(sender, receiver)
        .await
        .expect("client handshake failed");

    // 6. Send encrypted plaintext message to server
    let plaintext_msg = b"ClientHelloPlaintext";
    let encrypted_msg = client_session.encrypt(plaintext_msg).expect("client encryption failed");

    let request_msg = StartTlsSessionRequest { frame: encrypted_msg };
    let request_bytes = request_msg.encode_to_vec();

    let invoke_request = InvokeIsolateRequest {
        control_plane_metadata: Some(ControlPlaneMetadata {
            ipc_message_id: rand::random(),
            destination_operator_domain: "ServerDomain".to_string(),
            destination_service_name: "TlsSessionManagerService".to_string(),
            destination_method_name: "StartTlsSession".to_string(),
            ..Default::default()
        }),
        isolate_input: Some(EzHybridPayload {
            delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                datagrams: vec![request_bytes],
            })),
        }),
        ..Default::default()
    };

    request_tx.send(invoke_request).await.unwrap();

    // 7. Receive and decrypt server response
    let mut stream = response_stream.lock().await;
    let mut decrypted_response = Vec::new();
    while decrypted_response.is_empty() {
        if let Some(Ok(response)) = stream.next().await {
            let payload_bytes = match response.isolate_output.and_then(|o| o.delivery_method) {
                Some(DeliveryMethod::InlineData(data)) => {
                    data.datagrams.into_iter().next().unwrap_or_default()
                }
                _ => Vec::new(),
            };
            let response_msg = StartTlsSessionResponse::decode(payload_bytes.as_slice()).unwrap();
            decrypted_response =
                client_session.decrypt(&response_msg.frame).expect("client decryption failed");
        } else {
            panic!("Stream closed before receiving plaintext response!");
        }
    }
    assert_eq!(decrypted_response, b"ServerResponsePlaintext: request length=20");

    // 8. Verify mock enforcer received exact plaintext message
    {
        let mock_requests = harness.service.received_invocations.lock().await;
        assert_eq!(mock_requests.len(), 1);
        assert_eq!(mock_requests[0], b"ClientHelloPlaintext");
    }

    harness.stop().await.expect("Harness should stop");
}

#[tokio::test]
async fn test_tsm_integration_handshake_e2e_avs() {
    run_handshake_test(true).await;
}

#[tokio::test]
async fn test_tsm_integration_handshake_e2e_default() {
    run_handshake_test(false).await;
}

#[tokio::test]
async fn test_tsm_integration_inner_stream_error_propagation() {
    let harness = TestHarness::start(false).await.expect("Test harness should start");

    // Set simulated backend error
    *harness.service.stream_invoke_error.lock().await =
        Some(Status::unavailable("Overloaded prefill queue / load shedding"));

    // 1. Verify Isolate State is marked READY
    let mut final_state = None;
    for _ in 0..100 {
        final_state = *harness.service.latest_state.lock().await;
        if final_state == Some(IsolateState::Ready) {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(final_state, Some(IsolateState::Ready));

    // 2. Create client-side unattested context
    let ca_pem_path = find_test_file("test_ca.pem");
    let ca_der = oak_session_tls::utils::load_cert_der(std::io::BufReader::new(
        std::fs::File::open(ca_pem_path).expect("failed to open test_ca.pem"),
    ));

    let client_config = oak_session_tls::ClientContextConfig {
        tls_identity_provider: None,
        server_trust_anchor_provider: Some(
            oak_session_tls::utils::create_static_trust_anchor_provider(ca_der),
        ),
        custom_cert_verifier: None,
        expected_server_name: None,
    };
    let client_context = oak_session_tls::OakSessionTlsClientContext::create(client_config)
        .expect("failed to create client context");

    // 3. Set up client-side communication channel
    let (request_tx, request_rx) = channel::<InvokeIsolateRequest>(128);
    let mut client = harness.client.clone();
    let response = client.stream_invoke_isolate(ReceiverStream::new(request_rx)).await.unwrap();
    let response_stream = std::sync::Arc::new(tokio::sync::Mutex::new(response.into_inner()));

    // 4. Handshake callbacks
    let request_tx_clone = request_tx.clone();
    let sender = move |frame: Vec<u8>| {
        let request_tx = request_tx_clone.clone();
        async move {
            let request_msg = StartTlsSessionRequest { frame };
            let request_bytes = request_msg.encode_to_vec();

            let invoke_request = InvokeIsolateRequest {
                control_plane_metadata: Some(ControlPlaneMetadata {
                    ipc_message_id: rand::random(),
                    destination_operator_domain: "ServerDomain".to_string(),
                    destination_service_name: "TlsSessionManagerService".to_string(),
                    destination_method_name: "StartTlsSession".to_string(),
                    ..Default::default()
                }),
                isolate_input: Some(EzHybridPayload {
                    delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                        datagrams: vec![request_bytes],
                    })),
                }),
                ..Default::default()
            };

            request_tx.send(invoke_request).await.map_err(|e| std::io::Error::other(e.to_string()))
        }
    };

    let response_stream_clone = response_stream.clone();
    let receiver = move || {
        let response_stream = response_stream_clone.clone();
        async move {
            let mut stream = response_stream.lock().await;
            match stream.next().await {
                Some(Ok(response)) => {
                    let payload_bytes =
                        match response.isolate_output.and_then(|o| o.delivery_method) {
                            Some(DeliveryMethod::InlineData(data)) => {
                                data.datagrams.into_iter().next().unwrap_or_default()
                            }
                            _ => Vec::new(),
                        };
                    let response_msg = StartTlsSessionResponse::decode(payload_bytes.as_slice())
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    Ok(Some(response_msg.frame))
                }
                Some(Err(e)) => Err(std::io::Error::other(e.to_string())),
                None => Ok(None),
            }
        }
    };

    // 5. Complete TLS Handshake
    let (mut client_session, _initial_data) = client_context
        .new_initialized_session(sender, receiver)
        .await
        .expect("client handshake failed");

    // 6. Send encrypted request
    let plaintext_msg = b"ClientHelloPlaintext";
    let encrypted_msg = client_session.encrypt(plaintext_msg).expect("client encryption failed");

    let request_msg = StartTlsSessionRequest { frame: encrypted_msg };
    let request_bytes = request_msg.encode_to_vec();

    let invoke_request = InvokeIsolateRequest {
        control_plane_metadata: Some(ControlPlaneMetadata {
            ipc_message_id: rand::random(),
            destination_operator_domain: "ServerDomain".to_string(),
            destination_service_name: "TlsSessionManagerService".to_string(),
            destination_method_name: "StartTlsSession".to_string(),
            ..Default::default()
        }),
        isolate_input: Some(EzHybridPayload {
            delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                datagrams: vec![request_bytes],
            })),
        }),
        ..Default::default()
    };

    request_tx.send(invoke_request).await.unwrap();

    // 7. Receive and verify error response without hanging
    let mut stream = response_stream.lock().await;
    let mut received_status = None;
    while received_status.is_none() {
        let timeout_result = tokio::time::timeout(Duration::from_secs(5), stream.next()).await;
        let next_msg =
            timeout_result.expect("Timed out waiting for server error response (hang detected!)");

        match next_msg {
            Some(Ok(response)) => {
                let payload_bytes = match response.isolate_output.and_then(|o| o.delivery_method) {
                    Some(DeliveryMethod::InlineData(data)) => {
                        data.datagrams.into_iter().next().unwrap_or_default()
                    }
                    _ => Vec::new(),
                };
                let response_msg =
                    StartTlsSessionResponse::decode(payload_bytes.as_slice()).unwrap();
                let _ = client_session.decrypt(&response_msg.frame);
            }
            Some(Err(status)) => {
                received_status = Some(status);
            }
            None => {
                panic!("Stream closed before receiving error status!");
            }
        }
    }

    let status = received_status.unwrap();
    assert_eq!(status.code(), tonic::Code::Unavailable);

    harness.stop().await.expect("Harness should stop");
}

#[tokio::test]
async fn test_tsm_integration_forwards_control_plane_metadata_across_multiple_messages() {
    let harness = TestHarness::start(false).await.expect("Test harness should start");

    let mut final_state = None;
    for _ in 0..100 {
        final_state = *harness.service.latest_state.lock().await;
        if final_state == Some(IsolateState::Ready) {
            break;
        }
        sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(final_state, Some(IsolateState::Ready));

    let ca_pem_path = find_test_file("test_ca.pem");
    let ca_der = oak_session_tls::utils::load_cert_der(std::io::BufReader::new(
        std::fs::File::open(ca_pem_path).expect("failed to open test_ca.pem"),
    ));

    let client_config = oak_session_tls::ClientContextConfig {
        tls_identity_provider: None,
        server_trust_anchor_provider: Some(
            oak_session_tls::utils::create_static_trust_anchor_provider(ca_der),
        ),
        custom_cert_verifier: None,
        expected_server_name: None,
    };
    let client_context = oak_session_tls::OakSessionTlsClientContext::create(client_config)
        .expect("failed to create client context");

    let mut expected_request_metadata = std::collections::HashMap::new();
    // Non-UTF-8 bytes verify opaque ctags propagation without string conversion.
    expected_request_metadata.insert("ctags".to_string(), b"\x80\x01opaque".to_vec());
    expected_request_metadata.insert("X-Geo-Location".to_string(), b"US".to_vec());
    let expected_extensions = b"serialized_http_header_context".to_vec();

    let (request_tx, request_rx) = channel::<InvokeIsolateRequest>(128);
    let mut client = harness.client.clone();
    let response = client.stream_invoke_isolate(ReceiverStream::new(request_rx)).await.unwrap();
    let response_stream = std::sync::Arc::new(tokio::sync::Mutex::new(response.into_inner()));

    let request_tx_clone = request_tx.clone();
    let handshake_req_meta = expected_request_metadata.clone();
    let handshake_ext = expected_extensions.clone();
    let sender = move |frame: Vec<u8>| {
        let request_tx = request_tx_clone.clone();
        let request_metadata = handshake_req_meta.clone();
        let extensions = handshake_ext.clone();
        async move {
            let request_msg = StartTlsSessionRequest { frame };
            let request_bytes = request_msg.encode_to_vec();

            let invoke_request = InvokeIsolateRequest {
                control_plane_metadata: Some(ControlPlaneMetadata {
                    ipc_message_id: rand::random(),
                    destination_operator_domain: "ServerDomain".to_string(),
                    destination_service_name: "TlsSessionManagerService".to_string(),
                    destination_method_name: "StartTlsSession".to_string(),
                    request_metadata,
                    extensions,
                    ..Default::default()
                }),
                isolate_input: Some(EzHybridPayload {
                    delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                        datagrams: vec![request_bytes],
                    })),
                }),
                ..Default::default()
            };

            request_tx.send(invoke_request).await.map_err(|e| std::io::Error::other(e.to_string()))
        }
    };

    let response_stream_clone = response_stream.clone();
    let receiver = move || {
        let response_stream = response_stream_clone.clone();
        async move {
            let mut stream = response_stream.lock().await;
            match stream.next().await {
                Some(Ok(response)) => {
                    let payload_bytes =
                        match response.isolate_output.and_then(|o| o.delivery_method) {
                            Some(DeliveryMethod::InlineData(data)) => {
                                data.datagrams.into_iter().next().unwrap_or_default()
                            }
                            _ => Vec::new(),
                        };
                    let response_msg = StartTlsSessionResponse::decode(payload_bytes.as_slice())
                        .map_err(|e| std::io::Error::other(e.to_string()))?;
                    Ok(Some(response_msg.frame))
                }
                Some(Err(e)) => Err(std::io::Error::other(e.to_string())),
                None => Ok(None),
            }
        }
    };

    let (mut client_session, _initial_data) = client_context
        .new_initialized_session(sender, receiver)
        .await
        .expect("client handshake failed");

    for (idx, plaintext_msg) in [b"Message 1", b"Message 2", b"Message 3"].into_iter().enumerate() {
        let encrypted_msg =
            client_session.encrypt(plaintext_msg).expect("client encryption failed");
        let request_bytes = StartTlsSessionRequest { frame: encrypted_msg }.encode_to_vec();

        // Send empty metadata on frame 0 and different metadata on later frames to verify
        // the backend session retains the initial handshake metadata across all frames.
        let (frame_req_meta, frame_ext) = if idx == 0 {
            (std::collections::HashMap::new(), Vec::new())
        } else {
            let mut mutated = std::collections::HashMap::new();
            mutated.insert("ctags".to_string(), b"\x80\x02mutated".to_vec());
            (mutated, b"mutated_extensions".to_vec())
        };

        let invoke_request = InvokeIsolateRequest {
            control_plane_metadata: Some(ControlPlaneMetadata {
                ipc_message_id: rand::random(),
                destination_operator_domain: "ServerDomain".to_string(),
                destination_service_name: "TlsSessionManagerService".to_string(),
                destination_method_name: "StartTlsSession".to_string(),
                request_metadata: frame_req_meta,
                extensions: frame_ext,
                ..Default::default()
            }),
            isolate_input: Some(EzHybridPayload {
                delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                    datagrams: vec![request_bytes],
                })),
            }),
            ..Default::default()
        };

        request_tx.send(invoke_request).await.unwrap();

        let mut stream = response_stream.lock().await;
        let mut decrypted_response = Vec::new();
        while decrypted_response.is_empty() {
            let next_msg = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .expect("Timed out waiting for plaintext response");
            match next_msg {
                Some(Ok(response)) => {
                    let payload_bytes =
                        match response.isolate_output.and_then(|o| o.delivery_method) {
                            Some(DeliveryMethod::InlineData(data)) => {
                                data.datagrams.into_iter().next().unwrap_or_default()
                            }
                            _ => Vec::new(),
                        };
                    let response_msg =
                        StartTlsSessionResponse::decode(payload_bytes.as_slice()).unwrap();
                    decrypted_response = client_session
                        .decrypt(&response_msg.frame)
                        .expect("client decryption failed");
                }
                Some(Err(status)) => {
                    panic!("Received gRPC error from response stream: {status:?}")
                }
                None => {
                    panic!("Stream closed unexpectedly before receiving plaintext response")
                }
            }
        }
        assert_eq!(
            decrypted_response,
            format!("ServerResponsePlaintext: request length={}", plaintext_msg.len()).into_bytes()
        );
    }

    {
        let received_meta = harness.service.received_control_plane_metadata.lock().await;
        assert_eq!(received_meta.len(), 3);
        for meta in received_meta.iter() {
            assert_eq!(meta.request_metadata, expected_request_metadata);
            assert_eq!(meta.extensions, expected_extensions);
        }
    }

    harness.stop().await.expect("Harness should stop");
}

#[derive(Debug, Default, Clone)]
struct MockIsolateEzBridge {
    latest_state: Arc<Mutex<Option<IsolateState>>>,
    received_invocations: Arc<Mutex<Vec<Vec<u8>>>>,
    received_control_plane_metadata: Arc<Mutex<Vec<ControlPlaneMetadata>>>,
    stream_invoke_error: Arc<Mutex<Option<Status>>>,
}

#[tonic::async_trait]
impl IsolateEzBridge for MockIsolateEzBridge {
    type StreamInvokeEzStream = ReceiverStream<Result<InvokeEzResponse, Status>>;

    async fn stream_invoke_ez(
        &self,
        request: Request<Streaming<InvokeEzRequest>>,
    ) -> Result<Response<Self::StreamInvokeEzStream>, Status> {
        let mut stream = request.into_inner();
        let (tx, rx) = channel(CHANNEL_SIZE);
        let received_invocations = self.received_invocations.clone();
        let received_control_plane_metadata = self.received_control_plane_metadata.clone();
        let stream_invoke_error = self.stream_invoke_error.clone();

        tokio::spawn(async move {
            while let Some(msg) = stream.next().await {
                let req = match msg {
                    Ok(r) => r,
                    Err(_) => break,
                };

                if let Some(err) = stream_invoke_error.lock().await.clone() {
                    let _ = tx.send(Err(err)).await;
                    break;
                }

                let payload_bytes =
                    match req.isolate_request_payload.and_then(|p| p.delivery_method) {
                        Some(DeliveryMethod::InlineData(data)) => {
                            data.datagrams.into_iter().next().unwrap_or_default()
                        }
                        _ => Vec::new(),
                    };

                // Record request
                received_invocations.lock().await.push(payload_bytes.clone());
                if let Some(meta) = &req.control_plane_metadata {
                    received_control_plane_metadata.lock().await.push(meta.clone());
                }

                // Construct response
                let plaintext_str =
                    format!("ServerResponsePlaintext: request length={}", payload_bytes.len());
                let response_bytes = plaintext_str.into_bytes();

                let response_payload = EzHybridPayload {
                    delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                        datagrams: vec![response_bytes],
                    })),
                };

                let response = InvokeEzResponse {
                    control_plane_metadata: Some(ControlPlaneMetadata {
                        ipc_message_id: req
                            .control_plane_metadata
                            .as_ref()
                            .map(|m| m.ipc_message_id)
                            .unwrap_or(0),
                        ..Default::default()
                    }),
                    ez_response_payload: Some(response_payload),
                    ..Default::default()
                };

                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn invoke_ez(
        &self,
        req: Request<InvokeEzRequest>,
    ) -> Result<Response<InvokeEzResponse>, Status> {
        let req_inner = req.into_inner();
        let payload_bytes = match req_inner.isolate_request_payload.and_then(|p| p.delivery_method)
        {
            Some(DeliveryMethod::InlineData(data)) => {
                data.datagrams.into_iter().next().unwrap_or_default()
            }
            _ => Vec::new(),
        };

        if payload_bytes.is_empty() {
            return Err(Status::invalid_argument("Empty payload in InvokeEzRequest"));
        }

        // Decode FetchTlsCertificateRequest
        let request_msg = match FetchTlsCertificateRequest::decode(payload_bytes.as_slice()) {
            Ok(m) => m,
            Err(e) => {
                log::error!("Failed to decode request msg: {:?}", e);
                return Err(Status::invalid_argument("Failed to decode request msg"));
            }
        };

        let csr_der_bytes = request_msg.signed_certificate_signing_request;

        // 1. Get the CA key pair and certificate from the static cache
        let (ca_cert, ca_key_pair) = &*FAKE_AVS;

        // 2. Parse the CSR to extract the client's public key
        let csr_params = rcgen::CertificateSigningRequestParams::from_der(
            &CertificateSigningRequestDer::from(csr_der_bytes.clone()),
        )
        .map_err(|e| Status::internal(format!("failed to parse CSR: {}", e)))?;

        // 3. Create certificate parameters for the issued certificate
        let params = CertificateParams::new(vec!["oak-session-tls".to_string()]).unwrap();

        // 4. Issue the certificate signed by the static fake CA
        let signed_cert =
            params.signed_by(&csr_params.public_key, ca_cert, ca_key_pair).map_err(|e| {
                Status::internal(format!("failed to sign certificate with static CA: {}", e))
            })?;

        let signed_cert_der = signed_cert.der().as_ref().to_vec();

        // 5. Use the pre-serialized CA certificate DER for the trust anchors
        let ca_cert_der = ca_cert.der().as_ref().to_vec();

        // Construct FetchTlsCertificateResponse
        let response_msg = FetchTlsCertificateResponse {
            certificate_chain: vec![signed_cert_der],
            trust_anchors: vec![ca_cert_der],
        };
        let response_bytes = response_msg.encode_to_vec();

        let response_payload = EzHybridPayload {
            delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData {
                datagrams: vec![response_bytes],
            })),
        };

        let response = InvokeEzResponse {
            control_plane_metadata: Some(ControlPlaneMetadata {
                ipc_message_id: req_inner
                    .control_plane_metadata
                    .as_ref()
                    .map(|m| m.ipc_message_id)
                    .unwrap_or(0),
                ..Default::default()
            }),
            ez_response_payload: Some(response_payload),
            ..Default::default()
        };

        Ok(Response::new(response))
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

#[derive(Debug)]
struct TestHarness {
    client: EzIsolateBridgeClient<tonic::transport::Channel>,
    service: MockIsolateEzBridge,
    server_handle: Option<tokio::task::JoinHandle<Result<(), tonic::transport::Error>>>,
    fake_server_shutdown_tx: Sender<()>,
    tsm_process: Option<Child>,
}

impl TestHarness {
    async fn start(enable_avs: bool) -> Result<Self, Box<dyn Error>> {
        // Ensure parent directory for UDS and FIFO exists.
        let server_uds_path = Path::new(SERVER_UDS_PATH.as_str());
        if let Some(parent) = server_uds_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                anyhow::anyhow!("Failed to create parent dir {}: {}", parent.display(), e)
            })?;
        }
        // Clean up any old socket/FIFO files that might exist.
        for path in [SERVER_UDS_PATH.as_str(), CLIENT_UDS_PATH.as_str(), READY_FIFO_PATH.as_str()] {
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

        let server_cert_path = find_test_file("test_server.pem");
        let server_key_path = find_test_file("test_server.key");

        // Spawn the tls_session_manager_isolate binary
        let binary_path = "./tls_session_manager_isolate";
        let mut command = Command::new(binary_path);
        command.kill_on_drop(true);
        command
            .env("SERVER_UDS_PATH", SERVER_UDS_PATH.as_str())
            .env("CLIENT_UDS_PATH", CLIENT_UDS_PATH.as_str())
            .env("READY_FIFO_PATH", READY_FIFO_PATH.as_str())
            .arg("--destination-operator-domain")
            .arg("ServerDomain")
            .arg("--destination-service-name")
            .arg("PlaintextServiceSession")
            .arg("--destination-method-name")
            .arg("PlaintextStream");

        if enable_avs {
            command.arg("--enable-avs");
        }

        command
            .arg("--server-cert-path")
            .arg(server_cert_path)
            .arg("--server-key-path")
            .arg(server_key_path)
            .stderr(Stdio::inherit())
            .stdout(Stdio::inherit());

        let child = command
            .spawn()
            .map_err(|e| anyhow::anyhow!("Failed to spawn tls_session_manager_isolate: {}", e))?;

        // Signal ready by opening the FIFO for writing.
        // This blocks until the server also opens it for reading.
        let _ = tokio::fs::OpenOptions::new()
            .write(true)
            .open(READY_FIFO_PATH.as_str())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to open ready FIFO: {}", e))?;

        // Initialize the client after the server signals readiness
        let uds_uri = format!("http://localhost/{}", SERVER_UDS_PATH.as_str());
        let endpoint = Endpoint::from_shared(uds_uri)
            .map_err(|e| anyhow::anyhow!("Invalid UDS URI: {}", e))?;

        let channel = endpoint.connect_with_connector_lazy(service_fn(|uri: Uri| async move {
            let path = uri.path();
            let stream = tokio::net::UnixStream::connect(path).await?;
            Ok::<_, std::io::Error>(TokioIo::new(stream))
        }));

        let client = EzIsolateBridgeClient::new(channel);

        Ok(Self {
            client,
            service: isolate_ez_service,
            server_handle: Some(server_handle),
            fake_server_shutdown_tx,
            tsm_process: Some(child),
        })
    }

    async fn stop(mut self) -> Result<(), Box<dyn Error>> {
        if let Some(mut child) = self.tsm_process.take() {
            child.kill().await.map_err(|e| {
                anyhow::anyhow!("Failed to kill tls_session_manager_isolate: {}", e)
            })?;
        }

        // Stop the fake enforcer server.
        self.fake_server_shutdown_tx.send(()).await?;
        if let Some(handle) = self.server_handle.take() {
            handle
                .await
                .map_err(|e| anyhow::anyhow!("Fake enforcer server task panicked: {}", e))?
                .map_err(|e| anyhow::anyhow!("Fake enforcer server failed: {}", e))?;
        }

        // Clean up is handled automatically on Drop.

        Ok(())
    }
}

/// Utility function to robustly resolve paths of pre-shared test keys in Bazel runfiles or local directories.
fn find_test_file(filename: &str) -> String {
    let r = runfiles::Runfiles::create().expect("Failed to initialize Runfiles");
    let path = format!("oak~/oak_session/tls/testing/{}", filename);
    if let Some(resolved) = r.rlocation(&path).filter(|p| p.exists()) {
        return resolved.to_string_lossy().into_owned();
    }
    panic!("Could not find test file {} in runfiles path: {}", filename, path);
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        for path in [SERVER_UDS_PATH.as_str(), CLIENT_UDS_PATH.as_str(), READY_FIFO_PATH.as_str()] {
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
