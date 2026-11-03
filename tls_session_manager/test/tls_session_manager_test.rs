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
use std::sync::Arc;
use tokio::sync::mpsc::{channel, Receiver};
use tokio::sync::oneshot;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tokio_stream::StreamExt;
use tonic::transport::Server;

use tls_session_manager_proto::tls_session_manager::v1::{
    tls_session_manager_service_client::TlsSessionManagerServiceClient,
    tls_session_manager_service_server::TlsSessionManagerServiceServer, StartTlsSessionRequest,
};

use tls_session_manager::{InvokeConfig, TlsSessionManager, TsmConfig};
use tls_session_manager_sdk::{ForwardedControlPlaneMetadata, TlsSessionManagerService};

use rcgen::CertificateParams;
use rustls_pki_types::CertificateSigningRequestDer;
use std::sync::Mutex;
use std::sync::OnceLock;

static FAKE_AVS: OnceLock<(rcgen::Certificate, rcgen::KeyPair)> = OnceLock::new();

fn get_fake_avs() -> &'static (rcgen::Certificate, rcgen::KeyPair) {
    FAKE_AVS.get_or_init(|| {
        let ca_pem_path = find_test_file("test_ca.pem");
        let ca_key_path = find_test_file("test_ca.key");
        let ca_pem = std::fs::read_to_string(ca_pem_path).unwrap();
        let ca_key = std::fs::read_to_string(ca_key_path).unwrap();

        let ca_key_pair = rcgen::KeyPair::from_pem(&ca_key).unwrap();
        let ca_params = rcgen::CertificateParams::from_ca_cert_pem(&ca_pem).unwrap();
        let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
        (ca_cert, ca_key_pair)
    })
}

#[derive(Debug, Clone)]
struct MockInvoker {
    received_requests: Arc<Mutex<Vec<Vec<u8>>>>,
    received_states: Arc<Mutex<Vec<enforcer_proto::enforcer::v1::IsolateState>>>,
    should_fail_fetch_cert: Arc<std::sync::atomic::AtomicBool>,
    stream_server_error: Arc<Mutex<Option<tonic::Status>>>,
    received_forwarded_metadata: Arc<Mutex<Vec<Option<ForwardedControlPlaneMetadata>>>>,
}

impl MockInvoker {
    fn new() -> Self {
        Self {
            received_requests: Arc::new(Mutex::new(Vec::new())),
            received_states: Arc::new(Mutex::new(Vec::new())),
            should_fail_fetch_cert: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            stream_server_error: Arc::new(Mutex::new(None)),
            received_forwarded_metadata: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[tonic::async_trait]
impl tls_session_manager::ez_invoker::EzInvoker for MockInvoker {
    async fn stream_server(
        &self,
        request: tonic::Request<Receiver<Vec<u8>>>,
    ) -> Result<Receiver<Result<Vec<u8>, tonic::Status>>, tonic::Status> {
        self.received_forwarded_metadata
            .lock()
            .unwrap()
            .push(request.extensions().get::<ForwardedControlPlaneMetadata>().cloned());
        let mut request_rx = request.into_inner();
        let (response_tx, response_rx) = channel::<Result<Vec<u8>, tonic::Status>>(10);
        let received_requests = self.received_requests.clone();
        let stream_server_error = self.stream_server_error.clone();

        tokio::spawn(async move {
            while let Some(request) = request_rx.recv().await {
                // Record the received request
                received_requests.lock().unwrap().push(request.clone());

                let stream_err = stream_server_error.lock().unwrap().clone();
                if let Some(err) = stream_err {
                    let _ = response_tx.send(Err(err)).await;
                    break;
                }

                let plaintext_str =
                    format!("ServerResponsePlaintext: request length={}", request.len());
                let response = plaintext_str.into_bytes();
                if response_tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }
        });

        Ok(response_rx)
    }

    async fn fetch_frontend_certificate(
        &self,
        request: setup_isolate_proto::setup_isolate::v1::FetchFrontendTlsCertificateRequest,
    ) -> Result<
        setup_isolate_proto::setup_isolate::v1::FetchFrontendTlsCertificateResponse,
        tonic::Status,
    > {
        if self.should_fail_fetch_cert.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(tonic::Status::internal("simulated fetch certificate failure"));
        }

        let csr_der_bytes = request.signed_certificate_signing_request;
        if csr_der_bytes.is_empty() {
            return Err(tonic::Status::invalid_argument("CSR is empty"));
        }

        // 1. Get the CA key pair and certificate from the static cache
        let (ca_cert, ca_key_pair) = get_fake_avs();

        // 2. Parse the CSR to extract the client's public key
        let csr_params = rcgen::CertificateSigningRequestParams::from_der(
            &CertificateSigningRequestDer::from(csr_der_bytes),
        )
        .map_err(|e| tonic::Status::internal(format!("failed to parse CSR: {}", e)))?;

        // 3. Create certificate parameters for the issued certificate
        let params = CertificateParams::new(vec!["oak-session-tls".to_string()]).unwrap();

        // 4. Issue the certificate signed by the static fake CA
        let signed_cert =
            params.signed_by(&csr_params.public_key, ca_cert, ca_key_pair).map_err(|e| {
                tonic::Status::internal(format!("failed to sign certificate with static CA: {}", e))
            })?;

        let signed_cert_der = signed_cert.der().as_ref().to_vec();
        let ca_cert_der = ca_cert.der().as_ref().to_vec();

        Ok(setup_isolate_proto::setup_isolate::v1::FetchFrontendTlsCertificateResponse {
            certificate_chain: vec![signed_cert_der],
            trust_anchors: vec![ca_cert_der],
        })
    }

    async fn new_isolate_state(
        &self,
        state: enforcer_proto::enforcer::v1::IsolateState,
    ) -> Result<(), tonic::Status> {
        self.received_states.lock().unwrap().push(state);
        Ok(())
    }
}

fn get_server_target() -> InvokeConfig {
    InvokeConfig {
        domain_name: "ServerDomain".to_string(),
        service_name: "ServerService".to_string(),
        method_name: "ServerMethod".to_string(),
    }
}

/// Utility function to robustly resolve paths of pre-shared test keys in Bazel runfiles or local directories.
fn find_test_file(filename: &str) -> String {
    let paths = [
        format!("oak_session/tls/testing/{}", filename),
        format!("external/oak/oak_session/tls/testing/{}", filename),
        format!("external/oak~/oak_session/tls/testing/{}", filename),
        format!("../oak_session/tls/testing/{}", filename),
    ];
    for p in &paths {
        if std::path::Path::new(p).exists() {
            return p.clone();
        }
    }
    if let Ok(runfiles_dir) = std::env::var("RUNFILES_DIR") {
        let p =
            format!("{}/_main/external/oak~/oak_session/tls/testing/{}", runfiles_dir, filename);
        if std::path::Path::new(&p).exists() {
            return p;
        }
        let p = format!("{}/oak/oak_session/tls/testing/{}", runfiles_dir, filename);
        if std::path::Path::new(&p).exists() {
            return p;
        }
    }
    panic!("Could not find test file: {}", filename);
}

async fn start_tsm(
    tsm: TlsSessionManager,
) -> Result<(TlsSessionManagerServiceClient<tonic::transport::Channel>, oneshot::Sender<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let tsm_server = TlsSessionManagerServiceServer::new(tsm);

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        Server::builder()
            .add_service(tsm_server)
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                shutdown_rx.await.ok();
            })
            .await
            .unwrap();
    });

    let addr = format!("http://{}", addr);
    let tsm_client = TlsSessionManagerServiceClient::connect(addr).await?;
    Ok((tsm_client, shutdown_tx))
}

#[tokio::test]
async fn test_start_tls_session_handshake() {
    // Load pre-shared test credentials from Bazel runfiles at runtime
    let server_cert_pem = std::fs::read_to_string(find_test_file("test_server.pem"))
        .expect("failed to read test_server.pem");
    let server_key_pem = std::fs::read_to_string(find_test_file("test_server.key"))
        .expect("failed to read test_server.key");

    let ez_invoker = Arc::new(MockInvoker::new());
    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: false,
            server_cert_pem: Some(server_cert_pem),
            server_key_pem: Some(server_key_pem),
        },
    );

    let (mut tsm_client, shutdown_tx) = start_tsm(tsm).await.unwrap();

    // 1. Create client-side unattested context with the pre-shared test CA
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

    // 2. Set up the client-side communication channel
    let (request_tx, request_rx) = channel::<StartTlsSessionRequest>(128);
    let response = tsm_client.start_tls_session(ReceiverStream::new(request_rx)).await.unwrap();
    let response_stream = std::sync::Arc::new(tokio::sync::Mutex::new(response.into_inner()));

    // 3. Define the callbacks to drive the client-side handshake
    let request_tx_clone = request_tx.clone();
    let sender = move |frame: Vec<u8>| {
        let request_tx = request_tx_clone.clone();
        async move {
            request_tx
                .send(StartTlsSessionRequest { frame })
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        }
    };

    let response_stream_clone = response_stream.clone();
    let receiver = move || {
        let response_stream = response_stream_clone.clone();
        async move {
            let mut stream = response_stream.lock().await;
            match stream.next().await {
                Some(Ok(response)) => Ok(Some(response.frame)),
                Some(Err(e)) => Err(std::io::Error::other(e.to_string())),
                None => Ok(None),
            }
        }
    };

    // 4. Drive the client-side handshake
    let (mut client_session, _initial_data) = client_context
        .new_initialized_session(sender, receiver)
        .await
        .expect("client handshake failed");

    // 5. Placeholder plaintext exchange: Send encrypted plaintext message to server
    let plaintext_msg = b"ClientHelloPlaintext";
    let encrypted_msg = client_session.encrypt(plaintext_msg).expect("client encryption failed");
    request_tx.send(StartTlsSessionRequest { frame: encrypted_msg }).await.unwrap();

    // 6. Receive and decrypt server response (loop until we get a non-empty plaintext response)
    let mut stream = response_stream.lock().await;
    let mut decrypted_response = Vec::new();
    while decrypted_response.is_empty() {
        if let Some(Ok(response)) = stream.next().await {
            decrypted_response =
                client_session.decrypt(&response.frame).expect("client decryption failed");
        } else {
            panic!("Stream closed before receiving plaintext response!");
        }
    }
    assert_eq!(decrypted_response, b"ServerResponsePlaintext: request length=20");

    // 7. Verify that the mock invoker received the exact plaintext message sent by the client
    let mock_requests = ez_invoker.received_requests.lock().unwrap();
    assert_eq!(mock_requests.len(), 1);
    assert_eq!(mock_requests[0], b"ClientHelloPlaintext");

    shutdown_tx.send(()).unwrap();
}

#[tokio::test]
async fn test_start_tls_session_dynamic_fake_service() {
    use fake_test_service_proto::fake_test_service::v1::{UpperCaseRequest, UpperCaseResponse};
    use fake_test_service_sdk::{UpperCaseRequestStream, UpperCaseService};
    use prost::Message;
    use tonic::{Request, Response, Status};

    // Load pre-shared test credentials from Bazel runfiles at runtime
    let server_cert_pem = std::fs::read_to_string(find_test_file("test_server.pem"))
        .expect("failed to read test_server.pem");
    let server_key_pem = std::fs::read_to_string(find_test_file("test_server.key"))
        .expect("failed to read test_server.key");

    // We configure the session manager to call UpperCaseService/UpperCaseStream
    let server_target = InvokeConfig {
        domain_name: "UpperCaseDomain".to_string(),
        service_name: "UpperCaseService".to_string(),
        method_name: "UpperCaseStream".to_string(),
    };

    #[derive(Debug, Clone)]
    struct UpperCaseServiceImpl {
        received_requests: Arc<Mutex<Vec<UpperCaseRequest>>>,
    }

    #[tonic::async_trait]
    impl UpperCaseService for UpperCaseServiceImpl {
        type UpperCaseStreamStream = ReceiverStream<Result<UpperCaseResponse, Status>>;

        async fn upper_case_stream<T: UpperCaseRequestStream>(
            &self,
            request: Request<T>,
        ) -> Result<Response<Self::UpperCaseStreamStream>, Status> {
            let mut stream = request.into_inner();
            let (tx, rx) = channel::<Result<UpperCaseResponse, Status>>(10);
            let received_requests = self.received_requests.clone();

            tokio::spawn(async move {
                while let Some(req_res) = stream.next().await {
                    let req = match req_res {
                        Ok(req) => req,
                        Err(e) => {
                            eprintln!("Error in request stream: {:?}", e);
                            break;
                        }
                    };
                    received_requests.lock().unwrap().push(req.clone());
                    let output = req.input.to_uppercase();
                    if tx.send(Ok(UpperCaseResponse { output })).await.is_err() {
                        break;
                    }
                }
            });

            Ok(Response::new(ReceiverStream::new(rx)))
        }
    }

    #[derive(Debug, Clone)]
    struct UpperCaseServiceEzInvoker {
        service: Arc<UpperCaseServiceImpl>,
    }

    #[tonic::async_trait]
    impl tls_session_manager::ez_invoker::EzInvoker for UpperCaseServiceEzInvoker {
        async fn stream_server(
            &self,
            request: Request<Receiver<Vec<u8>>>,
        ) -> Result<Receiver<Result<Vec<u8>, Status>>, Status> {
            let request_stream = request.map(|request_rx| {
                ReceiverStream::new(request_rx).map(|bytes| {
                    UpperCaseRequest::decode(bytes.as_slice())
                        .map_err(|e| Status::internal(e.to_string()))
                })
            });

            let response = self.service.upper_case_stream(request_stream).await?;

            let mut response_stream = response.into_inner();
            let (response_tx, response_rx) = channel::<Result<Vec<u8>, Status>>(10);

            tokio::spawn(async move {
                while let Some(res_result) = response_stream.next().await {
                    match res_result {
                        Ok(res) => {
                            if response_tx.send(Ok(res.encode_to_vec())).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("Error from service response stream: {:?}", e);
                            let _ = response_tx.send(Err(e)).await;
                            break;
                        }
                    }
                }
            });

            Ok(response_rx)
        }

        async fn fetch_frontend_certificate(
            &self,
            _request: setup_isolate_proto::setup_isolate::v1::FetchFrontendTlsCertificateRequest,
        ) -> Result<
            setup_isolate_proto::setup_isolate::v1::FetchFrontendTlsCertificateResponse,
            Status,
        > {
            Err(Status::unimplemented("unimplemented"))
        }

        async fn new_isolate_state(
            &self,
            _state: enforcer_proto::enforcer::v1::IsolateState,
        ) -> Result<(), Status> {
            Ok(())
        }
    }

    let received_requests = Arc::new(Mutex::new(Vec::new()));
    let service_impl =
        Arc::new(UpperCaseServiceImpl { received_requests: received_requests.clone() });
    let ez_invoker = Arc::new(UpperCaseServiceEzInvoker { service: service_impl });
    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target,
            enable_avs: false,
            server_cert_pem: Some(server_cert_pem),
            server_key_pem: Some(server_key_pem),
        },
    );

    let (mut tsm_client, shutdown_tx) = start_tsm(tsm).await.unwrap();

    // 1. Create client-side unattested context with the pre-shared test CA
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

    // 2. Set up the client-side communication channel
    let (request_tx, request_rx) = channel::<StartTlsSessionRequest>(128);
    let response = tsm_client.start_tls_session(ReceiverStream::new(request_rx)).await.unwrap();
    let response_stream = std::sync::Arc::new(tokio::sync::Mutex::new(response.into_inner()));

    // 3. Define the callbacks to drive the client-side handshake
    let request_tx_clone = request_tx.clone();
    let sender = move |frame: Vec<u8>| {
        let request_tx = request_tx_clone.clone();
        async move {
            request_tx
                .send(StartTlsSessionRequest { frame })
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        }
    };

    // 4. Define the receiver callback
    let response_stream_clone = response_stream.clone();
    let receiver = move || {
        let response_stream = response_stream_clone.clone();
        async move {
            let mut stream = response_stream.lock().await;
            match stream.next().await {
                Some(Ok(response)) => Ok(Some(response.frame)),
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

    // 6. Send encrypted serialized UpperCaseRequest message to server
    let inner_req = UpperCaseRequest { input: "hello dynamic grpc".to_string() };
    let serialized_req = inner_req.encode_to_vec();
    let encrypted_msg = client_session.encrypt(&serialized_req).expect("client encryption failed");
    request_tx.send(StartTlsSessionRequest { frame: encrypted_msg }).await.unwrap();

    // 7. Receive and decrypt server response
    let mut stream = response_stream.lock().await;
    let mut decrypted_response = Vec::new();
    while decrypted_response.is_empty() {
        if let Some(Ok(response)) = stream.next().await {
            decrypted_response =
                client_session.decrypt(&response.frame).expect("client decryption failed");
        } else {
            panic!("Stream closed before receiving response!");
        }
    }
    let inner_resp = UpperCaseResponse::decode(decrypted_response.as_slice()).unwrap();
    assert_eq!(inner_resp.output, "HELLO DYNAMIC GRPC");

    // 8. Verify mock invoker received the exact UpperCaseRequest
    let mock_requests = received_requests.lock().unwrap();
    assert_eq!(mock_requests.len(), 1);
    assert_eq!(mock_requests[0].input, "hello dynamic grpc");

    shutdown_tx.send(()).unwrap();
}

#[tokio::test]
async fn test_fetch_frontend_certificate_unit() -> Result<()> {
    let mock_invoker = Arc::new(MockInvoker::new());
    let (cert_pem, key_pem) = tls_session_manager::fetch_frontend_certificate(mock_invoker).await?;

    // Parse the PEM chain to ensure that the returned values can be successfully parsed by the PEM parser
    let parsed_certs = ::pem::parse_many(&cert_pem)?;
    assert_eq!(parsed_certs.len(), 1);
    assert_eq!(parsed_certs[0].tag(), "CERTIFICATE");

    // Ensure the private key can also be successfully parsed as a valid PEM structure
    let parsed_key = ::pem::parse(&key_pem)?;
    assert!(parsed_key.tag().contains("PRIVATE KEY"));

    Ok(())
}

#[tokio::test]
async fn test_async_fetch_avs_cert_ready_signaling() -> Result<()> {
    use enforcer_proto::enforcer::v1::IsolateState;

    let ez_invoker = Arc::new(MockInvoker::new());
    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: true,
            server_cert_pem: None,
            server_key_pem: None,
        },
    );

    tsm.start_async_certificate_fetch();

    // Wait and poll the received states.
    let mut received_ready = false;
    for _ in 0..40 {
        let found = {
            let states = ez_invoker.received_states.lock().unwrap();
            states.contains(&IsolateState::Ready)
        };
        if found {
            received_ready = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    assert!(received_ready, "Did not receive IsolateState::Ready signal");

    Ok(())
}

#[tokio::test]
async fn test_avs_tls_handshake_success() {
    let ez_invoker = Arc::new(MockInvoker::new());
    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: true,
            server_cert_pem: None,
            server_key_pem: None,
        },
    );

    tsm.start_async_certificate_fetch();

    let (mut tsm_client, shutdown_tx) = start_tsm(tsm).await.unwrap();

    // 1. Create client-side unattested context with the pre-shared test CA
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

    // 2. Set up the client-side communication channel
    let (request_tx, request_rx) = channel::<StartTlsSessionRequest>(128);
    let response = tsm_client.start_tls_session(ReceiverStream::new(request_rx)).await.unwrap();
    let response_stream = std::sync::Arc::new(tokio::sync::Mutex::new(response.into_inner()));

    // 3. Define the callbacks to drive the client-side handshake
    let request_tx_clone = request_tx.clone();
    let sender = move |frame: Vec<u8>| {
        let request_tx = request_tx_clone.clone();
        async move {
            request_tx
                .send(StartTlsSessionRequest { frame })
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        }
    };

    let response_stream_clone = response_stream.clone();
    let receiver = move || {
        let response_stream = response_stream_clone.clone();
        async move {
            let mut stream = response_stream.lock().await;
            match stream.next().await {
                Some(Ok(response)) => Ok(Some(response.frame)),
                Some(Err(e)) => Err(std::io::Error::other(e.to_string())),
                None => Ok(None),
            }
        }
    };

    // 4. Drive the client-side handshake
    let (mut client_session, _initial_data) = client_context
        .new_initialized_session(sender, receiver)
        .await
        .expect("client handshake failed");

    // 5. Plaintext exchange: Send encrypted plaintext message to server
    let plaintext_msg = b"ClientHelloPlaintext";
    let encrypted_msg = client_session.encrypt(plaintext_msg).expect("client encryption failed");
    request_tx.send(StartTlsSessionRequest { frame: encrypted_msg }).await.unwrap();

    // 6. Receive and decrypt server response
    let mut stream = response_stream.lock().await;
    let mut decrypted_response = Vec::new();
    while decrypted_response.is_empty() {
        if let Some(Ok(response)) = stream.next().await {
            decrypted_response =
                client_session.decrypt(&response.frame).expect("client decryption failed");
        } else {
            panic!("Stream closed before receiving plaintext response!");
        }
    }
    assert_eq!(decrypted_response, b"ServerResponsePlaintext: request length=20");

    let mock_requests = ez_invoker.received_requests.lock().unwrap();
    assert_eq!(mock_requests.len(), 1);
    assert_eq!(mock_requests[0], plaintext_msg);

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_avs_tls_handshake_failure_propagation() {
    let ez_invoker = Arc::new(MockInvoker::new());
    ez_invoker.should_fail_fetch_cert.store(true, std::sync::atomic::Ordering::SeqCst);

    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: true,
            server_cert_pem: None,
            server_key_pem: None,
        },
    );

    tsm.start_async_certificate_fetch();

    let (mut tsm_client, shutdown_tx) = start_tsm(tsm).await.unwrap();

    let (_request_tx, request_rx) = channel::<StartTlsSessionRequest>(128);
    let response = tsm_client.start_tls_session(ReceiverStream::new(request_rx)).await;

    match response {
        Ok(res) => {
            let mut stream = res.into_inner();
            let first_msg = stream.next().await;
            match first_msg {
                Some(Err(status)) => {
                    assert_eq!(status.code(), tonic::Code::Internal);
                    assert!(status.message().contains("Failed to fetch frontend certificate"));
                }
                other => {
                    panic!("Expected stream to yield gRPC internal status error, got {:?}", other)
                }
            }
        }
        Err(status) => {
            assert_eq!(status.code(), tonic::Code::Internal);
        }
    }

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_inner_stream_unavailable_error_propagation() {
    let server_cert_pem = std::fs::read_to_string(find_test_file("test_server.pem"))
        .expect("failed to read test_server.pem");
    let server_key_pem = std::fs::read_to_string(find_test_file("test_server.key"))
        .expect("failed to read test_server.key");

    let ez_invoker = Arc::new(MockInvoker::new());
    // Simulate inner stream load shedding error (UNAVAILABLE)
    *ez_invoker.stream_server_error.lock().unwrap() =
        Some(tonic::Status::unavailable("Overloaded prefill queue / load shedding"));

    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: false,
            server_cert_pem: Some(server_cert_pem),
            server_key_pem: Some(server_key_pem),
        },
    );

    let (mut tsm_client, shutdown_tx) = start_tsm(tsm).await.unwrap();

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

    let (request_tx, request_rx) = channel::<StartTlsSessionRequest>(128);
    let response = tsm_client.start_tls_session(ReceiverStream::new(request_rx)).await.unwrap();
    let response_stream = std::sync::Arc::new(tokio::sync::Mutex::new(response.into_inner()));

    let request_tx_clone = request_tx.clone();
    let sender = move |frame: Vec<u8>| {
        let request_tx = request_tx_clone.clone();
        async move {
            request_tx
                .send(StartTlsSessionRequest { frame })
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        }
    };

    let response_stream_clone = response_stream.clone();
    let receiver = move || {
        let response_stream = response_stream_clone.clone();
        async move {
            let mut stream = response_stream.lock().await;
            match stream.next().await {
                Some(Ok(response)) => Ok(Some(response.frame)),
                Some(Err(e)) => Err(std::io::Error::other(e.to_string())),
                None => Ok(None),
            }
        }
    };

    // Complete TLS Handshake
    let (mut client_session, _initial_data) = client_context
        .new_initialized_session(sender, receiver)
        .await
        .expect("client handshake failed");

    // Send encrypted request
    let plaintext_msg = b"ClientHelloPlaintext";
    let encrypted_msg = client_session.encrypt(plaintext_msg).expect("client encryption failed");
    request_tx.send(StartTlsSessionRequest { frame: encrypted_msg }).await.unwrap();

    // Verify client receives UNAVAILABLE status without hanging
    let mut stream = response_stream.lock().await;
    let mut received_status = None;
    while received_status.is_none() {
        let timeout_result =
            tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.next()).await;
        let next_msg =
            timeout_result.expect("Timed out waiting for server error response (hang detected!)");

        match next_msg {
            Some(Ok(response)) => {
                // Consume post-handshake TLS frames (e.g. NewSessionTicket)
                let _ = client_session.decrypt(&response.frame);
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

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_tsm_debug_format_and_self_signed_init() {
    let ez_invoker = Arc::new(MockInvoker::new());
    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: false,
            server_cert_pem: None,
            server_key_pem: None,
        },
    );

    let debug_str = format!("{:?}", tsm);
    assert!(debug_str.contains("TlsSessionManager"));

    let (_request_tx, request_rx) = channel::<Result<StartTlsSessionRequest, tonic::Status>>(10);
    let res = tsm.start_tls_session(tonic::Request::new(ReceiverStream::new(request_rx))).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_tls_handshake_invalid_frame_failure() {
    let server_cert_pem = std::fs::read_to_string(find_test_file("test_server.pem"))
        .expect("failed to read test_server.pem");
    let server_key_pem = std::fs::read_to_string(find_test_file("test_server.key"))
        .expect("failed to read test_server.key");

    let ez_invoker = Arc::new(MockInvoker::new());
    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: false,
            server_cert_pem: Some(server_cert_pem),
            server_key_pem: Some(server_key_pem),
        },
    );

    let (mut tsm_client, shutdown_tx) = start_tsm(tsm).await.unwrap();

    let (request_tx, request_rx) = channel::<StartTlsSessionRequest>(10);
    let response = tsm_client.start_tls_session(ReceiverStream::new(request_rx)).await.unwrap();
    let mut response_stream = response.into_inner();

    // Send invalid frame during handshake
    request_tx
        .send(StartTlsSessionRequest {
            frame: vec![0x16, 0x03, 0x01, 0x00, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        })
        .await
        .unwrap();

    let next_msg = response_stream.next().await;
    match next_msg {
        Some(Err(status)) => {
            assert_eq!(status.code(), tonic::Code::Internal);
        }
        other => {
            panic!("Expected handshake error status, got {:?}", other);
        }
    }

    assert!(ez_invoker.received_requests.lock().unwrap().is_empty());
    assert!(ez_invoker.received_forwarded_metadata.lock().unwrap().is_empty());

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_client_decryption_failure_handling() {
    let server_cert_pem = std::fs::read_to_string(find_test_file("test_server.pem"))
        .expect("failed to read test_server.pem");
    let server_key_pem = std::fs::read_to_string(find_test_file("test_server.key"))
        .expect("failed to read test_server.key");

    let ez_invoker = Arc::new(MockInvoker::new());
    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: false,
            server_cert_pem: Some(server_cert_pem),
            server_key_pem: Some(server_key_pem),
        },
    );

    let (mut tsm_client, shutdown_tx) = start_tsm(tsm).await.unwrap();

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

    let (request_tx, request_rx) = channel::<StartTlsSessionRequest>(128);
    let response = tsm_client.start_tls_session(ReceiverStream::new(request_rx)).await.unwrap();
    let response_stream = std::sync::Arc::new(tokio::sync::Mutex::new(response.into_inner()));

    let request_tx_clone = request_tx.clone();
    let sender = move |frame: Vec<u8>| {
        let request_tx = request_tx_clone.clone();
        async move {
            request_tx
                .send(StartTlsSessionRequest { frame })
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        }
    };

    let response_stream_clone = response_stream.clone();
    let receiver = move || {
        let response_stream = response_stream_clone.clone();
        async move {
            let mut stream = response_stream.lock().await;
            match stream.next().await {
                Some(Ok(response)) => Ok(Some(response.frame)),
                Some(Err(e)) => Err(std::io::Error::other(e.to_string())),
                None => Ok(None),
            }
        }
    };

    // Complete TLS Handshake
    let (mut client_session, _initial_data) = client_context
        .new_initialized_session(sender, receiver)
        .await
        .expect("client handshake failed");

    // Encrypt a valid message, then corrupt the ciphertext payload
    let plaintext = b"Hello";
    let mut encrypted_frame = client_session.encrypt(plaintext).unwrap();
    let len = encrypted_frame.len();
    encrypted_frame[len - 1] ^= 0xFF;

    request_tx.send(StartTlsSessionRequest { frame: encrypted_frame }).await.unwrap();

    let mut stream = response_stream.lock().await;
    let timeout_result = tokio::time::timeout(tokio::time::Duration::from_secs(3), async {
        while let Some(msg) = stream.next().await {
            if msg.is_err() {
                break;
            }
        }
    })
    .await;
    assert!(timeout_result.is_ok());

    let _ = shutdown_tx.send(());
}

async fn run_session_against_tsm(
    tsm: &TlsSessionManager,
    forwarded_metadata: Option<ForwardedControlPlaneMetadata>,
) {
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

    let (request_tx, request_rx) = channel::<Result<StartTlsSessionRequest, tonic::Status>>(128);
    let mut service_request = tonic::Request::new(ReceiverStream::new(request_rx));
    if let Some(meta) = forwarded_metadata {
        service_request.extensions_mut().insert(meta);
    }

    let response = TlsSessionManagerService::start_tls_session(tsm, service_request)
        .await
        .expect("start_tls_session failed");
    let response_stream = Arc::new(tokio::sync::Mutex::new(response.into_inner()));

    let request_tx_clone = request_tx.clone();
    let sender = move |frame: Vec<u8>| {
        let request_tx = request_tx_clone.clone();
        async move {
            request_tx
                .send(Ok(StartTlsSessionRequest { frame }))
                .await
                .map_err(|e| std::io::Error::other(e.to_string()))
        }
    };

    let response_stream_clone = response_stream.clone();
    let receiver = move || {
        let response_stream = response_stream_clone.clone();
        async move {
            let mut stream = response_stream.lock().await;
            match stream.next().await {
                Some(Ok(response)) => Ok(Some(response.frame)),
                Some(Err(e)) => Err(std::io::Error::other(e.to_string())),
                None => Ok(None),
            }
        }
    };

    let (mut client_session, _initial_data) = client_context
        .new_initialized_session(sender, receiver)
        .await
        .expect("client handshake failed");

    let encrypted_frame = client_session.encrypt(b"Hello").unwrap();
    request_tx.send(Ok(StartTlsSessionRequest { frame: encrypted_frame })).await.unwrap();

    let mut stream = response_stream.lock().await;
    let mut decrypted_response = Vec::new();
    while decrypted_response.is_empty() {
        let next_item = tokio::time::timeout(tokio::time::Duration::from_secs(5), stream.next())
            .await
            .expect("Timed out waiting for response frame from TlsSessionManager");
        match next_item {
            Some(Ok(response)) => {
                decrypted_response = client_session.decrypt(&response.frame).unwrap();
            }
            Some(Err(status)) => {
                panic!("Stream failed before receiving plaintext response: {status}");
            }
            None => {
                panic!("Stream closed before receiving plaintext response!");
            }
        }
    }
    assert_eq!(decrypted_response, b"ServerResponsePlaintext: request length=5");
}

async fn run_start_tls_session_with_forwarded_metadata(
    forwarded_metadata: Option<ForwardedControlPlaneMetadata>,
) -> Option<ForwardedControlPlaneMetadata> {
    let server_cert_pem = std::fs::read_to_string(find_test_file("test_server.pem"))
        .expect("failed to read test_server.pem");
    let server_key_pem = std::fs::read_to_string(find_test_file("test_server.key"))
        .expect("failed to read test_server.key");

    let ez_invoker = Arc::new(MockInvoker::new());
    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: false,
            server_cert_pem: Some(server_cert_pem),
            server_key_pem: Some(server_key_pem),
        },
    );

    run_session_against_tsm(&tsm, forwarded_metadata).await;

    let mut recorded = ez_invoker.received_forwarded_metadata.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    recorded.pop().unwrap()
}

#[tokio::test]
async fn test_start_tls_session_forwards_control_plane_metadata_to_invoker() {
    let mut req_meta = std::collections::HashMap::new();
    // Non-UTF-8 bytes verify opaque ctags propagation without string conversion.
    req_meta.insert("ctags".to_string(), b"\x80\x01opaque".to_vec());
    req_meta.insert("X-Geo-Location".to_string(), b"US".to_vec());
    let expected_metadata = ForwardedControlPlaneMetadata {
        request_metadata: req_meta,
        extensions: b"serialized_http_header_context".to_vec(),
    };

    let captured =
        run_start_tls_session_with_forwarded_metadata(Some(expected_metadata.clone())).await;
    assert_eq!(captured, Some(expected_metadata));
}

#[tokio::test]
async fn test_start_tls_session_without_forwarded_metadata() {
    let captured = run_start_tls_session_with_forwarded_metadata(None).await;
    assert_eq!(captured, None);
}

#[tokio::test]
async fn test_start_tls_session_forwards_partial_control_plane_metadata() {
    let mut req_meta = std::collections::HashMap::new();
    req_meta.insert("ctags".to_string(), b"only_request_metadata".to_vec());
    let only_request_metadata =
        ForwardedControlPlaneMetadata { request_metadata: req_meta, extensions: Vec::new() };
    assert_eq!(
        run_start_tls_session_with_forwarded_metadata(Some(only_request_metadata.clone())).await,
        Some(only_request_metadata)
    );

    let only_extensions = ForwardedControlPlaneMetadata {
        request_metadata: std::collections::HashMap::new(),
        extensions: b"only_extensions".to_vec(),
    };
    assert_eq!(
        run_start_tls_session_with_forwarded_metadata(Some(only_extensions.clone())).await,
        Some(only_extensions)
    );
}

#[tokio::test]
async fn test_start_tls_session_handshake_failure_does_not_forward_metadata() {
    let server_cert_pem = std::fs::read_to_string(find_test_file("test_server.pem"))
        .expect("failed to read test_server.pem");
    let server_key_pem = std::fs::read_to_string(find_test_file("test_server.key"))
        .expect("failed to read test_server.key");

    let ez_invoker = Arc::new(MockInvoker::new());
    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: false,
            server_cert_pem: Some(server_cert_pem),
            server_key_pem: Some(server_key_pem),
        },
    );

    let (request_tx, request_rx) = channel::<Result<StartTlsSessionRequest, tonic::Status>>(10);
    let mut service_request = tonic::Request::new(ReceiverStream::new(request_rx));
    let mut req_meta = std::collections::HashMap::new();
    req_meta.insert("ctags".to_string(), b"should_not_be_forwarded".to_vec());
    service_request.extensions_mut().insert(ForwardedControlPlaneMetadata {
        request_metadata: req_meta,
        extensions: b"should_not_be_forwarded".to_vec(),
    });

    let response = TlsSessionManagerService::start_tls_session(&tsm, service_request)
        .await
        .expect("start_tls_session failed");
    let mut response_stream = response.into_inner();

    request_tx
        .send(Ok(StartTlsSessionRequest {
            frame: vec![0x16, 0x03, 0x01, 0x00, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        }))
        .await
        .unwrap();

    let next_msg =
        tokio::time::timeout(tokio::time::Duration::from_secs(5), response_stream.next())
            .await
            .expect("Timed out waiting for handshake error");
    match next_msg {
        Some(Err(status)) => assert_eq!(status.code(), tonic::Code::Internal),
        other => panic!("Expected handshake error status, got {:?}", other),
    }

    assert!(ez_invoker.received_requests.lock().unwrap().is_empty());
    assert!(ez_invoker.received_forwarded_metadata.lock().unwrap().is_empty());
}

#[tokio::test]
async fn test_start_tls_session_concurrent_sessions_isolate_forwarded_metadata() {
    let server_cert_pem = std::fs::read_to_string(find_test_file("test_server.pem"))
        .expect("failed to read test_server.pem");
    let server_key_pem = std::fs::read_to_string(find_test_file("test_server.key"))
        .expect("failed to read test_server.key");

    let ez_invoker = Arc::new(MockInvoker::new());
    let tsm = TlsSessionManager::new(
        ez_invoker.clone(),
        TsmConfig {
            server_target: get_server_target(),
            enable_avs: false,
            server_cert_pem: Some(server_cert_pem),
            server_key_pem: Some(server_key_pem),
        },
    );

    let mut meta_a_map = std::collections::HashMap::new();
    meta_a_map.insert("session".to_string(), b"A".to_vec());
    let meta_a = ForwardedControlPlaneMetadata {
        request_metadata: meta_a_map,
        extensions: b"ext_A".to_vec(),
    };

    let mut meta_b_map = std::collections::HashMap::new();
    meta_b_map.insert("session".to_string(), b"B".to_vec());
    let meta_b = ForwardedControlPlaneMetadata {
        request_metadata: meta_b_map,
        extensions: b"ext_B".to_vec(),
    };

    tokio::join!(
        run_session_against_tsm(&tsm, Some(meta_a.clone())),
        run_session_against_tsm(&tsm, Some(meta_b.clone())),
    );

    let recorded = ez_invoker.received_forwarded_metadata.lock().unwrap();
    assert_eq!(recorded.len(), 2);
    assert!(recorded.contains(&Some(meta_a)));
    assert!(recorded.contains(&Some(meta_b)));
}
