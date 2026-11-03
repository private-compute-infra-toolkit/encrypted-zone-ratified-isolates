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

pub mod ez_invoker;

use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status};

use tls_session_manager_sdk::{
    with_sdk_client, IsolateEzBridgeSdkClient, StartTlsSessionRequestStream,
    TlsSessionManagerService,
};

use tls_session_manager_proto::tls_session_manager::v1::{
    StartTlsSessionRequest, StartTlsSessionResponse,
};

use anyhow::Context;
use oak_session_tls::{OakSessionTlsServerContext, ServerContextConfig};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use setup_isolate_proto::setup_isolate::v1::FetchFrontendTlsCertificateRequest;

use enforcer_proto::enforcer::v1::IsolateState;

const RESPONSE_STREAM_CAPACITY: usize = 128;

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
    pub enable_avs: bool,
    pub server_cert_pem: Option<String>,
    pub server_key_pem: Option<String>,
}

use tokio::sync::OnceCell;

#[with_sdk_client]
pub struct TlsSessionManager {
    #[allow(dead_code)]
    server_target: InvokeConfig,
    server_context_cell: Arc<OnceCell<Result<OakSessionTlsServerContext, Status>>>,
    ez_invoker: Arc<dyn ez_invoker::EzInvoker>,
}

impl std::fmt::Debug for TlsSessionManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsSessionManager")
            .field("server_target", &self.server_target)
            .finish_non_exhaustive()
    }
}
impl TlsSessionManager {
    pub fn new(ez_invoker: Arc<dyn ez_invoker::EzInvoker>, tsm_config: TsmConfig) -> Self {
        let server_context_cell = Arc::new(OnceCell::new());

        if !tsm_config.enable_avs {
            let provider = if let (Some(cert_pem), Some(key_pem)) =
                (tsm_config.server_cert_pem, tsm_config.server_key_pem)
            {
                let cert_der = oak_session_tls::utils::load_cert_der(std::io::BufReader::new(
                    cert_pem.as_bytes(),
                ));
                let key_der = oak_session_tls::utils::load_key_der(std::io::BufReader::new(
                    key_pem.as_bytes(),
                ));
                oak_session_tls::utils::create_static_cert_identity_provider(
                    key_der,
                    vec![cert_der],
                )
            } else {
                oak_session_tls::utils::create_self_signed()
                    .expect("failed to create self-signed certificate provider")
            };

            let config = ServerContextConfig {
                tls_identity_provider: provider,
                client_trust_anchor_provider: None,
                custom_cert_verifier: None,
            };
            let server_context = OakSessionTlsServerContext::create(config)
                .expect("failed to create TLS server context");
            if server_context_cell.set(Ok(server_context)).is_err() {
                panic!("Failed to set TLS server context OnceCell");
            }
        } else {
            log::info!(
                "AVS is enabled for TLS Server Context. Skipping server context initialization."
            );
        }

        Self {
            server_target: tsm_config.server_target,
            server_context_cell,
            ez_invoker,
            client: Default::default(),
        }
    }

    async fn get_or_init_server_context(
        cell: &OnceCell<Result<OakSessionTlsServerContext, Status>>,
        ez_invoker: Arc<dyn ez_invoker::EzInvoker>,
    ) -> Result<&OakSessionTlsServerContext, Status> {
        let result = cell
            .get_or_init(|| async move {
                let (cert_pem, key_pem) =
                    match crate::fetch_frontend_certificate(ez_invoker.clone()).await {
                        Ok(res) => res,
                        Err(e) => {
                            return Err(Status::internal(format!(
                                "Failed to fetch frontend certificate: {:?}",
                                e
                            )))
                        }
                    };

                let cert_chain: Vec<rustls_pki_types::CertificateDer<'static>> =
                    match rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem.as_bytes()))
                        .collect::<Result<Vec<_>, _>>()
                    {
                        Ok(chain) => chain,
                        Err(e) => {
                            return Err(Status::internal(format!(
                                "Failed to parse certificate chain: {:?}",
                                e
                            )))
                        }
                    };

                log::info!("Fetched AVS cert chain with {:?} certificates", cert_chain.len());
                let key_der = oak_session_tls::utils::load_key_der(std::io::BufReader::new(
                    key_pem.as_bytes(),
                ));
                let provider = oak_session_tls::utils::create_static_cert_identity_provider(
                    key_der, cert_chain,
                );
                let config = ServerContextConfig {
                    tls_identity_provider: provider,
                    client_trust_anchor_provider: None,
                    custom_cert_verifier: None,
                };

                match OakSessionTlsServerContext::create(config) {
                    Ok(ctx) => Ok(ctx),
                    Err(e) => Err(Status::internal(format!(
                        "Failed to create OakSessionTlsServerContext: {:?}",
                        e
                    ))),
                }
            })
            .await;

        match result {
            Ok(ctx) => Ok(ctx),
            Err(status) => Err(status.clone()),
        }
    }

    pub fn start_async_certificate_fetch(&self) {
        let server_context_cell = self.server_context_cell.clone();
        let ez_invoker = self.ez_invoker.clone();

        tokio::spawn(async move {
            let res =
                Self::get_or_init_server_context(&server_context_cell, ez_invoker.clone()).await;
            match res {
                Ok(_) => {
                    if let Err(e) = ez_invoker.new_isolate_state(IsolateState::Ready).await {
                        log::error!("Failed to set IsolateState to Ready in Enforcer: {:?}", e);
                    }
                }
                Err(status) => {
                    log::error!("Async certificate fetch failed: {:?}", status);
                }
            }
        });
    }

    /// Generic helper to handle incoming StartTlsSession requests using new_initialized_session
    async fn start_tls_session_helper<T>(
        &self,
        client_request_stream: Request<T>,
    ) -> Result<Response<ReceiverStream<Result<StartTlsSessionResponse, Status>>>, Status>
    where
        T: StartTlsSessionRequestStream,
    {
        let ez_invoker = self.ez_invoker.clone();
        // Extract metadata and extensions once at stream start to forward after the handshake.
        let (request_metadata, request_extensions, client_request_stream) =
            client_request_stream.into_parts();
        let client_request_stream = Arc::new(tokio::sync::Mutex::new(client_request_stream));
        let (client_response_tx, client_response_rx) =
            tokio::sync::mpsc::channel(RESPONSE_STREAM_CAPACITY);

        let server_context_cell = self.server_context_cell.clone();

        tokio::spawn(async move {
            // Blocking until a OakSessionTLSContext is available.
            let server_context =
                match Self::get_or_init_server_context(&server_context_cell, ez_invoker.clone())
                    .await
                {
                    Ok(ctx) => ctx,
                    Err(status) => {
                        let _ = client_response_tx.send(Err(status)).await;
                        return;
                    }
                };
            let client_response_tx_clone = client_response_tx.clone();

            // Define the sender callback: sends TLS frames produced by the engine to the client via gRPC.
            let sender = move |frame: Vec<u8>| {
                let client_response_tx = client_response_tx_clone.clone();
                async move {
                    client_response_tx
                        .send(Ok(StartTlsSessionResponse { frame }))
                        .await
                        .map_err(|e| std::io::Error::other(e.to_string()))
                }
            };

            let client_request_stream_clone = client_request_stream.clone();
            // Define the receiver callback: pulls client TLS frames from the incoming gRPC stream.
            let receiver = move || {
                let client_request_stream = client_request_stream_clone.clone();
                async move {
                    let mut stream = client_request_stream.lock().await;
                    match stream.next().await {
                        Some(Ok(request)) => Ok(Some(request.frame)),
                        Some(Err(e)) => Err(std::io::Error::other(e.to_string())),
                        None => Ok(None),
                    }
                }
            };

            // Run the handshake. Once successful, we obtain an open OakSessionTls and initial application data.
            match server_context.new_initialized_session(sender, receiver).await {
                Ok((session, _initial_data)) => {
                    log::info!("TLS Handshake completed successfully!");

                    // Create channel for talking to the server
                    let (server_request_tx, server_request_rx) =
                        tokio::sync::mpsc::channel::<Vec<u8>>(RESPONSE_STREAM_CAPACITY);
                    let server_request = Request::from_parts(
                        request_metadata,
                        request_extensions,
                        server_request_rx,
                    );
                    let server_response_rx = match ez_invoker.stream_server(server_request).await {
                        Ok(response) => response,
                        Err(status) => {
                            log::error!("Failed to start stream_server: {:?}", status);
                            if let Err(e) = client_response_tx.send(Err(status)).await {
                                log::error!("Failed to send error status to client: {:?}", e);
                            }
                            return;
                        }
                    };

                    let session = Arc::new(tokio::sync::Mutex::new(session));
                    let mut join_set = tokio::task::JoinSet::new();

                    // Take encrypted requests from client, pass decrypted requests to server
                    let client_request_stream_clone = client_request_stream.clone();
                    let session_clone = session.clone();
                    join_set.spawn(async move {
                        while let Some(request) =
                            client_request_stream_clone.lock().await.next().await
                        {
                            let request = match request {
                                Ok(req) => req,
                                Err(e) => {
                                    log::error!("Client request stream error: {:?}", e);
                                    return Err(anyhow::anyhow!(
                                        "Client request stream error: {:?}",
                                        e
                                    ));
                                }
                            };
                            let decrypted_payload =
                                match session_clone.lock().await.decrypt(&request.frame) {
                                    Ok(payload) => payload,
                                    Err(e) => {
                                        log::error!("Server decryption failed: {:?}", e);
                                        return Err(anyhow::anyhow!(
                                            "Server decryption failed: {:?}",
                                            e
                                        ));
                                    }
                                };
                            if server_request_tx.send(decrypted_payload).await.is_err() {
                                break;
                            }
                        }
                        drop(server_request_tx);
                        Ok::<(), anyhow::Error>(())
                    });

                    // Take decrypted responses from server, pass encrypted responses to client
                    let client_response_tx_clone = client_response_tx.clone();
                    let session_clone2 = session.clone();
                    join_set.spawn(async move {
                        let mut server_response_rx = server_response_rx;
                        while let Some(response_result) = server_response_rx.recv().await {
                            let response = match response_result {
                                Ok(resp) => resp,
                                Err(status) => {
                                    log::error!("Server response stream error: {:?}", status);
                                    if let Err(e) =
                                        client_response_tx_clone.send(Err(status.clone())).await
                                    {
                                        log::error!(
                                            "Failed to send error status to client: {:?}",
                                            e
                                        );
                                    }
                                    return Err(anyhow::anyhow!(
                                        "Server stream error: {:?}",
                                        status
                                    ));
                                }
                            };
                            let encrypted_response =
                                match session_clone2.lock().await.encrypt(&response) {
                                    Ok(frame) => frame,
                                    Err(e) => {
                                        log::error!("Server encryption failed: {:?}", e);
                                        return Err(anyhow::anyhow!(
                                            "Server encryption failed: {:?}",
                                            e
                                        ));
                                    }
                                };
                            if client_response_tx_clone
                                .send(Ok(StartTlsSessionResponse { frame: encrypted_response }))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        drop(client_response_tx_clone);
                        Ok::<(), anyhow::Error>(())
                    });

                    drop(client_response_tx);

                    // Wait for tasks to complete or fail
                    while let Some(res) = join_set.join_next().await {
                        match res {
                            Ok(Ok(())) => {
                                // One direction finished cleanly. Continue waiting for the other.
                            }
                            Ok(Err(e)) => {
                                log::error!("Task failed: {:?}", e);
                                join_set.abort_all();
                                break;
                            }
                            Err(e) => {
                                log::error!("Task join error: {:?}", e);
                                join_set.abort_all();
                                break;
                            }
                        }
                    }
                }

                Err(e) => {
                    log::error!("TLS Handshake failed: {:?}", e);
                    if let Err(send_err) = client_response_tx
                        .send(Err(Status::internal(format!("Handshake failed: {:?}", e))))
                        .await
                    {
                        log::error!(
                            "Failed to send handshake failure status to client: {:?}",
                            send_err
                        );
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(client_response_rx)))
    }
}

/// Standard StartTlsSession RPC
#[tonic::async_trait]
impl TlsSessionManagerService for TlsSessionManager {
    type StartTlsSessionStream = ReceiverStream<Result<StartTlsSessionResponse, Status>>;

    async fn start_tls_session<T: StartTlsSessionRequestStream>(
        &self,
        request: Request<T>,
    ) -> Result<Response<Self::StartTlsSessionStream>, Status> {
        // TODO: b/509939896 - Pass through or proxy the session to the actual downstream target once start_tls_session_helper is updated.
        self.start_tls_session_helper(request).await
    }
}

// For testing purposes and legacy compatibility, we also implement the Tonic-generated trait.
#[tonic::async_trait]
impl tls_session_manager_proto::tls_session_manager::v1::tls_session_manager_service_server::TlsSessionManagerService for TlsSessionManager {
    type StartTlsSessionStream = ReceiverStream<Result<StartTlsSessionResponse, Status>>;

    async fn start_tls_session(
        &self,
        request: Request<tonic::Streaming<StartTlsSessionRequest>>,
    ) -> Result<Response<Self::StartTlsSessionStream>, Status> {
        // TODO: b/509939896 - Pass through or proxy the session to the actual downstream target once start_tls_session_helper is updated.
        self.start_tls_session_helper(request).await
    }
}

fn der_chain_to_pem(chain: &[Vec<u8>]) -> String {
    let mut pem_chain = String::new();
    for der in chain {
        let pem_struct = pem::Pem::new("CERTIFICATE", der.clone());
        let pem_str = pem::encode(&pem_struct);
        pem_chain.push_str(&pem_str);
    }
    pem_chain
}

/// Fetches the signed frontend TLS certificate from SetupService using the given invoker,
/// generates the matching local key pair, and returns the PEM-encoded certificate chain
/// and private key.
///
/// # Returns
/// A tuple containing:
/// - `(String, String)`: `(PEM-encoded Certificate Chain, PEM-encoded Private Key)`
pub async fn fetch_frontend_certificate(
    ez_invoker: Arc<dyn crate::ez_invoker::EzInvoker + Send + Sync>,
) -> anyhow::Result<(String, String)> {
    // 1. Create local key pair
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .map_err(|e| anyhow::anyhow!("generating local key pair: {}", e))?;

    // 2. Generate an empty CSR.
    let params = CertificateParams::default();
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| anyhow::anyhow!("generating CSR: {}", e))?;
    let csr_der = csr.der().to_vec();

    // 3. Send the CSR in the FetchFrontendTlsCertificate request using the invoker
    let request =
        FetchFrontendTlsCertificateRequest { signed_certificate_signing_request: csr_der };

    let response = ez_invoker
        .fetch_frontend_certificate(request)
        .await
        .context("fetching frontend TLS certificate with retry")?;

    // 4. In standard TLS (RFC 5246 / RFC 8446), the certificate chain sent by the server
    // should include the server's certificate and any intermediate certificates, but omit the
    // root CA certificate because the client must already have the root CA in its trust store.
    let cert_pem = der_chain_to_pem(&response.certificate_chain);
    let key_pem = key_pair.serialize_pem();

    Ok((cert_pem, key_pem))
}
