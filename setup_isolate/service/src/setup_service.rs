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

use metrics::Metrics;
use std::time::Instant;
use tonic::{Request, Response, Status};

use ez_mtls_proto::enforcer::v1::{GetCertificateRequest, GetCertificateResponse, PolicyHint};
use oak_time_std::clock::SystemTimeClock;
use setup_isolate_proto::setup_isolate::v1::{
    FetchFrontendTlsCertificateRequest, FetchFrontendTlsCertificateResponse,
    FetchTlsCertificateRequest, FetchTlsCertificateResponse, GetTlsCsrRequest, GetTlsCsrResponse,
    ValidateIsolateEndorsementRequest, ValidateIsolateEndorsementResponse,
};
use setup_isolate_sdk::{
    DataScopeType, IsolateEzBridgeSdkClient, RpcHandler, SetupService as SetupServiceTrait,
    with_sdk_client,
};

/// Configuration for the Setup Ratified Isolate
#[derive(Debug, Clone, Default)]
pub struct SetupConfig {
    pub operator_role: String,
}

/// Setup Service implementation supports multiple bootstrapping methods defined in
/// setup_isolate_proto::setup_isolate::v1.
#[with_sdk_client]
pub struct SetupService {
    #[allow(dead_code)]
    config: SetupConfig,
    metrics: Metrics,
}

impl SetupService {
    /// Creates a new instance of the Setup Service.
    pub fn new(config: SetupConfig) -> Self {
        Self {
            config,
            metrics: Metrics::default(),
            // The client is initialized with Default::default() because the actual connection
            // establishment and management are handled by the #[with_sdk_client] macro wrapper.
            client: Default::default(),
        }
    }

    async fn fetch_certificate_internal(
        &self,
        signed_csr: Vec<u8>,
        policy_hint: PolicyHint,
    ) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), Status> {
        // TODO(b/529807113): Remove verbose loggings for debugging in this repo.
        log::info!(
            "fetch_certificate_internal called with csr size: {}, policy_hint: {:?}",
            signed_csr.len(),
            policy_hint
        );

        let get_cert_req = GetCertificateRequest {
            csr: signed_csr,
            operator_role: self.config.operator_role.clone(),
            policy_hint: policy_hint.into(),
        };

        // The request is routed externally to the Proxy through the
        // thick/avs-proxy, which is a special endpoint for proxying traffic to AVS.
        // The corresponding Ez Manifest must define this endpoint as a backend dependency.
        let rpc_handler = RpcHandler::new(
            self.get_client(),
            "thick/avs-proxy".to_string(),
            "".to_string(), // The service name is left empty because the external proxy routes traffic directly based on the domain.
            DataScopeType::Public,
        );

        log::info!("Making isolate_rpc_call to thick/avs-proxy for GetCertificate");
        let proxy_start = Instant::now();
        let result: Result<GetCertificateResponse, Status> = rpc_handler
            .isolate_rpc_call(
                "",
                /* method name: empty for external proxies */ get_cert_req,
            )
            .await;
        self.metrics
            .record_avs_proxy_latency(proxy_start.elapsed().as_secs_f64());

        match &result {
            Ok(resp) => {
                log::info!(
                    "isolate_rpc_call succeeded. Received {} certs.",
                    resp.certs.len()
                );
                self.metrics.record_certificate_fetch(policy_hint, "OK");
            }
            Err(e) => {
                log::error!("isolate_rpc_call failed with error: {:?}", e);
                self.metrics
                    .record_certificate_fetch(policy_hint, e.code().to_string().as_str());
            }
        }

        let get_cert_resp: GetCertificateResponse = result?;

        // The last element in the certs vector is the trust anchor.
        let mut certs = get_cert_resp.certs;
        let trust_anchors = match certs.pop() {
            Some(root_cert) => vec![root_cert],
            None => Vec::new(),
        };

        log::info!(
            "Processed certificates. Chain size: {}, trust anchors size: {}",
            certs.len(),
            trust_anchors.len()
        );

        Ok((certs, trust_anchors))
    }
}

#[tonic::async_trait]
impl SetupServiceTrait for SetupService {
    async fn get_tls_csr(
        &self,
        request: Request<GetTlsCsrRequest>,
    ) -> Result<Response<GetTlsCsrResponse>, Status> {
        let req = request.into_inner();
        log::info!(
            "get_tls_csr called with public_key size: {}",
            req.public_key.len()
        );
        Err(Status::unimplemented("not implemented yet"))
    }

    async fn fetch_mtls_certificate(
        &self,
        request: Request<FetchTlsCertificateRequest>,
    ) -> Result<Response<FetchTlsCertificateResponse>, Status> {
        let start = Instant::now();
        let method = "FetchMtlsCertificate";
        let req = request.into_inner();
        log::info!(
            "fetch_mtls_certificate called with csr size: {}",
            req.signed_certificate_signing_request.len()
        );
        let result = self
            .fetch_certificate_internal(
                req.signed_certificate_signing_request,
                PolicyHint::BackendMtlsCert,
            )
            .await;

        self.metrics
            .record_rpc_latency(method, start.elapsed().as_secs_f64());

        match &result {
            Ok((chain, anchors)) => {
                log::info!(
                    "fetch_mtls_certificate succeeded. Chain size: {}, anchors size: {}",
                    chain.len(),
                    anchors.len()
                );
                self.metrics.record_rpc_call(method, "OK");
            }
            Err(e) => {
                log::error!("fetch_mtls_certificate failed with error: {:?}", e);
                self.metrics
                    .record_rpc_call(method, e.code().to_string().as_str());
            }
        }

        let (certificate_chain, trust_anchors) = result?;

        Ok(Response::new(FetchTlsCertificateResponse {
            certificate_chain,
            trust_anchors,
        }))
    }

    async fn fetch_frontend_tls_certificate(
        &self,
        request: Request<FetchFrontendTlsCertificateRequest>,
    ) -> Result<Response<FetchFrontendTlsCertificateResponse>, Status> {
        let start = Instant::now();
        let method = "FetchFrontendTlsCertificate";
        let req = request.into_inner();
        log::info!(
            "fetch_frontend_tls_certificate called with csr size: {}",
            req.signed_certificate_signing_request.len()
        );
        let result = self
            .fetch_certificate_internal(
                req.signed_certificate_signing_request,
                PolicyHint::FrontendTlsCert,
            )
            .await;

        self.metrics
            .record_rpc_latency(method, start.elapsed().as_secs_f64());

        match &result {
            Ok((chain, anchors)) => {
                log::info!(
                    "fetch_frontend_tls_certificate succeeded. Chain size: {}, anchors size: {}",
                    chain.len(),
                    anchors.len()
                );
                self.metrics.record_rpc_call(method, "OK");
            }
            Err(e) => {
                log::error!("fetch_frontend_tls_certificate failed with error: {:?}", e);
                self.metrics
                    .record_rpc_call(method, e.code().to_string().as_str());
            }
        }

        let (certificate_chain, trust_anchors) = result?;

        Ok(Response::new(FetchFrontendTlsCertificateResponse {
            certificate_chain,
            trust_anchors,
        }))
    }

    async fn validate_isolate_endorsement(
        &self,
        request: Request<ValidateIsolateEndorsementRequest>,
    ) -> Result<Response<ValidateIsolateEndorsementResponse>, Status> {
        let start = Instant::now();
        let method = "ValidateIsolateEndorsement";
        let req = request.into_inner();
        let clock = SystemTimeClock;
        let response = pes::verify_pes_endorsement(&clock, req);

        self.metrics
            .record_pes_validation_outcome(response.validation_error());
        self.metrics
            .record_rpc_latency(method, start.elapsed().as_secs_f64());

        Ok(Response::new(response))
    }
}
