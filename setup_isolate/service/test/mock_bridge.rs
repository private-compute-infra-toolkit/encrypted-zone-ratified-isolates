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

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use enforcer_proto::enforcer::v1::{
    self as ev1,
    isolate_ez_bridge_server::{IsolateEzBridge, IsolateEzBridgeServer},
};
use payload_proto::enforcer::v1::{
    EzHybridPayload, EzPayloadData, ez_hybrid_payload::DeliveryMethod,
};
use prost::Message;
use setup_isolate_lib::{SetupConfig, SetupService};
use setup_isolate_proto::setup_isolate::v1::{GetCertificateRequest, GetCertificateResponse};
use setup_isolate_sdk::IsolateEzBridgeSdkClient;
use tokio::{net::UnixListener, runtime::Runtime};
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

type CertHandler =
    Arc<dyn Fn(&GetCertificateRequest) -> Result<GetCertificateResponse, Status> + Send + Sync>;
type RoleSlot = (CertHandler, Vec<GetCertificateRequest>);

#[derive(Clone, Default)]
struct MockBridge {
    roles: Arc<Mutex<HashMap<String, RoleSlot>>>,
}

type TestEnv = (MockBridge, Arc<IsolateEzBridgeSdkClient>, Runtime);
static SHARED_ENV: OnceLock<TestEnv> = OnceLock::new();
static NEXT_ROLE_ID: AtomicU64 = AtomicU64::new(1);

fn shared_env() -> &'static TestEnv {
    SHARED_ENV.get_or_init(|| {
        std::thread::spawn(|| {
            let rt = Runtime::new().unwrap();
            let (bridge, client) = rt.block_on(async {
                let sock =
                    std::env::temp_dir().join(format!("ez_setup_test_{}.uds", std::process::id()));
                let _ = std::fs::remove_file(&sock);
                let inc = UnixListenerStream::new(UnixListener::bind(&sock).unwrap());
                let bridge = MockBridge::default();
                let svc = IsolateEzBridgeServer::new(bridge.clone());
                tokio::spawn(Server::builder().add_service(svc).serve_with_incoming(inc));
                // Safety: initialized once via `OnceLock` before `CLIENT_UDS_PATH` is read.
                unsafe { std::env::set_var("CLIENT_UDS_PATH", &sock) };
                let client = IsolateEzBridgeSdkClient::new().await.unwrap();
                (bridge, Arc::new(client))
            });
            (bridge, client, rt)
        })
        .join()
        .unwrap()
    })
}

pub fn build_service_with_handler<F>(allow_fallback: bool, handler: F) -> (SetupService, String)
where
    F: Fn(&GetCertificateRequest) -> Result<GetCertificateResponse, Status> + Send + Sync + 'static,
{
    let (bridge, client, _) = shared_env();
    let role = format!("role_{}", NEXT_ROLE_ID.fetch_add(1, Ordering::Relaxed));
    let mut roles = bridge.roles.lock().unwrap();
    roles.insert(role.clone(), (Arc::new(handler), vec![]));
    drop(roles);
    let setup_svc = SetupService::new(SetupConfig {
        operator_role: role.clone(),
        enable_unattested_fallback: allow_fallback,
    });
    setup_svc.set_client(client.clone());
    (setup_svc, role)
}

pub fn take_recorded_requests(role: &str) -> Vec<GetCertificateRequest> {
    let mut roles = shared_env().0.roles.lock().unwrap();
    roles
        .get_mut(role)
        .map(|(_, reqs)| std::mem::take(reqs))
        .unwrap_or_default()
}

#[tonic::async_trait]
impl IsolateEzBridge for MockBridge {
    type StreamInvokeEzStream = ReceiverStream<Result<ev1::InvokeEzResponse, Status>>;
    type CreateMemshareStream = ReceiverStream<Result<ev1::CreateMemshareResponse, Status>>;
    type NotifyIsolateStateStream = ReceiverStream<Result<ev1::NotifyIsolateStateResponse, Status>>;
    type StreamSubscribeToStream = ReceiverStream<Result<ev1::StreamSubscribeToResponse, Status>>;

    async fn invoke_ez(
        &self,
        request: Request<ev1::InvokeEzRequest>,
    ) -> Result<Response<ev1::InvokeEzResponse>, Status> {
        let req = request.into_inner();
        let req_bytes = match req.isolate_request_payload.and_then(|p| p.delivery_method) {
            Some(DeliveryMethod::InlineData(d)) => {
                d.datagrams.into_iter().next().ok_or_else(|| {
                    Status::invalid_argument("missing datagrams in InlineData payload")
                })?
            }
            _ => return Err(Status::invalid_argument("expected InlineData payload")),
        };
        let cert_req = GetCertificateRequest::decode(req_bytes.as_slice())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let handler = {
            let mut roles = self.roles.lock().unwrap();
            let (h, reqs) = roles
                .get_mut(&cert_req.operator_role)
                .ok_or_else(|| Status::not_found("operator_role not registered in mock bridge"))?;
            reqs.push(cert_req.clone());
            h.clone()
        };
        let datagrams = vec![handler(&cert_req)?.encode_to_vec()];
        Ok(Response::new(ev1::InvokeEzResponse {
            control_plane_metadata: req.control_plane_metadata,
            ez_response_payload: Some(EzHybridPayload {
                delivery_method: Some(DeliveryMethod::InlineData(EzPayloadData { datagrams })),
            }),
            ..Default::default()
        }))
    }

    async fn stream_invoke_ez(
        &self,
        _: Request<Streaming<ev1::InvokeEzRequest>>,
    ) -> Result<Response<Self::StreamInvokeEzStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn create_memshare(
        &self,
        _: Request<Streaming<ev1::CreateMemshareRequest>>,
    ) -> Result<Response<Self::CreateMemshareStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn create_fileshare(
        &self,
        _: Request<ev1::CreateFileshareRequest>,
    ) -> Result<Response<ev1::CreateFileshareResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn notify_isolate_state(
        &self,
        _: Request<Streaming<ev1::NotifyIsolateStateRequest>>,
    ) -> Result<Response<Self::NotifyIsolateStateStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn poll_isolate_state(
        &self,
        _: Request<ev1::PollIsolateStateRequest>,
    ) -> Result<Response<ev1::PollIsolateStateResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn publish_event_for(
        &self,
        _: Request<ev1::PublishEventForRequest>,
    ) -> Result<Response<ev1::PublishEventForResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn stream_subscribe_to(
        &self,
        _: Request<ev1::StreamSubscribeToRequest>,
    ) -> Result<Response<Self::StreamSubscribeToStream>, Status> {
        Err(Status::unimplemented("unused"))
    }
}
