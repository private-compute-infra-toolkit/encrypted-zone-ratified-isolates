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
use ez_isolate_bridge_sdk::PrivateInferenceService;
use prost::Message;
use std::env;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use tokio::fs::{create_dir_all, remove_file, try_exists};
use tokio::net::UnixListener;
use tokio::sync::mpsc::{channel, Sender};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::Request;

use enforcer_proto::data_scope_proto::enforcer::v1::DataScopeType;
use enforcer_proto::enforcer::v1::isolate_ez_bridge_server::{
    IsolateEzBridge, IsolateEzBridgeServer,
};
use enforcer_proto::enforcer::v1::{
    CreateFileshareRequest, CreateFileshareResponse, CreateMemshareRequest, CreateMemshareResponse,
    InvokeEzRequest, InvokeEzResponse, NotifyIsolateStateRequest, NotifyIsolateStateResponse,
    PollIsolateStateRequest, PollIsolateStateResponse, PublishEventForRequest,
    PublishEventForResponse, StreamSubscribeToRequest, StreamSubscribeToResponse,
};
use payload_proto::enforcer::v1::{ez_hybrid_payload, EzHybridPayload, EzPayloadData};
use private_inference_service_proto::private_inference_service::{
    FeatureName, GenerateContentRequest, GenerateContentResponse,
};
use trusted_aratea_traffic_lib::trusted_aratea_traffic::TrustedArateaTrafficImpl;

#[derive(Default, Clone)]
pub struct MockIsolateEzBridgeServer {}

#[tonic::async_trait]
impl IsolateEzBridge for MockIsolateEzBridgeServer {
    type StreamInvokeEzStream =
        Pin<Box<dyn Stream<Item = Result<InvokeEzResponse, tonic::Status>> + Send + 'static>>;

    async fn invoke_ez(
        &self,
        request: tonic::Request<InvokeEzRequest>,
    ) -> Result<tonic::Response<InvokeEzResponse>, tonic::Status> {
        let req = request.into_inner();
        if let Some(ref iscope) = req.isolate_request_iscope {
            if let Some(scope) = iscope.datagram_iscopes.first() {
                assert_eq!(scope.scope_type, DataScopeType::UserPrivate as i32);
            } else {
                panic!("No datagram_iscopes found in request");
            }
        } else {
            panic!("No isolate_request_iscope found in request");
        }

        let payload = if let Some(meta) = &req.control_plane_metadata {
            if meta.destination_service_name == "PrivateInferenceService" {
                if let Some(ref isolate_payload) = req.isolate_request_payload {
                    if let Some(ez_hybrid_payload::DeliveryMethod::InlineData(ref data)) =
                        isolate_payload.delivery_method
                    {
                        if !data.datagrams.is_empty() {
                            let request_proto =
                                GenerateContentRequest::decode(data.datagrams[0].as_slice())
                                    .map_err(|e| tonic::Status::invalid_argument(e.to_string()))?;

                            let response_proto = GenerateContentResponse {
                                opaque_field_1: format!("Echo: {}", request_proto.feature_name)
                                    .into_bytes(),
                            };

                            Some(EzHybridPayload {
                                delivery_method: Some(
                                    ez_hybrid_payload::DeliveryMethod::InlineData(EzPayloadData {
                                        datagrams: vec![response_proto.encode_to_vec()],
                                    }),
                                ),
                            })
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                req.isolate_request_payload
            }
        } else {
            req.isolate_request_payload
        };

        Ok(tonic::Response::new(InvokeEzResponse {
            control_plane_metadata: req.control_plane_metadata,
            ez_response_payload: payload,
            ..Default::default()
        }))
    }

    async fn stream_invoke_ez(
        &self,
        _request: tonic::Request<tonic::Streaming<InvokeEzRequest>>,
    ) -> Result<tonic::Response<Self::StreamInvokeEzStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("unimplemented"))
    }

    type NotifyIsolateStateStream =
        tokio_stream::wrappers::ReceiverStream<Result<NotifyIsolateStateResponse, tonic::Status>>;
    async fn notify_isolate_state(
        &self,
        _request: tonic::Request<tonic::Streaming<NotifyIsolateStateRequest>>,
    ) -> Result<tonic::Response<Self::NotifyIsolateStateStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("unimplemented"))
    }

    type CreateMemshareStream =
        tokio_stream::wrappers::ReceiverStream<Result<CreateMemshareResponse, tonic::Status>>;
    async fn create_memshare(
        &self,
        _request: tonic::Request<tonic::Streaming<CreateMemshareRequest>>,
    ) -> Result<tonic::Response<Self::CreateMemshareStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("unimplemented"))
    }

    async fn poll_isolate_state(
        &self,
        _request: tonic::Request<PollIsolateStateRequest>,
    ) -> Result<tonic::Response<PollIsolateStateResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("unimplemented"))
    }

    async fn create_fileshare(
        &self,
        _request: tonic::Request<CreateFileshareRequest>,
    ) -> Result<tonic::Response<CreateFileshareResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("unimplemented"))
    }

    async fn publish_event_for(
        &self,
        _request: tonic::Request<PublishEventForRequest>,
    ) -> Result<tonic::Response<PublishEventForResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("unimplemented"))
    }

    type StreamSubscribeToStream = ReceiverStream<Result<StreamSubscribeToResponse, tonic::Status>>;
    async fn stream_subscribe_to(
        &self,
        _request: tonic::Request<StreamSubscribeToRequest>,
    ) -> Result<tonic::Response<Self::StreamSubscribeToStream>, tonic::Status> {
        Err(tonic::Status::unimplemented("unimplemented"))
    }
}

pub struct TestHarness {
    pub client: Arc<ez_isolate_bridge_sdk::IsolateEzBridgeSdkClient>,
    pub isolate_ez_bridge_handle: JoinHandle<Result<(), anyhow::Error>>,
    pub isolate_ez_bridge_shutdown_tx: Sender<()>,
}

impl TestHarness {
    pub async fn start(socket_path: &Path) -> Result<Self> {
        env::set_var("CLIENT_UDS_PATH", socket_path.to_str().unwrap());
        if let Some(parent) = socket_path.parent() {
            create_dir_all(parent).await?;
        }
        if try_exists(socket_path).await? {
            remove_file(socket_path).await?;
        }
        let uds = UnixListener::bind(socket_path)?;
        let uds_stream = UnixListenerStream::new(uds);

        let (isolate_ez_bridge_shutdown_tx, mut isolate_ez_bridge_shutdown_rx) = channel(1);
        let mock_enforcer_server = MockIsolateEzBridgeServer::default();
        let isolate_ez_bridge_handle = tokio::spawn(async move {
            let server = IsolateEzBridgeServer::new(mock_enforcer_server);
            Server::builder()
                .add_service(server)
                .serve_with_incoming_shutdown(uds_stream, async move {
                    let _ = isolate_ez_bridge_shutdown_rx.recv().await;
                })
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            Ok(())
        });
        // Wait a small amount of time for the server to start listening
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        Ok(Self {
            client: Arc::new(
                ez_isolate_bridge_sdk::IsolateEzBridgeSdkClient::new()
                    .await
                    .map_err(|e| anyhow::anyhow!("{}", e))?,
            ),
            isolate_ez_bridge_handle,
            isolate_ez_bridge_shutdown_tx,
        })
    }

    pub async fn stop(self) -> Result<()> {
        let _ = self.isolate_ez_bridge_shutdown_tx.send(()).await;
        let _ = self.isolate_ez_bridge_handle.await?;
        Ok(())
    }
}

#[tokio::test]
async fn test_generate_content_forwarding() {
    let socket_path = Path::new("/tmp/trusted_aratea_traffic_test.sock");
    let harness = TestHarness::start(socket_path).await.unwrap();

    let service = TrustedArateaTrafficImpl::new("forward.domain".to_string());
    service.set_client(harness.client.clone());

    // Test allowed Smart Trust features
    for feature in [1100, 1101, 1199] {
        let req = Request::new(GenerateContentRequest {
            feature_name: feature,
            opaque_field_2: b"test_payload".to_vec(),
        });
        let response = service.generate_content(req).await.unwrap();
        assert_eq!(response.into_inner().opaque_field_1, format!("Echo: {}", feature).into_bytes());
    }

    // Test disallowed or unknown features
    for (feature_name, expected_err_msg) in [
        (FeatureName::Unspecified as i32, "Only Smart Trust features are allowed"),
        (999, "Unknown feature name"),
    ] {
        let req = Request::new(GenerateContentRequest {
            feature_name,
            opaque_field_2: b"test_payload".to_vec(),
        });
        let err = service.generate_content(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains(expected_err_msg));
    }

    harness.stop().await.unwrap();
}
