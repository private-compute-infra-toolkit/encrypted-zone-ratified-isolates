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
use tokio::sync::mpsc::channel;
use tokio::sync::oneshot;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::Server;

use tls_session_manager_proto::tls_session_manager::v1::{
    tls_session_manager_service_client::TlsSessionManagerServiceClient,
    tls_session_manager_service_server::TlsSessionManagerServiceServer, StartTlsSessionRequest,
};

// We use the SDK's adapter to bridge our implementation to a regular tonic server for testing
// if needed, but since our TlsSessionManager no longer implements the regular tonic trait
// directly (it implements the SDK's trait), we have a choice:
// 1. Implement the tonic trait for testing.
// 2. Test via the SDK's RpcDispatcher (more complex).
// 3. Keep a simple implementation of the tonic trait for the stub.

use tls_session_manager::{InvokeConfig, TlsSessionManager, TsmConfig};

fn get_server_target() -> InvokeConfig {
    InvokeConfig {
        domain_name: "ServerDomain".to_string(),
        service_name: "ServerService".to_string(),
        method_name: "ServerMethod".to_string(),
    }
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
async fn test_start_tls_session_unimplemented() {
    let tsm = TlsSessionManager::new(TsmConfig {
        server_target: get_server_target(),
        ..Default::default()
    });

    let (mut tsm_client, shutdown_tx) = start_tsm(tsm).await.unwrap();

    let req_stream = ReceiverStream::new(channel::<StartTlsSessionRequest>(10).1);
    let result = tsm_client.start_tls_session(req_stream).await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::Unimplemented);

    shutdown_tx.send(()).unwrap();
}
