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

use std::sync::Arc;

use prost::Message;
use setup_isolate_lib::{SetupConfig, SetupService};
use setup_isolate_proto::setup_isolate::v1::{
    ExpectedClaims, GetTlsCsrRequest, IsolatePackageEndorsement, ValidateIsolateEndorsementRequest,
    validate_isolate_endorsement_response::IsolateEndorsementValidationError,
};
use setup_isolate_sdk::{
    IsolateRpcService, SetupService as SetupServiceTrait, SetupServiceIsolateRpcService,
};
use tonic::Request;

#[tokio::test]
async fn test_get_tls_csr_unimplemented() {
    let service = SetupService::new(SetupConfig::default());
    let request = Request::new(GetTlsCsrRequest::default());
    let response = service.get_tls_csr(request).await;
    assert!(response.is_err());
    assert_eq!(response.unwrap_err().code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn test_get_tls_csr_adapter_unimplemented() {
    let service = Arc::new(SetupService::new(SetupConfig::default()));
    let adapter = SetupServiceIsolateRpcService::new(service);
    let request = GetTlsCsrRequest::default();
    let mut request_bytes = Vec::new();
    request.encode(&mut request_bytes).unwrap();

    let response = adapter
        .unary_rpc_handler("GetTlsCsr", &request_bytes, None)
        .await;
    assert!(response.is_err());
    assert_eq!(response.unwrap_err().code(), tonic::Code::Unimplemented);
}

#[tokio::test]
async fn test_validate_isolate_endorsement_missing_claims() {
    let service = SetupService::new(SetupConfig::default());
    let request = Request::new(ValidateIsolateEndorsementRequest {
        expected_claims: None,
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json: vec![1],
            signature: vec![2],
            pes_confirmation_json: vec![3],
        }),
        package_digest_sha256: "test-digest".to_string(),
    });
    let response = service
        .validate_isolate_endorsement(request)
        .await
        .unwrap()
        .into_inner();
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::ParsingFailure as i32
    );
    assert!(response.error_message.contains("Missing expected_claims"));
}

#[tokio::test]
async fn test_validate_isolate_endorsement_missing_digest() {
    let service = SetupService::new(SetupConfig::default());
    let request = Request::new(ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "test-publisher".to_string(),
            isolate_name: "test-isolate".to_string(),
            package_filename: "test-package.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json: vec![1],
            signature: vec![2],
            pes_confirmation_json: vec![3],
        }),
        package_digest_sha256: "".to_string(),
    });
    let response = service
        .validate_isolate_endorsement(request)
        .await
        .unwrap()
        .into_inner();
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::ParsingFailure as i32
    );
    assert!(
        response
            .error_message
            .contains("Missing package_digest_sha256")
    );
}

#[tokio::test]
async fn test_validate_isolate_endorsement_missing_endorsement() {
    let service = SetupService::new(SetupConfig::default());
    let request = Request::new(ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "test-publisher".to_string(),
            isolate_name: "test-isolate".to_string(),
            package_filename: "test-package.tar".to_string(),
        }),
        isolate_package_endorsement: None,
        package_digest_sha256: "test-digest".to_string(),
    });
    let response = service
        .validate_isolate_endorsement(request)
        .await
        .unwrap()
        .into_inner();
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::ParsingFailure as i32
    );
    assert!(
        response
            .error_message
            .contains("Missing isolate_package_endorsement")
    );
}

#[tokio::test]
async fn test_validate_isolate_endorsement_invalid_endorsement_bytes() {
    let service = SetupService::new(SetupConfig::default());
    let request = Request::new(ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "test-publisher".to_string(),
            isolate_name: "test-isolate".to_string(),
            package_filename: "test-package.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json: vec![1],
            signature: vec![2],
            pes_confirmation_json: vec![3],
        }),
        package_digest_sha256: "test-digest".to_string(),
    });
    let response = service
        .validate_isolate_endorsement(request)
        .await
        .unwrap()
        .into_inner();
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::ParsingFailure as i32
    );
    assert!(!response.error_message.is_empty());
}
