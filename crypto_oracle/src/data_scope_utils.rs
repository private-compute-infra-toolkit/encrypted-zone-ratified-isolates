// Copyright 2025 Google LLC
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

/// Utility functions for manipulating EZ structures that the oracle uses
/// These do not themselves rely on the oracle or its strucrtures
use data_scope_proto::enforcer::v1::{DataScopeType, EzDataScope, EzStaticScopeInfo};
use payload_proto::enforcer::v1::{EzPayload, EzPayloadData, EzPayloadScope};

/// Make a simple EzDataScope from a data scope type enum
pub fn to_datascope(scope: DataScopeType) -> EzDataScope {
    EzDataScope {
        static_info: Some(EzStaticScopeInfo { scope_type: scope.into(), ..Default::default() }),
        ..Default::default()
    }
}

/// Make a simple EzPayload from a single data and scope type
pub fn to_payload(data: Vec<u8>, scope: DataScopeType) -> EzPayload {
    EzPayload {
        payload_scope: Some(EzPayloadScope { datagram_scopes: vec![to_datascope(scope)] }),
        payload_data: Some(EzPayloadData { datagrams: vec![data] }),
    }
}

/// Extract scope type from EzDataScope
/// Generic "failure" of None if can't extract scope
pub fn extract_ez_data_scope(scope: &EzDataScope) -> Option<DataScopeType> {
    DataScopeType::try_from(scope.static_info.as_ref()?.scope_type).ok()
}

/// Extract first scope from EzPayload
/// Generic "failure" of None if can't extract scope
pub fn extract_payload_scope(payload: &EzPayload) -> Option<DataScopeType> {
    extract_ez_data_scope(payload.payload_scope.as_ref()?.datagram_scopes.first()?)
}

/// Extract first message from EzPayload
/// Generic "failure" of None if can't extract scope
pub fn extract_payload_message(payload: &EzPayload) -> Option<Vec<u8>> {
    Some(payload.payload_data.as_ref()?.datagrams.first()?.clone())
}
