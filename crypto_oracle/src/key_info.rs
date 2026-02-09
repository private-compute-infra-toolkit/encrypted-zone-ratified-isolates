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

/// Structures and types used by the Crypto Oracle
use data_scope_proto::enforcer::v1::EzDataScope;
use debug_ignore::DebugIgnore;
use tink_core::keyset::{Handle, Manager};

/// Single symmetric key. Key stored as Tink keyset Handle
#[derive(Debug)]
pub struct SymmetricKeyData {
    pub key: Handle,
}

/// Public asymmetric key, and optionally the corresponding private key
/// Key(s) stored as Tink keyset Handle
#[derive(Debug)]
pub struct AsymmetricKeyData {
    // There shouldn't be a case for storing just private key without its public counterpart
    pub public_key: Handle,
    // Optionally the private key corresponding to the public key
    pub private_key: Option<Handle>,
}

/// Contains either a single symmetric key, or an asymmetric key pair
#[derive(Debug)]
pub enum KeyData {
    Symmetric(SymmetricKeyData),
    Asymmetric(AsymmetricKeyData),
}

/// Stored key data and optional scope applied on use
/// Has both handle(s) for easy usage, and manager to support refreshing
#[derive(Debug)]
pub struct StoredKey {
    pub key_data: KeyData,
    /// Manager, for refreshing keys
    /// Ignore debug as it's not supported for managers
    ///   and Tink has non-private debug of Handles inside key_data instead
    pub manager: DebugIgnore<Manager>,
    /// Optional, Output scope of applying key.
    /// If not provided, defaults to input's scope
    /// TODO: Determine if this should be EzDataScope or DataScopeType
    pub output_scope: Option<EzDataScope>,
    /// If requested, the maximum number of consecutive failed refreshes allowed
    /// before a key is stale
    pub max_consecutive_failed_refreshes: Option<u32>,
    /// How many times refresh has failed on the same key
    pub num_consecutive_failed_refreshes: u32,
}

/// Based on KeyIdentifier proto, except scope moved to stored key
#[derive(Debug, Eq, PartialEq, Hash, Clone)]
pub struct KeyID {
    pub domain: String,
    pub key_name: String,
}
