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

/* Tonic status are too large in current version (0.13)
 * Fixed in tonic v0.14.0 https://github.com/hyperium/tonic/issues/2253
 * https://github.com/hyperium/tonic/releases/tag/v0.14.0
 */
#![allow(clippy::result_large_err)]
use crypto_oracle_key_info::{AsymmetricKeyData, KeyData, KeyID, StoredKey};
use crypto_oracle_proto::oracle::{
    DeleteKeyRequest, DeleteKeyResponse, GenerateKeyRequest, GenerateKeyResponse,
    GetPublicKeyRequest, GetPublicKeyResponse, KeyIdentifier, KeySetType, RefreshKeyRequest,
    RefreshKeyResponse, SignRequest, SignResponse, VerifyRequest, VerifyResponse,
};
use crypto_oracle_sdk::OracleApi;
use crypto_oracle_status::{create_status, tink_err_status, Code};
use dashmap::DashMap;
use data_scope_proto::enforcer::v1::{DataScopeType, EzDataScope};
use data_scope_utils::{
    extract_ez_data_scope, extract_payload_message, extract_payload_scope, to_payload,
};
use status_proto::enforcer::v1::Status;
use std::{cmp::max, sync::Arc};
use tink_core::{
    keyset::{BinaryWriter, Handle, Manager, MemReaderWriter},
    TinkError,
};
use tink_signature::{ecdsa_p256_key_without_prefix_template, new_signer, new_verifier};
use tonic::{Request, Response};

/// Provides trusted API for cryptographic operations
#[derive(Debug, Default)]
pub struct CryptoOracle {
    stored_keys: Arc<DashMap<KeyID, StoredKey>>,
    scheduled_refreshes: Arc<DashMap<KeyID, tokio::task::JoinHandle<()>>>,
}

impl CryptoOracle {
    pub fn new() -> Self {
        tink_signature::init();
        Self {
            stored_keys: Arc::new(DashMap::new()),
            scheduled_refreshes: Arc::new(DashMap::new()),
        }
    }

    /// Set up refresh for [key_id] with [refresh_duration].
    /// Errors out if fails to mutex lock, or refresh already scheduled
    fn schedule_refresh(
        &self,
        key_id: KeyID,
        refresh_duration: std::time::Duration,
    ) -> Result<(), String> {
        if self.scheduled_refreshes.contains_key(&key_id) {
            // Note: JoinMap insert overrides previous values
            // For now, explicitly don't support overriding, as it's only
            // called from Gen currently, and can't be called on existing keys
            // TODO: Support refresh schedule override API call
            return Err("Key already has scheduled refreshes".to_string());
        };

        let keys = self.stored_keys.clone();
        let key_id_clone = key_id.clone();

        let handle = tokio::task::spawn(async move {
            let mut interval = tokio::time::interval(refresh_duration);
            // Interval has a tick immediately, so skip it.
            interval.tick().await;

            // Task/loop is cancelled by aborting the handle from the map
            loop {
                interval.tick().await;

                // Short term hold mutable entry to refresh, to prevent locking
                let mut entry = match keys.entry(key_id.clone()) {
                    dashmap::Entry::Occupied(entry) => entry,
                    // Should never happen, but might if called before insertion
                    dashmap::Entry::Vacant(_) => {
                        log::error!(
                            "Internal error: Refresh task found no key for ID {:?}",
                            key_id
                        );
                        return;
                    }
                };
                let stored_key = entry.get_mut();

                // Helper manages tracking failed refreshes
                if let Err(status) = refresh_key_helper(stored_key, true, false) {
                    log::error!(
                        "Internal error: Refresh task for ID {:?} failed to automatically refresh: {:?}",
                        key_id, status
                    );
                }
            }
        });
        self.scheduled_refreshes.insert(key_id_clone, handle);
        Ok(())
    }

    /// Tries to cancel scheduled refresh, returns bool on if it was scheduled
    fn cancel_refresh(&self, key_id: &KeyID) -> bool {
        let Some((_key, handle)) = self.scheduled_refreshes.remove(key_id) else { return false };
        handle.abort();
        true
    }

    /// Get a handle to a prior version private key handle
    /// Makes a mutable lock on the entry to use the manager, so requires any other lock released
    /// Requires the current (primary key) version, to reset afterwards
    fn get_previous_handle(
        &self,
        key_id: &KeyID,
        requested_key_version_id: u32,
        current_key_version_id: u32,
    ) -> Result<Handle, Status> {
        let mut entry = match self.stored_keys.entry(key_id.clone()) {
            dashmap::Entry::Occupied(entry) => entry,
            dashmap::Entry::Vacant(_) => {
                log::error!("Key ID no longer exists: {:?}", key_id);
                return Err(create_status(Code::NotFound, "Key ID no longer exists"));
            }
        };
        // Hold onto mutable entry lock while temporarily setting older primary key
        let key = entry.get_mut();
        // Temporarily set primary key to requested older version, to extract the handle
        key.manager
            .set_primary(requested_key_version_id)
            .map_err(|e| tink_err_status("Failed to use older key version", e))?;
        // Get updated key handle from manager for the requested version
        let old_signing_key =
            key.manager.handle().map_err(|e| tink_err_status("Failure to get handle", e))?;
        // Restore current primary key
        key.manager
            .set_primary(current_key_version_id)
            .map_err(|e| tink_err_status("Failure to restore primary key", e))?;
        // Explicitly release entry lock
        drop(entry);
        Ok(old_signing_key)
    }
}

type GenerateKeyResponseResult = Result<Response<GenerateKeyResponse>, tonic::Status>;
type DeleteKeyResponseResult = Result<Response<DeleteKeyResponse>, tonic::Status>;
type RefreshKeyResponseResult = Result<Response<RefreshKeyResponse>, tonic::Status>;
type GetPublicKeyResponseResult = Result<Response<GetPublicKeyResponse>, tonic::Status>;
type SignResposneResult = Result<Response<SignResponse>, tonic::Status>;
type VerifyResponseResult = Result<Response<VerifyResponse>, tonic::Status>;

#[tonic::async_trait]
impl OracleApi for CryptoOracle {
    /// Generate a symmetric key or asymmetric key pair
    /// TODO: Implement Symmetric keygen
    /// Currently only does ecdsa_p256 asymmetric keys
    /// Returns nonzero status if can't parse, key already exists
    async fn generate_key(
        &self,
        request: Request<GenerateKeyRequest>,
    ) -> GenerateKeyResponseResult {
        let request = request.into_inner();

        let key_set_type = request.key_set_type();
        let (key_id, output_scope) = parse_key_id(request.key_id)?;
        if self.stored_keys.contains_key(&key_id) {
            return create_gen_response(Code::AlreadyExists, "Key ID already exists");
        }

        match key_set_type {
            KeySetType::KeySetUnspecified => {
                create_gen_response(Code::InvalidArgument, "Unspecified key set type")
            }
            KeySetType::Symmetric => {
                create_gen_response(Code::Unimplemented, "Symmetric keygen not implemented yet")
            }
            KeySetType::Asymmetric => {
                let (key_data, manager) = match create_asymmetric_key() {
                    Ok(result) => result,
                    Err(e) => return create_gen_response_tink(e),
                };
                let public_key_option = if request.return_public_key {
                    match get_primary_key_raw(&key_data.public_key) {
                        Ok(public_key) => Some(public_key),
                        Err(e) => return create_gen_response_tink(e),
                    }
                } else {
                    None
                };
                let dashmap::Entry::Vacant(entry) = self.stored_keys.entry(key_id.clone()) else {
                    return create_gen_response(Code::AlreadyExists, "Key ID already exists");
                };

                if request.refresh_interval_seconds > 0 {
                    let refresh_duration =
                        std::time::Duration::from_secs(request.refresh_interval_seconds);
                    if let Err(e) = self.schedule_refresh(key_id, refresh_duration) {
                        return create_gen_response(
                            Code::Internal,
                            &format!("Could not schedule refresh: {}", e),
                        );
                    };
                };

                entry.insert(StoredKey {
                    key_data: KeyData::Asymmetric(key_data),
                    manager: manager.into(),
                    output_scope,
                    max_consecutive_failed_refreshes: request.max_consecutive_failed_refreshes,
                    num_consecutive_failed_refreshes: 0,
                });
                create_gen_response_ok(public_key_option)
            }
        }
    }

    /// Deletes a key
    /// Removes the entire keyset from storage. Errors if key doesn't exist
    /// Cancels any scheduled refreshes, errors if failed to lock
    async fn delete_key(&self, request: Request<DeleteKeyRequest>) -> DeleteKeyResponseResult {
        let request = request.into_inner();

        let (key_id, _) = parse_key_id(request.key_id)?;
        match self.stored_keys.remove(&key_id) {
            None => create_delete_response(Code::NotFound, "Key ID does not exist"),
            Some(_) => {
                // Cancel any automatic refresh jobs, if they exist
                self.cancel_refresh(&key_id);
                create_delete_response(Code::Ok, "Key deleted")
            }
        }
    }

    /// Refreshes a held key, generating a new key (pair) version
    /// Optionally deactivates the previous key
    /// Tracks consecutive failures of the refresh itself
    async fn refresh_key(&self, request: Request<RefreshKeyRequest>) -> RefreshKeyResponseResult {
        let request = request.into_inner();
        let (key_id, _) = parse_key_id(request.key_id)?;
        let dashmap::Entry::Occupied(mut entry) = self.stored_keys.entry(key_id) else {
            return create_refresh_response(Code::NotFound, "Key ID does not exist");
        };
        let stored_key = entry.get_mut();
        match refresh_key_helper(stored_key, request.deprecate_previous, request.return_public_key)
        {
            Ok(public_key) => create_refresh_response_ok(public_key),
            Err(status) => {
                Ok(Response::new(RefreshKeyResponse { status: Some(status), public_key: None }))
            }
        }
    }

    /// Returns the public part of an asymmetric key
    /// Returns a serialization of a handle containing only the primary key
    /// Returns nonzero status if can't parse, key doesn't exist, key is symmetric
    async fn get_public_key(
        &self,
        request: Request<GetPublicKeyRequest>,
    ) -> GetPublicKeyResponseResult {
        let request = request.into_inner();

        let (key_id, _) = parse_key_id(request.key_id)?;
        let Some(data) = self.stored_keys.get(&key_id) else {
            return create_get_public_err(Code::NotFound, "Key ID does not exist");
        };
        let KeyData::Asymmetric(key_data) = &data.key_data else {
            return create_get_public_err(Code::FailedPrecondition, "Key is not asymmetric");
        };

        let handle = match get_primary_key_handle(&key_data.public_key) {
            Ok(handle) => handle,
            Err(e) => return create_get_public_tink("Failed to get primary public key", e),
        };
        let tink_key_id = handle.keyset_info().primary_key_id;
        let mut buffer: Vec<u8> = Vec::new();
        let mut writer = BinaryWriter::new(&mut buffer);
        match handle.write_with_no_secrets(&mut writer) {
            Err(e) => create_get_public_tink("Failed to write public key", e),
            Ok(()) => create_get_public_ok(buffer, tink_key_id),
        }
    }

    // Sign a message with the requested private key
    // TODO: Implement Symmetric key signing
    // If no key scope, uses message scope. Otherwise uses the more restrictive
    // Does not allow for scope relaxation (key scope weaker than message scope)
    // Currently assumes that the requested message payload has only one message
    async fn sign(&self, request: Request<SignRequest>) -> SignResposneResult {
        let request = request.into_inner();

        let (key_id, _) = parse_key_id(request.key_id)?;
        let Some(payload) = request.message_data else {
            return Err(tonic::Status::invalid_argument("Could not parse message"));
        };
        let Some(message_data) = extract_payload_message(&payload) else {
            return Err(tonic::Status::invalid_argument("Could not parse message data"));
        };
        let Some(message_scope) = extract_payload_scope(&payload) else {
            return Err(tonic::Status::invalid_argument("Could not parse message scope"));
        };

        let Some(stored_key) = self.stored_keys.get(&key_id) else {
            return create_sign_response_err(Code::NotFound, "Key ID does not exist");
        };

        if let Err(status) = check_refresh_failures(&stored_key) {
            return Ok(Response::new(SignResponse { status: Some(status), ..Default::default() }));
        }

        let scope = match &stored_key.value().output_scope {
            None => message_scope,
            Some(key_scope) => {
                let Some(key_scope) = extract_ez_data_scope(key_scope) else {
                    return create_sign_response_err(Code::Internal, "Could not parse key scope");
                };
                max(message_scope, key_scope)
            }
        };

        let mut verify_key_option = None;
        let signing_key = match &stored_key.value().key_data {
            KeyData::Symmetric(_) => {
                return create_sign_response_err(
                    Code::FailedPrecondition,
                    "Symmetric signing not supported",
                )
            }
            KeyData::Asymmetric(key_data) => {
                let Some(private_key) = &key_data.private_key else {
                    return create_sign_response_err(
                        Code::FailedPrecondition,
                        "Private key not available",
                    );
                };
                if request.return_verification_key {
                    verify_key_option = match get_primary_key_raw(&key_data.public_key) {
                        Ok(public_key) => Some(public_key),
                        Err(e) => return create_sign_response_tink("Failure to get public key", e),
                    }
                }
                private_key
            }
        };

        // Sign with latest key if no earlier version requested
        let Some(requested_key_version_id) = request.public_key_version_id else {
            return sign_with_key(signing_key, message_data, verify_key_option, scope);
        };
        // Sign with latest key if requested ID is the same as latest
        let current_key_version_id = signing_key.keyset_info().primary_key_id;
        if requested_key_version_id == current_key_version_id {
            return sign_with_key(signing_key, message_data, verify_key_option, scope);
        }

        // Release lock on key, to grab a mutable entry for the previous version handle instead
        drop(stored_key);
        let old_signing_key = match self.get_previous_handle(
            &key_id,
            requested_key_version_id,
            current_key_version_id,
        ) {
            Ok(handle) => handle,
            Err(status) => {
                return Ok(Response::new(SignResponse {
                    status: Some(status),
                    ..Default::default()
                }))
            }
        };

        // Maybe update corresponding returned public key, if requested
        if request.return_verification_key {
            let new_public = match old_signing_key.public() {
                Ok(public) => public,
                Err(e) => return create_sign_response_tink("Failure to get public key", e),
            };
            verify_key_option = match get_primary_key_raw(&new_public) {
                Ok(public_key) => Some(public_key),
                Err(e) => return create_sign_response_tink("Failure to get public key", e),
            }
        }

        sign_with_key(&old_signing_key, message_data, verify_key_option, scope)
    }

    /// Verify that the signature matches the message using the key
    /// Returns verification result (t/f) as public
    async fn verify(&self, request: Request<VerifyRequest>) -> VerifyResponseResult {
        let request = request.into_inner();

        let (key_id, _) = parse_key_id(request.key_id)?;
        let Some(message_payload) = request.message_data else {
            return Err(tonic::Status::invalid_argument("Could not parse message"));
        };
        let Some(message) = extract_payload_message(&message_payload) else {
            return Err(tonic::Status::invalid_argument("Could not parse message data"));
        };
        let Some(signature_payload) = request.signature else {
            return Err(tonic::Status::invalid_argument("Could not parse signature"));
        };
        let Some(signature) = extract_payload_message(&signature_payload) else {
            return Err(tonic::Status::invalid_argument("Could not parse signature data"));
        };

        let Some(stored_key) = self.stored_keys.get(&key_id) else {
            return create_verify_response(Code::NotFound, "Key ID does not exist", false);
        };
        if let Err(status) = check_refresh_failures(&stored_key) {
            return Ok(Response::new(VerifyResponse {
                status: Some(status),
                is_valid_signature: false,
            }));
        }

        let verify_key = match &stored_key.value().key_data {
            KeyData::Symmetric(_) => {
                return create_verify_response(
                    Code::FailedPrecondition,
                    "Symmetric verification not supported",
                    false,
                )
            }
            KeyData::Asymmetric(key_data) => &key_data.public_key,
        };

        let verifier = match new_verifier(verify_key) {
            Ok(verifier) => verifier,
            Err(e) => return create_verify_response_tink("Failure to create verifier", e),
        };
        let is_valid_signature = verifier.verify(&signature, &message).is_ok();

        create_verify_response(Code::Ok, "Ok", is_valid_signature)
    }
}

/// Parse a KeyIdentifier proto into the ID and data scope, if possible
fn parse_key_id(
    key_id: Option<KeyIdentifier>,
) -> Result<(KeyID, Option<EzDataScope>), tonic::Status> {
    match key_id {
        Some(key_id) => {
            Ok((KeyID { domain: key_id.domain, key_name: key_id.key_name }, key_id.output_scope))
        }
        None => Err(tonic::Status::invalid_argument("Could not parse Key ID")),
    }
}

/// Try to make an asymmetric stored key, or return the tink error as a status
fn create_asymmetric_key() -> Result<(AsymmetricKeyData, Manager), TinkError> {
    let mut manager = Manager::new();
    manager.add(&ecdsa_p256_key_without_prefix_template(), /* as_primary */ true)?;
    let private_key = manager.handle()?;
    let public_key = private_key.public()?;

    Ok((AsymmetricKeyData { public_key, private_key: Some(private_key) }, manager))
}

/// Separate helper, so it can be called by API or scheduled job
/// Optionally deactiavtes the previous key
/// Optionally returns the public key (optional, since faster to not)
/// Tracks consecutive failures of the refresh itself
fn refresh_key_helper(
    stored_key: &mut StoredKey,
    deprecate_previous: bool,
    return_public: bool,
) -> Result<Option<Vec<u8>>, Status> {
    match stored_key.key_data {
        KeyData::Symmetric(_) => {
            Err(create_status(Code::Unimplemented, "Symmetric refresh not implemented yet"))
        }
        KeyData::Asymmetric(ref mut key_data) => {
            if key_data.private_key.is_none() {
                return Err(create_status(Code::FailedPrecondition, "Private key not available"));
            };
            refresh_asymmetric_key(key_data, &mut stored_key.manager, deprecate_previous).map_err(
                |e| {
                    stored_key.num_consecutive_failed_refreshes += 1;
                    tink_err_status("Failure to refresh key", e)
                },
            )?;
            let public_key_option = if return_public {
                Some(get_primary_key_raw(&key_data.public_key).map_err(|e| {
                    stored_key.num_consecutive_failed_refreshes += 1;
                    tink_err_status("Failure to get public key", e)
                })?)
            } else {
                None
            };

            // Successfully refresh
            stored_key.num_consecutive_failed_refreshes = 0;
            Ok(public_key_option)
        }
    }
}

/// Refresh the manager's keys, updating the key_data with new handles
/// Marks previous id as deprecated if requested
fn refresh_asymmetric_key(
    key_data: &mut AsymmetricKeyData,
    manager: &mut Manager,
    deprecate_previous: bool,
) -> Result<(), TinkError> {
    let previous_key_id = key_data.public_key.keyset_info().primary_key_id;
    manager.rotate(&ecdsa_p256_key_without_prefix_template())?;
    if deprecate_previous {
        manager.disable(previous_key_id)?
    };
    let private_key = manager.handle()?;
    let public_key = private_key.public()?;
    // Update key_data
    key_data.public_key = public_key;
    key_data.private_key = Some(private_key);
    Ok(())
}

/// Gets just the primary key from a handle
/// Must be called on a key with no secrets (public)
/// Tink handle/manager have no "get primary" support
fn get_primary_key(handle: &Handle) -> Result<tink_proto::keyset::Key, TinkError> {
    let mut mem_writer = MemReaderWriter::default();
    handle.write_with_no_secrets(&mut mem_writer)?;
    let Some(keyset) = mem_writer.keyset else {
        return Err(TinkError::new("No keyset in handle"));
    };
    let primary_key_id = handle.keyset_info().primary_key_id;
    // Almost always the first one, so should be fast
    keyset
        .key
        .into_iter()
        .find(|key| key.key_id == primary_key_id)
        .ok_or(TinkError::new("Primary key not found"))
}

/// Provide a handle with just the primary public key
/// Must be called on a key with no secrets (public)
/// This is so that get_public_key can return just the primary, to match usage
pub fn get_primary_key_handle(handle: &Handle) -> Result<Handle, TinkError> {
    let primary_key = get_primary_key(handle)?;
    let primary_public_keyset =
        tink_proto::Keyset { primary_key_id: primary_key.key_id, key: vec![primary_key] };
    Handle::new_with_no_secrets(primary_public_keyset)
}

/// Provide the raw key data of the primary key, with no tink metadata
/// Must be called on a key with no secrets (public)
pub fn get_primary_key_raw(handle: &Handle) -> Result<Vec<u8>, TinkError> {
    let primary_key = get_primary_key(handle)?;
    let Some(key_data) = &primary_key.key_data else {
        return Err(TinkError::new("No key data in primary key"));
    };
    Ok(key_data.value.clone())
}

/// If a key has max consecutive refreshes set, check if it has not exceeded it
/// Returns OK is no max set, or not exceeded. Else returns status as error
fn check_refresh_failures(stored_key: &StoredKey) -> Result<(), Status> {
    let Some(max_consecutive_failed_refreshes) = stored_key.max_consecutive_failed_refreshes else {
        return Ok(());
    };
    if stored_key.num_consecutive_failed_refreshes > max_consecutive_failed_refreshes {
        return Err(create_status(Code::FailedPrecondition,
            "Key has too many failed refreshes. Key use not allowed until it is successfully refreshed"));
    }
    Ok(())
}

/// Helper to sign message with key, and include extra information
fn sign_with_key(
    signing_key: &Handle,
    message_data: Vec<u8>,
    verify_key_option: Option<Vec<u8>>,
    scope: DataScopeType,
) -> SignResposneResult {
    let signer = match new_signer(signing_key) {
        Ok(signer) => signer,
        Err(e) => return create_sign_response_tink("Failure to create signer", e),
    };
    let signature = match signer.sign(&message_data) {
        Ok(signature) => signature,
        Err(e) => return create_sign_response_tink("Failure to sign message", e),
    };
    create_sign_response_ok(signature, scope, verify_key_option)
}

fn create_gen_response(code: Code, message: &str) -> GenerateKeyResponseResult {
    Ok(Response::new(GenerateKeyResponse {
        status: Some(create_status(code, message)),
        public_key: None,
    }))
}
fn create_gen_response_ok(public_key: Option<Vec<u8>>) -> GenerateKeyResponseResult {
    Ok(Response::new(GenerateKeyResponse {
        status: Some(create_status(Code::Ok, "Ok")),
        public_key: public_key.map(|public_key| to_payload(public_key, DataScopeType::Public)),
    }))
}
fn create_gen_response_tink(err: TinkError) -> GenerateKeyResponseResult {
    Ok(Response::new(GenerateKeyResponse {
        status: Some(tink_err_status("Failed to make key: ", err)),
        public_key: None,
    }))
}

fn create_delete_response(code: Code, message: &str) -> DeleteKeyResponseResult {
    Ok(Response::new(DeleteKeyResponse { status: Some(create_status(code, message)) }))
}

fn create_refresh_response(code: Code, message: &str) -> RefreshKeyResponseResult {
    Ok(Response::new(RefreshKeyResponse {
        status: Some(create_status(code, message)),
        public_key: None,
    }))
}
fn create_refresh_response_ok(public_key: Option<Vec<u8>>) -> RefreshKeyResponseResult {
    Ok(Response::new(RefreshKeyResponse {
        status: Some(create_status(Code::Ok, "Ok")),
        public_key: public_key.map(|public_key| to_payload(public_key, DataScopeType::Public)),
    }))
}

fn create_get_public_ok(public_key: Vec<u8>, version_id: u32) -> GetPublicKeyResponseResult {
    Ok(Response::new(GetPublicKeyResponse {
        status: Some(create_status(Code::Ok, "Ok")),
        public_key: Some(to_payload(public_key, DataScopeType::Public)),
        public_key_version_id: version_id,
    }))
}
fn create_get_public_err(code: Code, message: &str) -> GetPublicKeyResponseResult {
    Ok(Response::new(GetPublicKeyResponse {
        status: Some(create_status(code, message)),
        public_key: None,
        public_key_version_id: 0,
    }))
}
fn create_get_public_tink(message: &str, err: TinkError) -> GetPublicKeyResponseResult {
    Ok(Response::new(GetPublicKeyResponse {
        status: Some(tink_err_status(message, err)),
        public_key: None,
        public_key_version_id: 0,
    }))
}

fn create_sign_response_ok(
    signature: Vec<u8>,
    scope: DataScopeType,
    verification_key: Option<Vec<u8>>,
) -> SignResposneResult {
    Ok(Response::new(SignResponse {
        status: Some(create_status(Code::Ok, "Ok")),
        signature: Some(to_payload(signature, scope)),
        verification_key: verification_key.map(|key| to_payload(key, DataScopeType::Public)),
    }))
}
fn create_sign_response_err(code: Code, message: &str) -> SignResposneResult {
    Ok(Response::new(SignResponse {
        status: Some(create_status(code, message)),
        ..Default::default()
    }))
}
fn create_sign_response_tink(message: &str, err: TinkError) -> SignResposneResult {
    Ok(Response::new(SignResponse {
        status: Some(tink_err_status(message, err)),
        ..Default::default()
    }))
}

fn create_verify_response(
    code: Code,
    message: &str,
    is_valid_signature: bool,
) -> VerifyResponseResult {
    Ok(Response::new(VerifyResponse {
        status: Some(create_status(code, message)),
        is_valid_signature,
    }))
}
fn create_verify_response_tink(message: &str, err: TinkError) -> VerifyResponseResult {
    Ok(Response::new(VerifyResponse {
        status: Some(tink_err_status(message, err)),
        is_valid_signature: false,
    }))
}
