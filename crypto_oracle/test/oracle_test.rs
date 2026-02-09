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

#[cfg(test)]
mod tests {
    use crypto_oracle::{get_primary_key_raw, CryptoOracle};
    use crypto_oracle_proto::oracle::{
        DeleteKeyRequest, GenerateKeyRequest, GetPublicKeyRequest, KeyIdentifier, KeySetType,
        RefreshKeyRequest, SignRequest, VerifyRequest,
    };
    use crypto_oracle_sdk::OracleApi;
    use crypto_oracle_status::Code;
    use data_scope_proto::enforcer::v1::DataScopeType;
    use data_scope_utils::{
        extract_payload_message, extract_payload_scope, to_datascope, to_payload,
    };
    use tink_core::keyset::{BinaryReader, Handle};
    use tink_signature::new_verifier;
    use tonic::Request;

    // Test helper functions
    fn make_key_id(domain: &str, key_name: &str) -> Option<KeyIdentifier> {
        Some(KeyIdentifier {
            domain: domain.to_string(),
            key_name: key_name.to_string(),
            output_scope: None,
        })
    }

    // Asymmetric key with no scope, and default parameters
    // No return public key, keys never stale, no automatic refresh, no signer
    fn make_simple_gen_request(domain: &str, key_name: &str) -> Request<GenerateKeyRequest> {
        Request::new(GenerateKeyRequest {
            key_id: Some(KeyIdentifier {
                domain: domain.to_string(),
                key_name: key_name.to_string(),
                output_scope: None,
            }),
            key_set_type: KeySetType::Asymmetric.into(),
            ..Default::default()
        })
    }

    fn make_gen_request(
        domain: &str,
        key_name: &str,
        output_scope_type: Option<DataScopeType>,
        return_public_key: bool,
        max_consecutive_failed_refreshes: Option<u32>,
        refresh_interval_seconds: u64,
    ) -> Request<GenerateKeyRequest> {
        Request::new(GenerateKeyRequest {
            key_id: Some(KeyIdentifier {
                domain: domain.to_string(),
                key_name: key_name.to_string(),
                output_scope: output_scope_type.map(to_datascope),
            }),
            key_set_type: KeySetType::Asymmetric.into(),
            return_public_key,
            max_consecutive_failed_refreshes,
            refresh_interval_seconds,
        })
    }

    fn make_del_request(domain: &str, key_name: &str) -> Request<DeleteKeyRequest> {
        Request::new(DeleteKeyRequest { key_id: make_key_id(domain, key_name) })
    }

    fn make_refresh_request(
        domain: &str,
        key_name: &str,
        deprecate_previous: bool,
        return_public_key: bool,
    ) -> Request<RefreshKeyRequest> {
        Request::new(RefreshKeyRequest {
            key_id: make_key_id(domain, key_name),
            deprecate_previous,
            return_public_key,
        })
    }

    fn make_get_public_request(domain: &str, key_name: &str) -> Request<GetPublicKeyRequest> {
        Request::new(GetPublicKeyRequest { key_id: make_key_id(domain, key_name) })
    }

    fn make_sign_request(
        domain: &str,
        key_name: &str,
        message_data: Vec<u8>,
        scope: DataScopeType,
        return_verification_key: bool,
        public_key_version_id: Option<u32>,
    ) -> Request<SignRequest> {
        Request::new(SignRequest {
            key_id: make_key_id(domain, key_name),
            message_data: Some(to_payload(message_data, scope)),
            return_verification_key,
            public_key_version_id,
        })
    }

    fn make_verify_request(
        domain: &str,
        key_name: &str,
        message_data: Vec<u8>,
        signature: Vec<u8>,
    ) -> Request<VerifyRequest> {
        Request::new(VerifyRequest {
            key_id: make_key_id(domain, key_name),
            message_data: Some(to_payload(message_data, DataScopeType::Public)),
            signature: Some(to_payload(signature, DataScopeType::Public)),
        })
    }

    // Ensure creation works
    #[tokio::test]
    async fn setup_test() {
        let _oracle = CryptoOracle::new();
    }

    #[tokio::test]
    async fn single_key_test() {
        let oracle = CryptoOracle::new();

        // Generate a new key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);
        // Returns empty public key
        assert!(gen_response.public_key.is_none());

        // Delete the key
        let del_request = make_del_request("d", "key");
        let del_response = oracle.delete_key(del_request).await.unwrap().into_inner();
        assert_eq!(del_response.status.unwrap().code, Code::Ok as i32);

        // Fail to delete again, showing key has been deleted
        let del_request = make_del_request("d", "key");
        let del_response = oracle.delete_key(del_request).await.unwrap().into_inner();
        assert_eq!(del_response.status.unwrap().code, Code::NotFound as i32);

        // Generate into the deleted area (fine). Also different scope. Also return public
        let gen_request =
            make_gen_request("d", "key", Some(DataScopeType::UserPrivate), true, None, 0);
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);
        // Returns non-empty public key
        assert_ne!(extract_payload_message(&gen_response.public_key.unwrap()).unwrap().len(), 0);
    }

    // Test various simple error cases
    #[tokio::test]
    async fn simple_key_error_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        // Set up initial key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        // Fail to make the same key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::AlreadyExists as i32);

        // Fail on generate missing ID
        let gen_request = Request::new(GenerateKeyRequest { key_id: None, ..Default::default() });
        let gen_response = oracle.generate_key(gen_request).await;
        assert_eq!(gen_response.err().unwrap().code(), tonic::Code::InvalidArgument);

        // Fail on delete missing ID
        let del_request = Request::new(DeleteKeyRequest { key_id: None });
        let del_response = oracle.delete_key(del_request).await;
        assert_eq!(del_response.err().unwrap().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn refresh_key_changed_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        // Set up initial key, return public
        let gen_request = make_gen_request("d", "key", None, true, None, 0);
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);
        let first_raw_key = extract_payload_message(&gen_response.public_key.unwrap()).unwrap();
        assert_ne!(first_raw_key.len(), 0);
        // Get first public key
        let get_request = make_get_public_request("d", "key");
        let get_response = oracle.get_public_key(get_request).await.unwrap().into_inner();
        assert_eq!(get_response.status.unwrap().code, Code::Ok as i32);
        let first_key = extract_payload_message(&get_response.public_key.unwrap()).unwrap();
        // Refresh, return public
        let refresh_request = make_refresh_request("d", "key", false, true);
        let refresh_response = oracle.refresh_key(refresh_request).await.unwrap().into_inner();
        assert_eq!(refresh_response.status.unwrap().code, Code::Ok as i32);
        let second_raw_key =
            extract_payload_message(&refresh_response.public_key.unwrap()).unwrap();
        // Raw key has changed
        assert_ne!(second_raw_key.len(), 0);
        assert_ne!(first_raw_key, second_raw_key);
        // Get second public key
        let get_request = make_get_public_request("d", "key");
        let get_response = oracle.get_public_key(get_request).await.unwrap().into_inner();
        assert_eq!(get_response.status.unwrap().code, Code::Ok as i32);
        let second_key = extract_payload_message(&get_response.public_key.unwrap()).unwrap();
        // Key has changed
        assert_ne!(first_key, second_key);
        // Second key only returns one (get public)
        let mut reader = BinaryReader::new(&second_key[..]);
        let second_key_info = Handle::read_with_no_secrets(&mut reader).unwrap().keyset_info();
        assert_eq!(second_key_info.key_info.len(), 1);
        // Refresh with no return public is empty
        let refresh_request = make_refresh_request("d", "key", false, false);
        let refresh_response = oracle.refresh_key(refresh_request).await.unwrap().into_inner();
        assert_eq!(refresh_response.status.unwrap().code, Code::Ok as i32);
        assert!(refresh_response.public_key.is_none());
    }

    #[tokio::test]
    async fn refresh_key_error_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        // Set up initial key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        // Fail to refresh missing key
        let refresh_request = make_refresh_request("d", "key2", false, false);
        let refresh_response = oracle.refresh_key(refresh_request).await.unwrap().into_inner();
        assert_eq!(refresh_response.status.unwrap().code, Code::NotFound as i32);

        // Fail to refresh no key
        let refresh_request =
            Request::new(RefreshKeyRequest { key_id: None, ..Default::default() });
        let refresh_response = oracle.refresh_key(refresh_request).await;
        assert_eq!(refresh_response.err().unwrap().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn get_public_key_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        // Set up initial key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        let get_request = make_get_public_request("d", "key");
        let get_response = oracle.get_public_key(get_request).await.unwrap().into_inner();
        assert_eq!(get_response.status.unwrap().code, Code::Ok as i32);
        let key = get_response.public_key.unwrap();
        // Key is public
        let scope = extract_payload_scope(&key).unwrap();
        assert_eq!(scope, DataScopeType::Public);
        // Nontrivial id
        assert_ne!(get_response.public_key_version_id, 0);

        let key_data = extract_payload_message(&key).unwrap();
        let mut reader = BinaryReader::new(&key_data[..]);
        let read_handle = Handle::read_with_no_secrets(&mut reader).unwrap();
        let info = read_handle.keyset_info();
        // Assert one non-trivial key
        assert_ne!(info.primary_key_id, 0);
        assert_eq!(info.key_info.len(), 1);
        // Assert that the type url has "public key" in it
        assert!(info.key_info[0].clone().type_url.to_lowercase().contains("publickey"));
    }

    #[tokio::test]
    async fn get_public_key_error_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        // Set up initial key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        // Fail missing ID
        let get_request = Request::new(GetPublicKeyRequest { key_id: None });
        let get_response = oracle.get_public_key(get_request).await;
        assert_eq!(get_response.err().unwrap().code(), tonic::Code::InvalidArgument);

        // Fail on ID doesn't exist
        let get_request = make_get_public_request("d", "key2");
        let get_response = oracle.get_public_key(get_request).await.unwrap().into_inner();
        assert_eq!(get_response.status.unwrap().code, Code::NotFound as i32);
    }

    #[tokio::test]
    async fn scheduled_refresh_test() {
        let oracle: CryptoOracle = CryptoOracle::new();

        // Set up initial key, with 1s refresh timer
        let gen_request = make_gen_request("d", "key", None, false, None, 1);
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        // Get original public key
        let get_request = make_get_public_request("d", "key");
        let get_response = oracle.get_public_key(get_request).await.unwrap().into_inner();
        assert_eq!(get_response.status.unwrap().code, Code::Ok as i32);
        let first_key = extract_payload_message(&get_response.public_key.unwrap()).unwrap();

        // Wait long enough to ensure refresh happened
        tokio::time::sleep(tokio::time::Duration::from_secs_f32(1.2)).await;

        // Get refreshed public key.
        // Also check that the key can be used while scheduled job is running
        let get_request = make_get_public_request("d", "key");
        let get_response = oracle.get_public_key(get_request).await.unwrap().into_inner();
        assert_eq!(get_response.status.unwrap().code, Code::Ok as i32);
        let second_key = extract_payload_message(&get_response.public_key.unwrap()).unwrap();
        // Key has changed by automatic refresh
        assert_ne!(first_key, second_key);
    }

    #[tokio::test]
    async fn signature_noscope_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        // Set up initial key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        let message = vec![2, 7, 1, 8, 2, 8];
        let scope = DataScopeType::UserPrivate;
        let sign_request = make_sign_request("d", "key", message.clone(), scope, false, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        assert_eq!(sign_response.status.unwrap().code, Code::Ok as i32);
        let signature = sign_response.signature.unwrap();
        // Scope same as message scope
        assert_eq!(extract_payload_scope(&signature), Some(scope));
        // Signature is not empty
        let signature_data = extract_payload_message(&signature).unwrap();
        assert_ne!(signature_data.len(), 0);

        // Verify
        let verify_request = make_verify_request("d", "key", message, signature_data);
        let verify_response = oracle.verify(verify_request).await.unwrap().into_inner();
        assert_eq!(verify_response.status.unwrap().code, Code::Ok as i32);
        // Assert verify passed
        assert!(verify_response.is_valid_signature);
    }

    #[tokio::test]
    async fn signature_withscope_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        let key_scope = DataScopeType::DomainOwned;
        // Set up initial key with scope
        let gen_request = make_gen_request("d", "key", Some(key_scope), false, None, 0);
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        // Message less restrictive than key, so restrict signature to key scope
        let message = vec![3, 1, 4, 1, 5, 9];
        let message_scope = DataScopeType::Public;
        let sign_request =
            make_sign_request("d", "key", message.clone(), message_scope, false, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        assert_eq!(sign_response.status.unwrap().code, Code::Ok as i32);
        let signature = sign_response.signature.unwrap();
        // Scope same as key scope
        assert_eq!(extract_payload_scope(&signature), Some(key_scope));
        // Signature is not empty
        let signature_data = extract_payload_message(&signature).unwrap();
        assert_ne!(signature_data.len(), 0);

        // Message more restrictive than key, keeps message scope
        let message_scope = DataScopeType::UserPrivate;
        let sign_request =
            make_sign_request("d", "key", message.clone(), message_scope, false, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        assert_eq!(sign_response.status.unwrap().code, Code::Ok as i32);
        let signature = sign_response.signature.unwrap();
        // Scope same as key scope
        assert_eq!(extract_payload_scope(&signature), Some(message_scope));
        // Signature is not empty
        let signature_data = extract_payload_message(&signature).unwrap();
        assert_ne!(signature_data.len(), 0);

        // Verify
        let verify_request = make_verify_request("d", "key", message, signature_data);
        let verify_response = oracle.verify(verify_request).await.unwrap().into_inner();
        assert_eq!(verify_response.status.unwrap().code, Code::Ok as i32);
        // Assert verify passed
        assert!(verify_response.is_valid_signature);
    }

    #[tokio::test]
    async fn sign_key_return_test() {
        let oracle = CryptoOracle::new();
        // Set up initial key, saving the raw public key
        let gen_request = make_gen_request("d", "key", None, true, None, 0);
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);
        let public_key = extract_payload_message(&gen_response.public_key.unwrap()).unwrap();
        assert_ne!(public_key.len(), 0);

        let message = vec![0, 6, 9, 3, 1, 4];
        let scope = DataScopeType::UserPrivate;

        // Sign with no verification key requested
        let sign_request = make_sign_request("d", "key", message.clone(), scope, false, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        assert_eq!(sign_response.status.unwrap().code, Code::Ok as i32);
        assert!(sign_response.signature.is_some());
        assert!(sign_response.verification_key.is_none());

        // Sign with verification key requested
        let sign_request = make_sign_request("d", "key", message.clone(), scope, true, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        assert_eq!(sign_response.status.unwrap().code, Code::Ok as i32);
        assert!(sign_response.signature.is_some());
        // Returned key, matches one from gen
        assert!(sign_response.verification_key.is_some());
        let verification_key =
            extract_payload_message(&sign_response.verification_key.unwrap()).unwrap();
        assert!(!verification_key.is_empty());
        assert_eq!(public_key, verification_key);
    }

    #[tokio::test]
    async fn sign_error_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        let key_scope = DataScopeType::DomainOwned;
        // Set up initial key
        let gen_request = make_gen_request("d", "key", Some(key_scope), false, None, 0);
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        let message = vec![1, 4, 1, 4, 2, 1];
        let message_scope = DataScopeType::UserPrivate;

        // Fail to sign with missing key
        let sign_request =
            make_sign_request("d", "key2", message.clone(), message_scope, false, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        assert_eq!(sign_response.status.unwrap().code, Code::NotFound as i32);

        // Fail to sign no key
        let sign_request = Request::new(SignRequest {
            key_id: None,
            message_data: Some(to_payload(message, message_scope)),
            ..Default::default()
        });
        let sign_response = oracle.sign(sign_request).await;
        assert_eq!(sign_response.err().unwrap().code(), tonic::Code::InvalidArgument);

        // Fail to sign no message
        let sign_request = Request::new(SignRequest {
            key_id: Some(KeyIdentifier {
                domain: "d".to_string(),
                key_name: "key".to_string(),
                output_scope: None,
            }),
            message_data: None,
            ..Default::default()
        });
        let sign_response = oracle.sign(sign_request).await;
        assert_eq!(sign_response.err().unwrap().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn signature_versioned_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        // Set up initial key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        // Get key's first version
        let get_request = make_get_public_request("d", "key");
        let get_response = oracle.get_public_key(get_request).await.unwrap().into_inner();
        assert_eq!(get_response.status.unwrap().code, Code::Ok as i32);
        let first_version_id = get_response.public_key_version_id;
        assert_ne!(first_version_id, 0);
        // Make verifier with first version
        let first_public_key_bytes =
            extract_payload_message(&get_response.public_key.unwrap()).unwrap();
        let mut reader = BinaryReader::new(&first_public_key_bytes[..]);
        let first_public_key = Handle::read_with_no_secrets(&mut reader).unwrap();
        let first_public_key_raw = get_primary_key_raw(&first_public_key).unwrap();
        let verifier = new_verifier(&first_public_key).unwrap();

        // Refresh key
        let refresh_request = make_refresh_request("d", "key", false, false);
        let refresh_response = oracle.refresh_key(refresh_request).await.unwrap().into_inner();
        assert_eq!(refresh_response.status.unwrap().code, Code::Ok as i32);

        let message = vec![0, 9, 1, 5, 9, 6];
        let scope = DataScopeType::UserPrivate;

        // Sign with first version (Return raw public key to check)
        let sign_request =
            make_sign_request("d", "key", message.clone(), scope, true, Some(first_version_id));
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        assert_eq!(sign_response.status.unwrap().code, Code::Ok as i32);
        let first_signature = extract_payload_message(&sign_response.signature.unwrap()).unwrap();
        // Has same corresponding raw public key
        let first_signature_key =
            extract_payload_message(&sign_response.verification_key.unwrap()).unwrap();
        assert_eq!(first_signature_key, first_public_key_raw);

        // First version accepted by first version verifier
        assert!(verifier.verify(&first_signature, &message).is_ok());

        // First version accepted by oracle (first version not disabled)
        let verify_request =
            make_verify_request("d", "key", message.clone(), first_signature.clone());
        let verify_response = oracle.verify(verify_request).await.unwrap().into_inner();
        assert_eq!(verify_response.status.unwrap().code, Code::Ok as i32);
        assert!(verify_response.is_valid_signature);

        // Sign with latest version
        let sign_request = make_sign_request("d", "key", message.clone(), scope, true, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        let second_signature = extract_payload_message(&sign_response.signature.unwrap()).unwrap();
        assert_ne!(first_signature, second_signature);
        // Has different corresponding raw public key
        let second_signature_key =
            extract_payload_message(&sign_response.verification_key.unwrap()).unwrap();
        assert_ne!(second_signature_key, first_public_key_raw);
        // New signature doesn't verify with old version
        assert!(verifier.verify(&second_signature, &message).is_err());
    }

    #[tokio::test]
    async fn verify_error_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        // Set up initial key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);
        // Second key
        let gen_request = make_simple_gen_request("d", "key2");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        let message = vec![1, 6, 1, 8, 0, 3];
        let scope = DataScopeType::UserPrivate;
        let sign_request = make_sign_request("d", "key", message.clone(), scope, false, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        assert_eq!(sign_response.status.unwrap().code, Code::Ok as i32);
        let signature = extract_payload_message(&sign_response.signature.unwrap()).unwrap();

        // Verification fails on wrong key
        let verify_request = make_verify_request("d", "key2", message.clone(), signature.clone());
        let verify_response = oracle.verify(verify_request).await.unwrap().into_inner();
        assert_eq!(verify_response.status.unwrap().code, Code::Ok as i32);
        assert!(!verify_response.is_valid_signature);

        // Verification fails on wrong message
        let message2 = vec![1, 2, 3];
        let verify_request = make_verify_request("d", "key", message2, signature.clone());
        let verify_response = oracle.verify(verify_request).await.unwrap().into_inner();
        assert_eq!(verify_response.status.unwrap().code, Code::Ok as i32);
        assert!(!verify_response.is_valid_signature);

        // Verification fails on wrong signature
        let signature2 = vec![1, 2, 3];
        let verify_request = make_verify_request("d", "key", message.clone(), signature2);
        let verify_response = oracle.verify(verify_request).await.unwrap().into_inner();
        assert_eq!(verify_response.status.unwrap().code, Code::Ok as i32);
        assert!(!verify_response.is_valid_signature);

        // Fail on missing key
        let verify_request =
            make_verify_request("d", "not_key", message.clone(), signature.clone());
        let verify_response = oracle.verify(verify_request).await.unwrap().into_inner();
        assert_eq!(verify_response.status.unwrap().code, Code::NotFound as i32);
        assert!(!verify_response.is_valid_signature);

        // Fail on no key
        let verify_request = Request::new(VerifyRequest {
            key_id: None,
            message_data: Some(to_payload(message.clone(), scope)),
            signature: Some(to_payload(signature.clone(), scope)),
        });
        let verify_response = oracle.verify(verify_request).await;
        assert_eq!(verify_response.err().unwrap().code(), tonic::Code::InvalidArgument);

        // Fail on no message
        let verify_request = Request::new(VerifyRequest {
            key_id: make_key_id("d", "key"),
            message_data: None,
            signature: Some(to_payload(signature.clone(), scope)),
        });
        let verify_response = oracle.verify(verify_request).await;
        assert_eq!(verify_response.err().unwrap().code(), tonic::Code::InvalidArgument);

        // Fail on no signature
        let verify_request = Request::new(VerifyRequest {
            key_id: make_key_id("d", "key"),
            message_data: Some(to_payload(message.clone(), scope)),
            signature: None,
        });
        let verify_response = oracle.verify(verify_request).await;
        assert_eq!(verify_response.err().unwrap().code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn verify_active_prior_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        // Set up initial key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        // Sign using first key
        let message = vec![0, 5, 7, 7, 2, 1];
        let sign_request =
            make_sign_request("d", "key", message.clone(), DataScopeType::Public, false, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        let signature = extract_payload_message(&sign_response.signature.unwrap()).unwrap();

        // Refresh without deactivate previous
        let refresh_request = make_refresh_request("d", "key", false, false);
        let refresh_response = oracle.refresh_key(refresh_request).await.unwrap().into_inner();
        assert_eq!(refresh_response.status.unwrap().code, Code::Ok as i32);

        // Verify still works, since previous key is still active, just not primary
        let verify_request = make_verify_request("d", "key", message.clone(), signature.clone());
        let verify_response = oracle.verify(verify_request).await.unwrap().into_inner();
        assert_eq!(verify_response.status.unwrap().code, Code::Ok as i32);
        assert!(verify_response.is_valid_signature);

        // Signature has changed if signed with new key
        let sign_request =
            make_sign_request("d", "key", message.clone(), DataScopeType::Public, false, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        let signature_2 = extract_payload_message(&sign_response.signature.unwrap()).unwrap();
        assert_ne!(signature, signature_2);
    }

    #[tokio::test]
    async fn verify_deactive_prior_test() {
        let oracle: CryptoOracle = CryptoOracle::new();
        // Set up initial key
        let gen_request = make_simple_gen_request("d", "key");
        let gen_response = oracle.generate_key(gen_request).await.unwrap().into_inner();
        assert_eq!(gen_response.status.unwrap().code, Code::Ok as i32);

        // Sign using first key
        let message = vec![0, 7, 3, 2, 0, 5];
        let sign_request =
            make_sign_request("d", "key", message.clone(), DataScopeType::Public, false, None);
        let sign_response = oracle.sign(sign_request).await.unwrap().into_inner();
        let signature = extract_payload_message(&sign_response.signature.unwrap()).unwrap();

        // Refresh with deactivate previous
        let refresh_request = make_refresh_request("d", "key", true, false);
        let refresh_response = oracle.refresh_key(refresh_request).await.unwrap().into_inner();
        assert_eq!(refresh_response.status.unwrap().code, Code::Ok as i32);

        // Verify fails, since previous key has been deactivated
        let verify_request = make_verify_request("d", "key", message.clone(), signature.clone());
        let verify_response = oracle.verify(verify_request).await.unwrap().into_inner();
        assert_eq!(verify_response.status.unwrap().code, Code::Ok as i32);
        assert!(!verify_response.is_valid_signature);
    }
}
