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
use oak_proto_rust::oak::attestation::v1::{
    ClaimReferenceValue, Endorsement, EndorsementDetails, EndorsementReferenceValue, KeyType,
    PesReferenceValue, Signature, SignedEndorsement, TLogReferenceValues, VerifyingKey,
    VerifyingKeySet, endorsement, t_log_reference_values,
};
use oak_time::Clock;
use setup_isolate_proto::setup_isolate::v1::{
    ExpectedClaims, ValidateIsolateEndorsementRequest, ValidateIsolateEndorsementResponse,
    Validity, validate_isolate_endorsement_response::IsolateEndorsementValidationError,
};
use thiserror::Error;
use timestamp_proto::google::protobuf::Timestamp;
use x509_cert::{Certificate, der::Encode};

/// PEM bundle of the PES root certificates trusted at compile time. It holds
/// one or more certificates, so that PES keys can be rotated seamlessly.
const PES_CERTS_PEM: &str = include_str!("pes_certs.pem");

pub const PUBLISHER_CLAIM_TYPE: &str = "https://github.com/private-compute-infra-toolkit/public-endorsement-service/blob/main/docs/claims/publisher.md";
pub const ARTIFACT_CLAIM_TYPE: &str = "https://github.com/private-compute-infra-toolkit/public-endorsement-service/blob/main/docs/claims/artifact.md";

const JSON_KEY_STATEMENT_SIGNATURE: &str = "statementSignature";
const JSON_KEY_ENDORSEMENT_SIGNATURES: &str = "endorsementSignatures";
const JSON_KEY_VERIFICATION_MATERIAL: &str = "verificationMaterial";
const JSON_KEY_ECDSA_P256_SHA256: &str = "ecdsaP256Sha256";
const JSON_KEY_DER_BYTES: &str = "derBytes";
const JSON_KEY_STATEMENT: &str = "statement";
const JSON_KEY_SERIALIZED: &str = "serialized";
const JSON_KEY_PREDICATE: &str = "predicate";
const JSON_KEY_CLAIMS: &str = "claims";
const JSON_KEY_TYPE: &str = "type";
const JSON_KEY_ANNOTATIONS: &str = "annotations";
const JSON_KEY_PUBLISHER_ID: &str = "publisher_id";
const JSON_KEY_FILENAME: &str = "filename";
const JSON_KEY_SUBJECT: &str = "subject";
const JSON_KEY_DIGEST: &str = "digest";
const JSON_KEY_SHA256: &str = "sha256";

#[derive(Error, Debug, Clone, PartialEq, Eq, Default)]
#[error("{error:?}: {message}")]
pub struct PesValidationError {
    pub error: IsolateEndorsementValidationError,
    pub message: String,
}

/// Validates whether the isolate package endorsements in the request are validly signed by PES.
///
/// This function extracts the endorsements, publisher signature, and PES confirmation from the request,
/// verifies the claims against `expected_claims`, and checks the cryptographic signatures against the
/// compile-time embedded PES X.509 root certificate.
///
/// # Arguments
/// * `clock` - A time source implementing `oak_time::Clock` used to evaluate certificate and endorsement validity periods.
/// * `request` - The `ValidateIsolateEndorsementRequest` containing expected claims, endorsement bytes, and expected digest.
///
/// # Returns
/// * `ValidateIsolateEndorsementResponse` containing the validity period on success or error details on failure.
pub fn verify_pes_endorsement(
    clock: &dyn Clock,
    request: ValidateIsolateEndorsementRequest,
) -> ValidateIsolateEndorsementResponse {
    let expected_claims = match request.expected_claims {
        Some(claims) => claims,
        None => {
            return ValidateIsolateEndorsementResponse {
                validation_error: IsolateEndorsementValidationError::ParsingFailure.into(),
                error_message: "Missing expected_claims in request".to_string(),
                ..Default::default()
            };
        }
    };
    if request.package_digest_sha256.is_empty() {
        return ValidateIsolateEndorsementResponse {
            validation_error: IsolateEndorsementValidationError::ParsingFailure.into(),
            error_message: "Missing package_digest_sha256 in request".to_string(),
            ..Default::default()
        };
    }
    let endorsement = match request.isolate_package_endorsement {
        Some(endorsement) => endorsement,
        None => {
            return ValidateIsolateEndorsementResponse {
                validation_error: IsolateEndorsementValidationError::ParsingFailure.into(),
                error_message: "Missing isolate_package_endorsement in request".to_string(),
                ..Default::default()
            };
        }
    };

    let signed_endorsement = SignedEndorsement {
        endorsement: Some(Endorsement {
            format: endorsement::Format::EndorsementFormatJsonIntoto.into(),
            serialized: endorsement.endorsement_json,
            ..Default::default()
        }),
        signature: Some(Signature {
            key_id: 1,
            raw: endorsement.signature,
        }),
        pes_confirmation: endorsement.pes_confirmation_json,
        ..Default::default()
    };

    match verify_pes_endorsement_internal(
        clock,
        signed_endorsement,
        &expected_claims,
        &request.package_digest_sha256,
    ) {
        Ok(validity) => ValidateIsolateEndorsementResponse {
            validity: Some(validity),
            ..Default::default()
        },
        Err(err) => ValidateIsolateEndorsementResponse {
            validation_error: err.error.into(),
            error_message: err.message,
            ..Default::default()
        },
    }
}

fn verify_pes_endorsement_internal(
    clock: &dyn Clock,
    signed_endorsement: SignedEndorsement,
    expected_claims: &ExpectedClaims,
    expected_package_digest_sha256: &str,
) -> Result<Validity, PesValidationError> {
    let now_utc_millis = clock.get_time().into_unix_millis();

    let endorsement_bytes = signed_endorsement
        .endorsement
        .as_ref()
        .map(|e| e.serialized.as_slice())
        .ok_or_else(|| PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: "Missing serialized endorsement bytes".to_string(),
        })?;

    // Step 1: Validate the package digest in the endorsement JSON.
    validate_package_digest(endorsement_bytes, expected_package_digest_sha256)?;

    // Step 2: Load the RSA Root Certificates into a VerifyingKeySet matching AVS pattern.
    let pes_root_key_set =
        load_rsa_sha2_256_keyset(PES_CERTS_PEM, now_utc_millis).map_err(|e| {
            PesValidationError {
                error: IsolateEndorsementValidationError::ParsingFailure,
                message: format!("Failed to load PES root certificates: {e}"),
            }
        })?;

    // Step 3: Load the Publisher verifying key from PES confirmation.
    let mut confirmation_json: serde_json::Value =
        serde_json::from_slice(&signed_endorsement.pes_confirmation).map_err(|e| {
            PesValidationError {
                error: IsolateEndorsementValidationError::ParsingFailure,
                message: format!("Failed to parse PES confirmation JSON: {e}"),
            }
        })?;
    let publisher_key_b64 = confirmation_json
        .get(JSON_KEY_STATEMENT_SIGNATURE)
        .and_then(|v| v.get(JSON_KEY_VERIFICATION_MATERIAL))
        .and_then(|v| v.get(JSON_KEY_ECDSA_P256_SHA256))
        .and_then(|v| v.get(JSON_KEY_DER_BYTES))
        .and_then(|v| v.as_str())
        .ok_or_else(|| PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: "No Publisher verifying key found in PES confirmation JSON".to_string(),
        })?;
    let publisher_key_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        publisher_key_b64,
    )
    .map_err(|e| PesValidationError {
        error: IsolateEndorsementValidationError::ParsingFailure,
        message: format!("Failed to base64-decode Publisher verifying key: {e}"),
    })?;
    let publisher_key_set = VerifyingKeySet {
        keys: vec![VerifyingKey {
            r#type: KeyType::EcdsaP256Sha256 as i32,
            key_id: 1,
            raw: publisher_key_bytes,
        }],
        signed_timestamp: None,
    };

    // Step 4: Validate claims in the PES confirmation.
    validate_claims(&confirmation_json, expected_claims)?;

    // Step 5: Construct EndorsementReferenceValue.
    let ref_value = EndorsementReferenceValue {
        endorser: Some(publisher_key_set),
        required_claims: Some(ClaimReferenceValue {
            claim_types: vec![
                PUBLISHER_CLAIM_TYPE.to_string(),
                ARTIFACT_CLAIM_TYPE.to_string(),
            ],
        }),
        tlog: Some(TLogReferenceValues {
            strategy: Some(t_log_reference_values::Strategy::All(())),
            pes: Some(PesReferenceValue {
                key_set: Some(pes_root_key_set),
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Step 6: Verify the endorsement across all PES signatures and get the validity period.
    let details = verify_endorsement_across_pes_signatures(
        now_utc_millis,
        signed_endorsement,
        &mut confirmation_json,
        &ref_value,
    )?;
    let oak_validity = details.valid.ok_or_else(|| PesValidationError {
        error: IsolateEndorsementValidationError::InvalidValidityPeriod,
        message: "Verified endorsement details missing validity period".to_string(),
    })?;

    let not_before = oak_validity.not_before.map(|t| Timestamp {
        seconds: t.seconds,
        nanos: t.nanos,
    });
    let not_after = oak_validity.not_after.map(|t| Timestamp {
        seconds: t.seconds,
        nanos: t.nanos,
    });
    Ok(Validity {
        not_before,
        not_after,
    })
}

/// Verifies the endorsement by trying each signature in `endorsementSignatures`.
///
/// Oak's `verify_pes_confirmation` currently only inspects
/// `endorsement_signatures.first()`. During PES key rotation, PES attaches
/// multiple signatures to `endorsementSignatures`, and once the first signing
/// key is retired or expired, checking only `.first()` fails even when a
/// subsequent signature is valid. We reorder `endorsementSignatures` on each
/// attempt so every signature is tried at `.first()` until one succeeds.
// TODO(b/565672521): Remove this traversal of signatures once Oak's
// `verify_pes_confirmation` iterates over all `endorsement_signatures`.
fn verify_endorsement_across_pes_signatures(
    now_utc_millis: i64,
    mut signed_endorsement: SignedEndorsement,
    confirmation_json: &mut serde_json::Value,
    ref_value: &EndorsementReferenceValue,
) -> Result<EndorsementDetails, PesValidationError> {
    let num_signatures = confirmation_json
        .get(JSON_KEY_ENDORSEMENT_SIGNATURES)
        .and_then(|v| v.as_array())
        .map_or(0, Vec::len);

    let mut last_err = match oak_attestation_verification::verify_endorsement(
        now_utc_millis,
        &signed_endorsement,
        ref_value,
    ) {
        Ok(details) => return Ok(details),
        Err(e) => e,
    };

    for i in 1..num_signatures {
        if let Some(sigs) = confirmation_json
            .get_mut(JSON_KEY_ENDORSEMENT_SIGNATURES)
            .and_then(|v| v.as_array_mut())
        {
            sigs.swap(0, i);
        }
        signed_endorsement.pes_confirmation =
            serde_json::to_vec(confirmation_json).map_err(|e| PesValidationError {
                error: IsolateEndorsementValidationError::ParsingFailure,
                message: format!("Failed to serialize PES confirmation JSON: {e}"),
            })?;

        match oak_attestation_verification::verify_endorsement(
            now_utc_millis,
            &signed_endorsement,
            ref_value,
        ) {
            Ok(details) => return Ok(details),
            Err(e) => last_err = e,
        }
    }

    Err(PesValidationError {
        error: IsolateEndorsementValidationError::VerificationFailed,
        message: format!("PES endorsement verification failed: {last_err}"),
    })
}

/// Validates that the endorsement JSON contains exactly one subject entry and its SHA256 digest
/// matches the expected package digest that Enforcer calculates.
fn validate_package_digest(
    endorsement_bytes: &[u8],
    expected_package_digest_sha256: &str,
) -> Result<(), PesValidationError> {
    let endorsement_json: serde_json::Value =
        serde_json::from_slice(endorsement_bytes).map_err(|e| PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: format!("Failed to parse endorsement JSON: {e}"),
        })?;

    let subjects = endorsement_json
        .get(JSON_KEY_SUBJECT)
        .and_then(|s| s.as_array())
        .ok_or_else(|| PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: "No subject array found in endorsement JSON".to_string(),
        })?;

    if subjects.is_empty() {
        return Err(PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: "Subject array is empty in endorsement JSON".to_string(),
        });
    }
    if subjects.len() > 1 {
        return Err(PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: "Multiple subjects found in endorsement JSON; expected exactly one"
                .to_string(),
        });
    }

    let subject = &subjects[0];
    let digest_sha256 = subject
        .get(JSON_KEY_DIGEST)
        .and_then(|d| d.get(JSON_KEY_SHA256))
        .and_then(|h| h.as_str())
        .ok_or_else(|| PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: "No sha256 digest found in endorsement subject".to_string(),
        })?;

    if !digest_sha256.eq_ignore_ascii_case(expected_package_digest_sha256) {
        return Err(PesValidationError {
            error: IsolateEndorsementValidationError::PackageDigestMismatch,
            message: format!(
                "Package digest mismatch: expected {}, got {}",
                expected_package_digest_sha256, digest_sha256
            ),
        });
    }

    Ok(())
}

fn validate_claims(
    confirmation_json: &serde_json::Value,
    expected_claims: &ExpectedClaims,
) -> Result<(), PesValidationError> {
    let serialized_b64 = confirmation_json
        .get(JSON_KEY_STATEMENT)
        .and_then(|s| s.get(JSON_KEY_SERIALIZED))
        .and_then(|v| v.as_str())
        .ok_or_else(|| PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: "No statement.serialized found in PES confirmation".to_string(),
        })?;
    let serialized_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, serialized_b64)
            .map_err(|e| PesValidationError {
                error: IsolateEndorsementValidationError::ParsingFailure,
                message: format!("Failed to base64-decode serialized statement: {e}"),
            })?;
    let statement_json: serde_json::Value =
        serde_json::from_slice(&serialized_bytes).map_err(|e| PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: format!("Failed to parse serialized statement JSON: {e}"),
        })?;
    let claims = statement_json
        .get(JSON_KEY_PREDICATE)
        .and_then(|p| p.get(JSON_KEY_CLAIMS))
        .and_then(|c| c.as_array())
        .ok_or_else(|| PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: "No predicate.claims found in statement".to_string(),
        })?;

    validate_publisher_id(claims, &expected_claims.publisher_id)?;
    validate_artifact_filename(claims, expected_claims)?;

    Ok(())
}

/// Validates that there is exactly one publisher claim in the PES confirmation and that its
/// `publisher_id` matches `expected_publisher_id`.
///
/// Note: PES checks the `publisher_id` claim in the client statements and enforces binding
/// (e.g. using OIDC / OCID). We still verify that only a single publisher claim exists here.
fn validate_publisher_id(
    claims: &[serde_json::Value],
    expected_publisher_id: &str,
) -> Result<(), PesValidationError> {
    let publisher_claim =
        find_and_ensure_exactly_one_claim(claims, PUBLISHER_CLAIM_TYPE, "Publisher")?;
    let endorsement_publisher_id = publisher_claim
        .get(JSON_KEY_ANNOTATIONS)
        .and_then(|a| a.get(JSON_KEY_PUBLISHER_ID))
        .and_then(|p| p.as_str())
        .ok_or_else(|| PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: "No publisher_id found in publisher claim".to_string(),
        })?;
    if endorsement_publisher_id != expected_publisher_id {
        return Err(PesValidationError {
            error: IsolateEndorsementValidationError::PublisherIdMismatch,
            message: format!(
                "Publisher ID mismatch: expected {}, got {}",
                expected_publisher_id, endorsement_publisher_id
            ),
        });
    }
    Ok(())
}

/// Validates that there is exactly one artifact claim in the PES confirmation and that its
/// `filename` annotation matches the expected isolate name and package filename.
///
/// PES annotates the artifact claim with the package path as published in the release, which is of
/// the form `<isolate_name>/<package_filename>` (e.g. `crypto_oracle/isolate_rootfs.tar`).
fn validate_artifact_filename(
    claims: &[serde_json::Value],
    expected_claims: &ExpectedClaims,
) -> Result<(), PesValidationError> {
    let artifact_claim =
        find_and_ensure_exactly_one_claim(claims, ARTIFACT_CLAIM_TYPE, "Artifact")?;
    let filename = artifact_claim
        .get(JSON_KEY_ANNOTATIONS)
        .and_then(|a| a.get(JSON_KEY_FILENAME))
        .and_then(|f| f.as_str())
        .ok_or_else(|| PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: "No filename found in artifact claim".to_string(),
        })?;
    let expected_filename = format!(
        "{}/{}",
        expected_claims.isolate_name, expected_claims.package_filename
    );
    if filename != expected_filename {
        return Err(PesValidationError {
            error: IsolateEndorsementValidationError::IsolateNameMismatch,
            message: format!(
                "Artifact filename mismatch: expected {expected_filename}, got {filename}"
            ),
        });
    }
    Ok(())
}

fn find_and_ensure_exactly_one_claim<'a>(
    claims: &'a [serde_json::Value],
    claim_type: &str,
    claim_name: &str,
) -> Result<&'a serde_json::Value, PesValidationError> {
    let mut matching = claims
        .iter()
        .filter(|c| c.get(JSON_KEY_TYPE).and_then(|t| t.as_str()) == Some(claim_type));
    let claim = matching.next().ok_or_else(|| PesValidationError {
        error: IsolateEndorsementValidationError::ParsingFailure,
        message: format!("{claim_name} claim not found in PES confirmation"),
    })?;
    if matching.next().is_some() {
        return Err(PesValidationError {
            error: IsolateEndorsementValidationError::ParsingFailure,
            message: format!("Multiple {claim_name} claims found in PES confirmation"),
        });
    }
    Ok(claim)
}

/// Checks whether an X.509 certificate's `not_before` / `not_after` validity
/// period covers `now_utc_millis`.
fn is_cert_valid_at(cert: &Certificate, now_utc_millis: i64) -> bool {
    let validity = &cert.tbs_certificate.validity;
    let not_before_millis = validity.not_before.to_unix_duration().as_millis() as i64;
    let not_after_millis = validity.not_after.to_unix_duration().as_millis() as i64;
    now_utc_millis >= not_before_millis && now_utc_millis <= not_after_millis
}

/// Extracts the SubjectPublicKeyInfo (SPKI) DER-encoded bytes from all
/// PEM-encoded X.509 certificates in a PEM string that are valid at
/// `now_utc_millis`.
fn extract_spki_from_pem(pem: &str, now_utc_millis: i64) -> Result<Vec<Vec<u8>>> {
    let certs = Certificate::load_pem_chain(pem.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to parse PES X.509 root certificate PEM: {e}"))?;
    certs
        .into_iter()
        .filter(|cert| is_cert_valid_at(cert, now_utc_millis))
        .map(|cert| {
            cert.tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|e| {
                    anyhow::anyhow!("Failed to encode PES root certificate SPKI to DER: {e}")
                })
        })
        .collect()
}

/// Loads a `VerifyingKeySet` with one `KeyType::RsaSha2256` key per valid
/// certificate in `pem_bundle` at `now_utc_millis`. Oak matches the key PES
/// signed with by its raw SPKI bytes, so all valid keys of the set are trusted,
/// which is what enables key rotation.
fn load_rsa_sha2_256_keyset(pem_bundle: &str, now_utc_millis: i64) -> Result<VerifyingKeySet> {
    // `load_pem_chain` does not handle an empty input.
    let raw_keys = if pem_bundle.trim().is_empty() {
        Vec::new()
    } else {
        extract_spki_from_pem(pem_bundle, now_utc_millis)?
    };
    if raw_keys.is_empty() {
        anyhow::bail!("No valid PES root certificate found in the embedded certificate bundle");
    }

    let keys = raw_keys
        .into_iter()
        .enumerate()
        .map(|(index, raw)| VerifyingKey {
            r#type: KeyType::RsaSha2256 as i32,
            key_id: index as u32,
            raw,
        })
        .collect();

    Ok(VerifyingKeySet {
        keys,
        signed_timestamp: None,
    })
}
