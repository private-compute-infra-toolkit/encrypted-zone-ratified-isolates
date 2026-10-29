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

use oak_time::{Instant, clock::FixedClock};
use runfiles::Runfiles;
use setup_isolate_proto::setup_isolate::v1::{
    ExpectedClaims, IsolatePackageEndorsement, ValidateIsolateEndorsementRequest,
    validate_isolate_endorsement_response::IsolateEndorsementValidationError,
};

const ENDORSEMENT_PATH: &str = "_main/pes/testdata/endorsement.json";
const SIGNED_ENDORSEMENT_PATH: &str = "_main/pes/testdata/endorsement.json.sig";
const PES_CONFIRMATION_PATH: &str = "_main/pes/testdata/pes_confirmation.json";
const PACKAGE_DIGEST_SHA256: &str =
    "b9b8312a420400f6698af90261478657d83f7efe0b45ad9473c217b83c63d821";

// Claim validation runs before signature verification, so these variants only need to alter the
// PES confirmation; they reuse the signed endorsement above.
const PES_CONFIRMATION_MULTIPLE_PUBLISHERS_PATH: &str =
    "_main/pes/testdata/pes_confirmation_multiple_publishers.json";
const PES_CONFIRMATION_MULTIPLE_ARTIFACTS_PATH: &str =
    "_main/pes/testdata/pes_confirmation_multiple_artifacts.json";

fn load_endorsement_test_data(
    r: &Runfiles,
    endorsement_path: &str,
    signed_endorsement_path: &str,
    pes_confirmation_path: &str,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let endorsement_path = r
        .rlocation(endorsement_path)
        .unwrap_or_else(|| panic!("Failed to resolve {endorsement_path}"));
    let signed_endorsement_path = r
        .rlocation(signed_endorsement_path)
        .unwrap_or_else(|| panic!("Failed to resolve {signed_endorsement_path}"));
    let pes_confirmation_path = r
        .rlocation(pes_confirmation_path)
        .unwrap_or_else(|| panic!("Failed to resolve {pes_confirmation_path}"));

    let endorsement_json = std::fs::read(&endorsement_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read endorsement JSON from {:?}: {}",
            endorsement_path, e
        )
    });
    let signed_endorsement_bytes = std::fs::read(&signed_endorsement_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read endorsement signature from {:?}: {}",
            signed_endorsement_path, e
        )
    });
    let pes_confirmation_json = std::fs::read(&pes_confirmation_path).unwrap_or_else(|e| {
        panic!(
            "Failed to read PES confirmation JSON from {:?}: {}",
            pes_confirmation_path, e
        )
    });

    (
        endorsement_json,
        signed_endorsement_bytes,
        pes_confirmation_json,
    )
}

/// Tests embed several PES certificates (prod, which signed the endorsement,
/// and staging), so this also covers verification against multiple PES keys.
#[test]
fn test_verify_pes_endorsement_success() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_PATH,
        );

    // Mock system clock to 2026-09-01 00:00:00 UTC (1788220800000 ms), which falls within
    // the validity period of the crypto_oracle testdata endorsement (2026-08-27 to 2026-10-26).
    let clock = FixedClock::at_instant(Instant::from_unix_millis(1_788_220_800_000));
    let request = ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "pcit-release-bot@google.com".to_string(),
            isolate_name: "crypto_oracle".to_string(),
            package_filename: "isolate_rootfs.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json,
            signature: signed_endorsement_bytes,
            pes_confirmation_json,
        }),
        package_digest_sha256: PACKAGE_DIGEST_SHA256.to_string(),
    };
    let response = pes::verify_pes_endorsement(&clock, request);
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::Unspecified as i32,
        "unexpected validation error: {}",
        response.error_message
    );
    assert!(response.error_message.is_empty());
    let validity = response.validity.expect("validity should be present");

    // Assert endorsement validity start time: 2026-08-27 14:52:00.199 UTC
    assert_eq!(
        validity.not_before.as_ref().map(|t| (t.seconds, t.nanos)),
        Some((1_787_842_320, 199_000_000))
    );
    // Assert endorsement validity end time: 2026-10-26 14:52:00.199 UTC
    assert_eq!(
        validity.not_after.as_ref().map(|t| (t.seconds, t.nanos)),
        Some((1_793_026_320, 199_000_000))
    );
}

#[test]
fn test_verify_pes_endorsement_publisher_mismatch() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_PATH,
        );

    let clock = FixedClock::at_instant(Instant::from_unix_millis(1_788_220_800_000));
    let request = ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "wrong-publisher@google.com".to_string(),
            isolate_name: "crypto_oracle".to_string(),
            package_filename: "isolate_rootfs.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json,
            signature: signed_endorsement_bytes,
            pes_confirmation_json,
        }),
        package_digest_sha256: PACKAGE_DIGEST_SHA256.to_string(),
    };
    let response = pes::verify_pes_endorsement(&clock, request);
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::PublisherIdMismatch as i32
    );
    assert!(response.error_message.contains("Publisher ID mismatch"));
}

#[test]
fn test_verify_pes_endorsement_isolate_mismatch() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_PATH,
        );

    let clock = FixedClock::at_instant(Instant::from_unix_millis(1_788_220_800_000));
    let request = ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "pcit-release-bot@google.com".to_string(),
            isolate_name: "wrong_isolate".to_string(),
            package_filename: "isolate_rootfs.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json,
            signature: signed_endorsement_bytes,
            pes_confirmation_json,
        }),
        package_digest_sha256: PACKAGE_DIGEST_SHA256.to_string(),
    };
    let response = pes::verify_pes_endorsement(&clock, request);
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::IsolateNameMismatch as i32
    );
    assert!(
        response
            .error_message
            .contains("Artifact filename mismatch")
    );
}

#[test]
fn test_verify_pes_endorsement_package_filename_mismatch() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_PATH,
        );

    let clock = FixedClock::at_instant(Instant::from_unix_millis(1_788_220_800_000));
    let request = ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "pcit-release-bot@google.com".to_string(),
            isolate_name: "crypto_oracle".to_string(),
            package_filename: "wrong_rootfs.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json,
            signature: signed_endorsement_bytes,
            pes_confirmation_json,
        }),
        package_digest_sha256: PACKAGE_DIGEST_SHA256.to_string(),
    };
    let response = pes::verify_pes_endorsement(&clock, request);
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::IsolateNameMismatch as i32
    );
    assert!(
        response
            .error_message
            .contains("Artifact filename mismatch")
    );
}

#[test]
fn test_verify_pes_endorsement_package_digest_mismatch() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_PATH,
        );

    let clock = FixedClock::at_instant(Instant::from_unix_millis(1_788_220_800_000));
    let request = ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "pcit-release-bot@google.com".to_string(),
            isolate_name: "crypto_oracle".to_string(),
            package_filename: "isolate_rootfs.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json,
            signature: signed_endorsement_bytes,
            pes_confirmation_json,
        }),
        package_digest_sha256: "wrong_digest_sha256".to_string(),
    };
    let response = pes::verify_pes_endorsement(&clock, request);
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::PackageDigestMismatch as i32
    );
    assert!(response.error_message.contains("Package digest mismatch"));
}

#[test]
fn test_verify_pes_endorsement_missing_package_digest() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_PATH,
        );

    let clock = FixedClock::at_instant(Instant::from_unix_millis(1_788_220_800_000));
    let request = ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "pcit-release-bot@google.com".to_string(),
            isolate_name: "crypto_oracle".to_string(),
            package_filename: "isolate_rootfs.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json,
            signature: signed_endorsement_bytes,
            pes_confirmation_json,
        }),
        package_digest_sha256: "".to_string(),
    };
    let response = pes::verify_pes_endorsement(&clock, request);
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

#[test]
fn test_verify_pes_endorsement_multiple_publisher_claims() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_MULTIPLE_PUBLISHERS_PATH,
        );

    let clock = FixedClock::at_instant(Instant::from_unix_millis(1_788_220_800_000));
    let request = ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "pcit-release-bot@google.com".to_string(),
            isolate_name: "crypto_oracle".to_string(),
            package_filename: "isolate_rootfs.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json,
            signature: signed_endorsement_bytes,
            pes_confirmation_json,
        }),
        package_digest_sha256: PACKAGE_DIGEST_SHA256.to_string(),
    };

    let response = pes::verify_pes_endorsement(&clock, request);
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::ParsingFailure as i32
    );
    assert!(
        response.error_message.contains("Multiple Publisher claims"),
        "unexpected error message: {}",
        response.error_message
    );
}

#[test]
fn test_verify_pes_endorsement_multiple_artifact_claims() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_MULTIPLE_ARTIFACTS_PATH,
        );

    let clock = FixedClock::at_instant(Instant::from_unix_millis(1_788_220_800_000));
    let request = ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "pcit-release-bot@google.com".to_string(),
            isolate_name: "crypto_oracle".to_string(),
            package_filename: "isolate_rootfs.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json,
            signature: signed_endorsement_bytes,
            pes_confirmation_json,
        }),
        package_digest_sha256: PACKAGE_DIGEST_SHA256.to_string(),
    };

    let response = pes::verify_pes_endorsement(&clock, request);
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::ParsingFailure as i32
    );
    assert!(
        response.error_message.contains("Multiple Artifact claims"),
        "unexpected error message: {}",
        response.error_message
    );
}

#[test]
fn test_verify_pes_endorsement_second_pes_signature_succeeds_during_rotation() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_PATH,
        );

    // Prepend a retired/invalid signature before the valid prod signature in
    // `endorsementSignatures` to simulate PES dual-signing during key rotation.
    let mut confirmation: serde_json::Value =
        serde_json::from_slice(&pes_confirmation_json).expect("valid confirmation JSON");
    let sigs = confirmation["endorsementSignatures"]
        .as_array_mut()
        .expect("endorsementSignatures array");
    let valid_sig = sigs[0].clone();
    let mut retired_sig = valid_sig.clone();
    retired_sig["signature"] = serde_json::Value::String("AAAA".to_string());
    *sigs = vec![retired_sig, valid_sig];

    // Mock system clock to 2026-10-01 00:00:00 UTC (1790812800000 ms), where the staging
    // certificate in the test bundle (Not After: 2026-09-29) is expired and filtered out,
    // while the prod certificate (Not After: 2027-03-02) and endorsement (notAfter: 2026-10-26)
    // remain valid.
    let clock = FixedClock::at_instant(Instant::from_unix_millis(1_790_812_800_000));
    let request = ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "pcit-release-bot@google.com".to_string(),
            isolate_name: "crypto_oracle".to_string(),
            package_filename: "isolate_rootfs.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json,
            signature: signed_endorsement_bytes,
            pes_confirmation_json: serde_json::to_vec(&confirmation).unwrap(),
        }),
        package_digest_sha256: PACKAGE_DIGEST_SHA256.to_string(),
    };

    let response = pes::verify_pes_endorsement(&clock, request);
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::Unspecified as i32,
        "unexpected validation error: {}",
        response.error_message
    );
    assert!(response.validity.is_some());
}

#[test]
fn test_verify_pes_endorsement_all_pes_signatures_fail() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_PATH,
        );

    let mut confirmation: serde_json::Value =
        serde_json::from_slice(&pes_confirmation_json).expect("valid confirmation JSON");
    let sigs = confirmation["endorsementSignatures"]
        .as_array_mut()
        .expect("endorsementSignatures array");
    let mut bad_sig_1 = sigs[0].clone();
    bad_sig_1["signature"] = serde_json::Value::String("AAAA".to_string());
    let mut bad_sig_2 = sigs[0].clone();
    bad_sig_2["signature"] = serde_json::Value::String("BBBB".to_string());
    *sigs = vec![bad_sig_1, bad_sig_2];

    let clock = FixedClock::at_instant(Instant::from_unix_millis(1_788_220_800_000));
    let request = ValidateIsolateEndorsementRequest {
        expected_claims: Some(ExpectedClaims {
            publisher_id: "pcit-release-bot@google.com".to_string(),
            isolate_name: "crypto_oracle".to_string(),
            package_filename: "isolate_rootfs.tar".to_string(),
        }),
        isolate_package_endorsement: Some(IsolatePackageEndorsement {
            endorsement_json,
            signature: signed_endorsement_bytes,
            pes_confirmation_json: serde_json::to_vec(&confirmation).unwrap(),
        }),
        package_digest_sha256: PACKAGE_DIGEST_SHA256.to_string(),
    };

    let response = pes::verify_pes_endorsement(&clock, request);
    assert!(response.validity.is_none());
    assert_eq!(
        response.validation_error,
        IsolateEndorsementValidationError::VerificationFailed as i32
    );
    assert!(
        response
            .error_message
            .contains("PES endorsement verification failed"),
        "unexpected error message: {}",
        response.error_message
    );
}

#[test]
fn test_verify_pes_endorsement_root_certs_not_valid_at_clock() {
    let r = Runfiles::create().expect("Failed to create runfiles resolver");
    let (endorsement_json, signed_endorsement_bytes, pes_confirmation_json) =
        load_endorsement_test_data(
            &r,
            ENDORSEMENT_PATH,
            SIGNED_ENDORSEMENT_PATH,
            PES_CONFIRMATION_PATH,
        );

    // 2019-01-01 00:00:00 UTC (before all embedded certificates' not_before) and
    // 2031-01-01 00:00:00 UTC (after all embedded certificates' not_after).
    for timestamp_millis in [1_546_300_800_000, 1_924_992_000_000] {
        let clock = FixedClock::at_instant(Instant::from_unix_millis(timestamp_millis));
        let request = ValidateIsolateEndorsementRequest {
            expected_claims: Some(ExpectedClaims {
                publisher_id: "pcit-release-bot@google.com".to_string(),
                isolate_name: "crypto_oracle".to_string(),
                package_filename: "isolate_rootfs.tar".to_string(),
            }),
            isolate_package_endorsement: Some(IsolatePackageEndorsement {
                endorsement_json: endorsement_json.clone(),
                signature: signed_endorsement_bytes.clone(),
                pes_confirmation_json: pes_confirmation_json.clone(),
            }),
            package_digest_sha256: PACKAGE_DIGEST_SHA256.to_string(),
        };

        let response = pes::verify_pes_endorsement(&clock, request);
        assert!(response.validity.is_none());
        assert_eq!(
            response.validation_error,
            IsolateEndorsementValidationError::ParsingFailure as i32
        );
        assert!(
            response
                .error_message
                .contains("No valid PES root certificate found"),
            "unexpected error message: {}",
            response.error_message
        );
    }
}
