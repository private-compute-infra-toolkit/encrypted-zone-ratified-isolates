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

use ez_mtls_proto::enforcer::v1::PolicyHint;
use opentelemetry::metrics::{Counter, Histogram};
use opentelemetry::{KeyValue, global};
use setup_isolate_proto::setup_isolate::v1::validate_isolate_endorsement_response::IsolateEndorsementValidationError;

/// Metric names for setup_isolate
pub const RPC_COUNT_NAME: &str = crate::metric_name!("rpc_count");
pub const CERTIFICATE_FETCH_COUNT_NAME: &str = crate::metric_name!("certificate_fetch_count");
pub const PES_VALIDATION_OUTCOME_NAME: &str = crate::metric_name!("pes_validation_outcome");
pub const RPC_LATENCIES_NAME: &str = crate::metric_name!("rpc_latencies");
pub const AVS_PROXY_RPC_LATENCIES_NAME: &str = crate::metric_name!("avs_proxy_rpc_latencies");

/// Metrics used by the Setup Ratified Isolate
#[derive(Debug, Clone)]
pub struct Metrics {
    pub rpc_count: Counter<u64>,
    pub certificate_fetch_count: Counter<u64>,
    pub pes_validation_outcome: Counter<u64>,
    pub rpc_latencies: Histogram<f64>,
    pub avs_proxy_rpc_latencies: Histogram<f64>,
}

impl Default for Metrics {
    /// Creates default metrics from the global meter
    fn default() -> Self {
        let meter = global::meter("setup_isolate");
        let rpc_count = meter
            .u64_counter(RPC_COUNT_NAME)
            .with_description("Counts total incoming gRPC requests to SetupService.")
            .build();
        let certificate_fetch_count = meter
            .u64_counter(CERTIFICATE_FETCH_COUNT_NAME)
            .with_description("Counts certificate fetch calls to thick/avs-proxy.")
            .build();
        let pes_validation_outcome = meter
            .u64_counter(PES_VALIDATION_OUTCOME_NAME)
            .with_description("Counts PES isolate endorsement validation outcomes.")
            .build();
        let rpc_latencies = meter
            .f64_histogram(RPC_LATENCIES_NAME)
            .with_description("Execution latency of SetupService RPC handlers in s.")
            .with_boundaries(power_of_2_boundaries())
            .with_unit("s")
            .build();
        let avs_proxy_rpc_latencies = meter
            .f64_histogram(AVS_PROXY_RPC_LATENCIES_NAME)
            .with_description(
                "Latency of external calls to thick/avs-proxy for certificate fetching in s.",
            )
            .with_boundaries(power_of_2_boundaries())
            .with_unit("s")
            .build();

        Self {
            rpc_count,
            certificate_fetch_count,
            pes_validation_outcome,
            rpc_latencies,
            avs_proxy_rpc_latencies,
        }
    }
}

impl Metrics {
    /// Records a gRPC request outcome count for the specified method and gRPC status code.
    pub fn record_rpc_call(&self, method: &str, status_code: &str) {
        self.rpc_count.add(
            1,
            &[
                KeyValue::new("method", method.to_string()),
                KeyValue::new("status_code", status_code.to_string()),
            ],
        );
    }

    /// Records a certificate fetch attempt to thick/avs-proxy with policy hint and status code.
    pub fn record_certificate_fetch(&self, policy_hint: PolicyHint, status_code: &str) {
        let label = match policy_hint {
            PolicyHint::BackendMtlsCert => "backend_mtls",
            PolicyHint::FrontendTlsCert => "frontend_tls",
            _ => "unknown",
        };
        self.certificate_fetch_count.add(
            1,
            &[
                KeyValue::new("policy_hint", label),
                KeyValue::new("status_code", status_code.to_string()),
            ],
        );
    }

    /// Records a PES endorsement validation outcome.
    pub fn record_pes_validation_outcome(
        &self,
        validation_error: IsolateEndorsementValidationError,
    ) {
        let label = match validation_error {
            IsolateEndorsementValidationError::Unspecified => "success",
            IsolateEndorsementValidationError::ParsingFailure => "parsing_failure",
            IsolateEndorsementValidationError::PublisherIdMismatch => "publisher_id_mismatch",
            IsolateEndorsementValidationError::IsolateNameMismatch => "isolate_name_mismatch",
            IsolateEndorsementValidationError::VerificationFailed => "verification_failed",
            IsolateEndorsementValidationError::InvalidValidityPeriod => "invalid_validity_period",
            IsolateEndorsementValidationError::PackageDigestMismatch => "package_digest_mismatch",
        };
        self.pes_validation_outcome
            .add(1, &[KeyValue::new("outcome", label)]);
    }

    /// Records the execution latency of a SetupService RPC handler in seconds.
    pub fn record_rpc_latency(&self, method: &str, latency_s: f64) {
        self.rpc_latencies
            .record(latency_s, &[KeyValue::new("method", method.to_string())]);
    }

    /// Records the latency of external calls to thick/avs-proxy in seconds.
    pub fn record_avs_proxy_latency(&self, latency_s: f64) {
        self.avs_proxy_rpc_latencies.record(latency_s, &[]);
    }
}

fn power_of_2_boundaries() -> Vec<f64> {
    std::iter::successors(Some(1i32), |n| n.checked_mul(2))
        .map(|n| f64::from(n) / 1000.0)
        .collect()
}

/// Helper macro to construct fully qualified metric names for `setup_isolate`.
///
/// Prepend the standard namespace (`encrypted_zone.ratified_isolate.setup_isolate.`)
/// to the given metric name to ensure consistent namespacing across the isolate.
#[macro_export]
macro_rules! metric_name {
    ($name:expr) => {
        concat!("encrypted_zone.ratified_isolate.setup_isolate.", $name)
    };
}
